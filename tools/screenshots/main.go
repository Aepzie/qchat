// Command screenshots renders the README screenshots of the qchat terminal
// interface. It drives the real interface (package tui) with fictional demo
// data, captures each screen as ANSI text and converts it into an SVG
// image of a terminal window.
//
//	go run ./tools/screenshots [-out docs/screenshots] [-only name] [-ansi dir]
//
// Nothing touches the network or a real profile: the Backend is an
// in-memory fake, and every person, ID, group and message is made up.
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Aepzie/qchat/internal/client"
	"github.com/Aepzie/qchat/internal/protocol"
	"github.com/Aepzie/qchat/internal/transport"
	"github.com/Aepzie/qchat/internal/tui"
)

const (
	demoAddr    = "relay.nordlicht.example:8443"
	demoVersion = "0.8.0"
)

// viewer is a model whose screen can be captured.
type viewer interface {
	tea.Model
	View() tea.View
}

// driver runs a Bubble Tea model without a terminal: it feeds messages to
// Update and executes the returned commands itself. Commands that block,
// such as waiting on an event channel, are parked and delivered once they
// complete.
type driver struct {
	model    viewer
	parked   []chan tea.Msg
	chat     chan tui.ChatEvent
	events   chan client.Event
	ticks    int
	maxTicks int
}

// send delivers one message to the model and runs the resulting command.
func (d *driver) send(msg tea.Msg) {
	next, cmd := d.model.Update(msg)
	d.model = next.(viewer)
	d.run(cmd)
}

// run executes cmd, delivering its message right away if it completes
// quickly and parking it otherwise.
func (d *driver) run(cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	ch := make(chan tea.Msg, 1)
	go func() { ch <- cmd() }()
	select {
	case msg := <-ch:
		d.deliver(msg)
	case <-time.After(30 * time.Millisecond):
		d.parked = append(d.parked, ch)
	}
}

// deliver unpacks batches and sequences and sends everything else to the
// model. Animation ticks beyond maxTicks are dropped, which freezes the
// animation at a chosen frame.
func (d *driver) deliver(msg tea.Msg) {
	switch m := msg.(type) {
	case nil, tea.QuitMsg:
		return
	case tea.BatchMsg:
		for _, cmd := range m {
			d.run(cmd)
		}
		return
	}
	v := reflect.ValueOf(msg)
	name := v.Type().Name()
	if name == "sequenceMsg" && v.Kind() == reflect.Slice {
		for i := range v.Len() {
			if cmd, ok := v.Index(i).Interface().(tea.Cmd); ok {
				d.run(cmd)
			}
		}
		return
	}
	if strings.HasSuffix(name, "TickMsg") {
		d.ticks++
		if d.ticks > d.maxTicks {
			return
		}
	}
	d.send(msg)
}

// settle delivers parked commands as they complete, until nothing has
// happened for a short while.
func (d *driver) settle() {
	for idle := 0; idle < 4; {
		if d.step() {
			idle = 0
			continue
		}
		idle++
		time.Sleep(15 * time.Millisecond)
	}
}

// step delivers one completed parked command, if any.
func (d *driver) step() bool {
	for i, ch := range d.parked {
		select {
		case msg := <-ch:
			d.parked = append(d.parked[:i:i], d.parked[i+1:]...)
			d.deliver(msg)
			return true
		default:
		}
	}
	return false
}

// push sends a chat event through the application channel.
func (d *driver) push(ev tui.ChatEvent) {
	d.chat <- ev
	d.settle()
}

// session sends a connection event through the session channel.
func (d *driver) session(ev client.Event) {
	d.events <- ev
	d.settle()
}

// keys presses each key in turn. Names such as "enter", "esc", "tab",
// "ctrl+n" and "alt+2" are special keys; anything else is typed.
func (d *driver) keys(names ...string) {
	for _, name := range names {
		d.send(keyPress(name))
		d.settle()
	}
}

// typeText types s one character at a time.
func (d *driver) typeText(s string) {
	for _, r := range s {
		d.send(tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	d.settle()
}

// command types a line and presses enter.
func (d *driver) command(line string) {
	d.typeText(line)
	d.keys("enter")
}

func keyPress(name string) tea.KeyPressMsg {
	switch name {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "tab":
		return tea.KeyPressMsg{Code: tea.KeyTab}
	}
	if rest, ok := strings.CutPrefix(name, "ctrl+"); ok {
		return tea.KeyPressMsg{Code: []rune(rest)[0], Mod: tea.ModCtrl}
	}
	if rest, ok := strings.CutPrefix(name, "alt+"); ok {
		return tea.KeyPressMsg{Code: []rune(rest)[0], Mod: tea.ModAlt}
	}
	r := []rune(name)[0]
	return tea.KeyPressMsg{Code: r, Text: name}
}

// screen returns the current screen as ANSI text.
func (d *driver) screen() string { return d.model.View().Content }

func demoPin() transport.Fingerprint {
	return transport.Fingerprint(sha256.Sum256([]byte("qchat-demo-relay")))
}

// newChat starts the chat interface with the demo backend in the given
// theme, at width×height, connected to the demo relay.
func newChat(theme string, width, height int, animate bool) *driver {
	d := &driver{
		chat:     make(chan tui.ChatEvent),
		events:   make(chan client.Event),
		maxTicks: 1 << 30,
	}
	if !animate {
		d.maxTicks = 0
	}
	d.model = tui.New(tui.Config{
		Addr:        demoAddr,
		Pin:         demoPin(),
		Events:      d.events,
		Backend:     newDemoBackend(theme),
		ChatEvents:  d.chat,
		Version:     demoVersion,
		Now:         func() time.Time { return clock },
		NoAnimation: !animate,
	})
	d.send(tea.WindowSizeMsg{Width: width, Height: height})
	d.run(d.model.Init())
	d.settle()
	if animate {
		return d
	}
	d.session(client.StateChanged{State: client.Connecting, Attempt: 1})
	d.session(client.StateChanged{State: client.Connected, Info: client.ConnectionInfo{
		Addr: demoAddr, Fingerprint: demoPin(), ProtocolVersion: protocol.Version,
		PingInterval: 15 * time.Second, MaxFrameSize: protocol.MaxFrameSize,
		Transport: client.TransportDescription, ConnectedAt: clock.Add(-47 * time.Minute),
	}})
	d.session(client.RTT{Duration: 38 * time.Millisecond})
	d.push(tui.SealedSenderChanged{Connected: true})
	return d
}

// Positions of the conversations reached with ctrl+n from System, before
// any message request arrives.
const (
	stepMara      = 1
	stepJonas     = 2
	stepLena      = 3
	stepNordlicht = 5
)

// open steps to a conversation with ctrl+n.
func (d *driver) open(steps int) {
	for range steps {
		d.keys("ctrl+n")
	}
}

// messageRequests delivers two messages from somebody who is not a
// contact.
func (d *driver) messageRequests() {
	d.push(tui.IncomingMessage{ContactID: stranger.compact(), UnknownSender: true,
		Message: in("r-1", 18, "Hi! Lena gave me your ID. I'm organising the climbing trip.")})
	d.push(tui.IncomingMessage{ContactID: stranger.compact(), UnknownSender: true,
		Message: in("r-2", 17, "Could you add me so we can plan the car pool?")})
}

// heroChat is the conversation with Mara used by the hero image and the
// theme gallery.
func heroChat(theme string, width, height int) *driver {
	d := newChat(theme, width, height, false)
	d.open(stepMara)
	d.push(tui.ConversationNotice{ConversationID: mara.compact(),
		Notice: "Mara set disappearing messages to 1 day. New messages are deleted that long after they are sent or received."})
	d.messageRequests()
	d.command("Looks **great**! Printing 40 copies on `Friday` 🎉")
	return d
}

// shot is one screenshot.
type shot struct {
	name    string
	title   string
	theme   string
	capture func() string
}

func shots() []shot {
	chatShot := func(name, title string, width, height int, script func(d *driver)) shot {
		return shot{name: name, title: title, theme: "phosphor", capture: func() string {
			d := newChat("phosphor", width, height, false)
			script(d)
			return d.screen()
		}}
	}
	list := []shot{
		{name: "hero", title: "qchat · Mara", theme: "phosphor", capture: func() string {
			return heroChat("phosphor", 120, 36).screen()
		}},
		chatShot("requests", "qchat · Requests", 100, 30, func(d *driver) {
			d.messageRequests()
			d.keys("alt+2")
		}),
		chatShot("group", "qchat · Team Nordlicht", 100, 30, func(d *driver) {
			d.open(stepNordlicht)
			d.push(tui.IncomingMessage{ContactID: lena.compact(), GroupID: nordlichtID,
				Message: from(lena, in("g-7", 1, "Then see you all on **Friday**!"))})
			d.command("Can someone mail the offline slides?")
			d.command("I'll bring the projector 🎥")
		}),
		chatShot("verify", "qchat · /verify", 120, 38, func(d *driver) {
			d.open(stepJonas)
			d.command("/verify")
		}),
		chatShot("whoami", "qchat · /whoami", 100, 30, func(d *driver) {
			d.open(stepMara)
			d.command("/whoami")
		}),
		chatShot("search", "qchat · /search", 100, 30, func(d *driver) {
			d.open(stepMara)
			d.command("/search all poster")
		}),
		chatShot("help", "qchat · /help", 100, 30, func(d *driver) {
			d.open(stepMara)
			d.command("/help")
		}),
		chatShot("system", "qchat · System", 100, 30, func(d *driver) {
			d.messageRequests()
			d.keys("alt+6")
			d.command("/status")
		}),
		chatShot("key-change", "qchat · Lena", 100, 30, func(d *driver) {
			d.open(stepLena)
			d.push(tui.ContactKeyChanged{ContactID: lena.compact()})
		}),
		chatShot("files", "qchat · Files", 100, 30, func(d *driver) {
			d.open(stepMara)
			d.messageRequests()
			d.keys("alt+5")
		}),
		{name: "create-profile", title: "qchat · new identity", theme: "phosphor", capture: createProfile},
		{name: "splash", title: "qchat", theme: "phosphor", capture: splash},
	}
	for _, theme := range []string{"phosphor", "neon", "matrix", "ice"} {
		list = append(list, shot{name: "theme-" + theme, title: "qchat · /theme " + theme, theme: theme, capture: func() string {
			return heroChat(theme, 100, 30).screen()
		}})
	}
	return list
}

// createProfile captures the first-run form with a name and part of a
// passphrase typed.
func createProfile() string {
	d := &driver{model: tui.NewCreateProfile(tui.CreateProfileConfig{NoAnimation: true})}
	d.send(tea.WindowSizeMsg{Width: 100, Height: 30})
	d.run(d.model.Init())
	d.settle()
	d.typeText("Robin")
	d.keys("tab")
	d.typeText("correct horse battery")
	return d.screen()
}

// splash captures the last frame of the start screen.
func splash() string {
	d := newChat("phosphor", 100, 30, true)
	d.maxTicks = tui.SplashFrames - 1
	deadline := time.Now().Add(5 * time.Second)
	for d.ticks < d.maxTicks && time.Now().Before(deadline) {
		if !d.step() {
			time.Sleep(10 * time.Millisecond)
		}
	}
	return d.screen()
}

func main() {
	outDir := flag.String("out", filepath.Join("docs", "screenshots"), "directory for the SVG files")
	ansiDir := flag.String("ansi", "", "also write the raw ANSI captures to this directory")
	only := flag.String("only", "", "render only the screenshot with this name")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, s := range shots() {
		if *only != "" && s.name != *only {
			continue
		}
		screen := s.capture()
		theme, _ := tui.ThemeByName(s.theme)
		svg := renderSVG(screen, svgOptions{
			title:      s.title,
			background: hexColor(theme.Background, "#0B0906"),
			foreground: hexColor(theme.Text, "#E6E6E6"),
		})
		path := filepath.Join(*outDir, s.name+".svg")
		if err := os.WriteFile(path, []byte(svg), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if *ansiDir != "" {
			if err := os.MkdirAll(*ansiDir, 0o755); err == nil {
				_ = os.WriteFile(filepath.Join(*ansiDir, s.name+".ans"), []byte(screen), 0o644)
			}
		}
		fmt.Printf("%-16s %6.1f KB  %s\n", s.name, float64(len(svg))/1024, path)
	}
}

// hexColor formats c as #rrggbb, or returns fallback for nil.
func hexColor(c color.Color, fallback string) string {
	if c == nil {
		return fallback
	}
	r, g, b, _ := c.RGBA()
	return fmt.Sprintf("#%02x%02x%02x", r>>8, g>>8, b>>8)
}
