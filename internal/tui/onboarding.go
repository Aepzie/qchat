package tui

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// MinPassphraseRunes is the minimum passphrase length, in characters.
const MinPassphraseRunes = 12

// Onboarding limits and timings.
const (
	maxSecretRunes     = 1024
	cardMinWidth       = 34
	cardMinHeight      = 16
	cardMaxWidth       = 60
	unlockFreeAttempts = 5
	unlockBaseDelay    = 5 * time.Second
	unlockMaxDelay     = 60 * time.Second
)

// ErrWrongPassphrase is returned by an UnlockConfig.Unlock function when
// the passphrase does not open the identity. Other errors are shown as
// they are.
var ErrWrongPassphrase = errors.New("wrong passphrase")

// ProfileSubmitted is emitted by CreateProfileModel when the form is valid.
// The receiver owns Passphrase and should overwrite it with zeros once the
// key has been derived.
type ProfileSubmitted struct {
	DisplayName string
	Passphrase  []byte
}

// OnboardingCancelled is emitted when the user leaves an onboarding model
// with esc or ctrl+c.
type OnboardingCancelled struct{}

// Unlocked is emitted by UnlockModel after Unlock succeeded.
type Unlocked struct{}

// field is a single-line text input. Secret fields render one bullet per
// character and never their content. The buffer grows by copying into a
// larger one and zeroing the old, so no stale copy of a secret stays behind
// in memory the field owns; key events and the terminal's own buffers are
// beyond its reach.
type field struct {
	value  []rune
	secret bool
}

func (f *field) insert(s string) {
	for _, r := range s {
		if r == '\t' || r == '\n' || r == '\r' || unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			continue
		}
		if len(f.value) >= maxSecretRunes {
			return
		}
		if len(f.value) == cap(f.value) {
			grown := make([]rune, len(f.value), max(2*cap(f.value), 64))
			copy(grown, f.value)
			clear(f.value[:cap(f.value)])
			f.value = grown
		}
		f.value = append(f.value, r)
	}
}

func (f *field) backspace() {
	if n := len(f.value); n > 0 {
		f.value[n-1] = 0
		f.value = f.value[:n-1]
	}
}

// wipe zeroes and empties the buffer.
func (f *field) wipe() {
	clear(f.value[:cap(f.value)])
	f.value = f.value[:0]
}

func (f *field) runes() int { return len(f.value) }

func (f *field) text() string { return string(f.value) }

// bytes returns the value as UTF-8 in a new buffer of exactly the right
// size, without an intermediate string.
func (f *field) bytes() []byte {
	n := 0
	for _, r := range f.value {
		n += utf8.RuneLen(r)
	}
	out := make([]byte, 0, n)
	for _, r := range f.value {
		out = utf8.AppendRune(out, r)
	}
	return out
}

// equal reports whether two fields hold the same text.
func (f *field) equal(g *field) bool {
	if len(f.value) != len(g.value) {
		return false
	}
	for i := range f.value {
		if f.value[i] != g.value[i] {
			return false
		}
	}
	return true
}

// prefixOf reports whether f's text is a proper prefix of g's.
func (f *field) prefixOf(g *field) bool {
	if len(f.value) >= len(g.value) {
		return false
	}
	for i := range f.value {
		if f.value[i] != g.value[i] {
			return false
		}
	}
	return true
}

// handleKey edits the field; it reports whether the key was consumed.
func (f *field) handleKey(msg tea.KeyPressMsg) bool {
	switch msg.String() {
	case "backspace", "ctrl+h":
		f.backspace()
		return true
	case "ctrl+u":
		f.wipe()
		return true
	}
	k := msg.Key()
	if k.Text == "" || k.Mod&(tea.ModCtrl|tea.ModAlt|tea.ModMeta|tea.ModSuper|tea.ModHyper) != 0 {
		return false
	}
	f.insert(k.Text)
	return true
}

// render draws the field's input row at width cells.
func (f *field) render(st styles, focused bool, width int) string {
	prompt := st.faint.Render("› ")
	if focused {
		prompt = st.accent.Bold(true).Render("› ")
	}
	room := max(width-3, 1)
	var shown string
	if f.secret {
		shown = strings.Repeat("•", min(len(f.value), room))
	} else {
		shown = string(f.value)
		for lipgloss.Width(shown) > room {
			_, size := utf8.DecodeRuneInString(shown)
			shown = shown[size:]
		}
	}
	line := prompt + st.text.Render(shown)
	if focused {
		line += lipgloss.NewStyle().Background(st.theme.Accent).Render(" ")
	}
	return line
}

// renderCard draws a centered card with a title, a subtitle and body
// lines, filling exactly width×height cells.
func renderCard(st styles, width, height int, title, subtitle string, body func(inner int) []string) string {
	if width < cardMinWidth || height < cardMinHeight {
		return renderTooSmall(st, width, height, cardMinWidth, cardMinHeight)
	}
	cardW := min(cardMaxWidth, width-2)
	inner := cardW - 6
	lines := []string{st.accent.Bold(true).Render(truncate(title, inner))}
	for _, l := range wrapLines(subtitle, inner) {
		lines = append(lines, st.muted.Render(l))
	}
	lines = append(lines, "")
	lines = append(lines, body(inner)...)
	for i, l := range lines {
		lines[i] = padRight(truncateStyled(l, inner), inner, lipgloss.NewStyle())
	}
	card := st.card.Render(strings.Join(lines, "\n"))
	return clamp(lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, card), width, height)
}

// cardView wraps rendered card content in a tea.View.
func cardView(content string) tea.View {
	v := tea.NewView(content)
	v.AltScreen = true
	v.WindowTitle = "qchat"
	return v
}

// CreateProfileConfig configures a CreateProfileModel.
type CreateProfileConfig struct {
	// Theme selects colors; the zero value means DefaultTheme.
	Theme Theme
	// QuitWhenDone makes the model end the program when the form is
	// submitted or cancelled, for use as a program of its own. Read the
	// outcome with Result and Cancelled afterwards. Otherwise the model
	// emits ProfileSubmitted or OnboardingCancelled.
	QuitWhenDone bool
}

// CreateProfileModel asks for a display name and a passphrase, twice.
type CreateProfileModel struct {
	cfg           CreateProfileConfig
	st            styles
	width, height int
	focus         int
	name          field
	pass, confirm field
	errText       string
	result        ProfileSubmitted
	done          bool
	cancelled     bool
}

// NewCreateProfile returns a CreateProfileModel with the name field focused.
func NewCreateProfile(cfg CreateProfileConfig) CreateProfileModel {
	return CreateProfileModel{
		cfg:     cfg,
		st:      newStyles(cfg.Theme),
		pass:    field{secret: true},
		confirm: field{secret: true},
	}
}

// Result returns the submitted profile, and false before submission. The
// caller owns the passphrase and should zero it after use.
func (m CreateProfileModel) Result() (ProfileSubmitted, bool) { return m.result, m.done }

// Cancelled reports whether the user cancelled.
func (m CreateProfileModel) Cancelled() bool { return m.cancelled }

// Init implements tea.Model.
func (m CreateProfileModel) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (m CreateProfileModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.done || m.cancelled {
		return m, nil
	}
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.PasteMsg:
		m.focused().insert(msg.Content)
		m.errText = ""
	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *CreateProfileModel) focused() *field {
	switch m.focus {
	case 1:
		return &m.pass
	case 2:
		return &m.confirm
	}
	return &m.name
}

func (m CreateProfileModel) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "esc":
		m.wipeAll()
		m.cancelled = true
		return m, m.finish(OnboardingCancelled{})
	case "tab", "down":
		m.focus = (m.focus + 1) % 3
		return m, nil
	case "shift+tab", "up":
		m.focus = (m.focus + 2) % 3
		return m, nil
	case "enter":
		if m.focus < 2 {
			m.focus++
			return m, nil
		}
		return m.submit()
	}
	if m.focused().handleKey(msg) {
		m.errText = ""
	}
	return m, nil
}

func (m CreateProfileModel) submit() (tea.Model, tea.Cmd) {
	name := cleanLine(m.name.text(), maxNameRunes)
	switch {
	case name == "":
		m.errText, m.focus = "Enter a display name. It stays on this device.", 0
		return m, nil
	case m.pass.runes() < MinPassphraseRunes:
		m.errText, m.focus = fmt.Sprintf("The passphrase needs at least %d characters.", MinPassphraseRunes), 1
		return m, nil
	case !m.pass.equal(&m.confirm):
		m.errText, m.focus = "The passphrases do not match. Type it again.", 2
		m.confirm.wipe()
		return m, nil
	}
	m.result = ProfileSubmitted{DisplayName: name, Passphrase: m.pass.bytes()}
	m.wipeAll()
	m.done = true
	return m, m.finish(m.result)
}

func (m *CreateProfileModel) wipeAll() {
	m.name.wipe()
	m.pass.wipe()
	m.confirm.wipe()
}

func (m CreateProfileModel) finish(msg tea.Msg) tea.Cmd {
	if m.cfg.QuitWhenDone {
		return tea.Quit
	}
	return func() tea.Msg { return msg }
}

// View implements tea.Model.
func (m CreateProfileModel) View() tea.View {
	if m.width <= 0 || m.height <= 0 {
		return cardView("")
	}
	st := m.st
	return cardView(renderCard(st, m.width, m.height, "Create your qchat identity",
		"Your keys are generated on this device and encrypted with your passphrase. There is no recovery if you forget it.",
		func(inner int) []string {
			var lines []string
			lines = append(lines, st.muted.Render("Display name"), m.name.render(st, m.focus == 0, inner))
			lines = append(lines, st.faint.Render("shown to you only; never sent"), "")
			lines = append(lines, st.muted.Render("Passphrase"), m.pass.render(st, m.focus == 1, inner), m.lengthHint(), "")
			lines = append(lines, st.muted.Render("Confirm passphrase"), m.confirm.render(st, m.focus == 2, inner), m.matchHint(), "")
			if m.errText != "" {
				for _, l := range wrapLines(m.errText, inner) {
					lines = append(lines, st.danger.Render(l))
				}
			}
			lines = append(lines, st.faint.Render(truncate("tab next field · enter continue · esc cancel", inner)))
			return lines
		}))
}

func (m CreateProfileModel) lengthHint() string {
	n := m.pass.runes()
	switch {
	case n == 0:
		return m.st.faint.Render(fmt.Sprintf("at least %d characters; a few random words work well", MinPassphraseRunes))
	case n < MinPassphraseRunes:
		return m.st.warn.Render(fmt.Sprintf("%d more characters needed", MinPassphraseRunes-n))
	}
	return m.st.ok.Render("✓ long enough")
}

func (m CreateProfileModel) matchHint() string {
	switch {
	case m.confirm.runes() == 0:
		return ""
	case m.pass.equal(&m.confirm):
		return m.st.ok.Render("✓ matches")
	case m.confirm.prefixOf(&m.pass):
		return m.st.faint.Render("keep typing")
	}
	return m.st.danger.Render("does not match")
}

// UnlockConfig configures an UnlockModel.
type UnlockConfig struct {
	// Unlock tries a passphrase. It runs in a tea.Cmd, may take a moment
	// (key derivation) and must not keep the slice, which is zeroed after
	// it returns. It returns ErrWrongPassphrase for a wrong passphrase.
	Unlock func(passphrase []byte) error
	// Hint is an optional line under the title, such as the profile path.
	Hint string
	// Theme selects colors; the zero value means DefaultTheme.
	Theme Theme
	// QuitWhenDone makes the model end the program after unlocking or
	// cancelling. Otherwise it emits Unlocked or OnboardingCancelled.
	QuitWhenDone bool
	// Now returns the current time, for the retry delay. Nil means time.Now.
	Now func() time.Time
}

type (
	unlockResultMsg struct{ err error }
	unlockTickMsg   struct{}
)

// UnlockModel asks for the passphrase of an existing identity. After
// unlockFreeAttempts wrong guesses every further attempt waits, with the
// delay doubling up to unlockMaxDelay.
type UnlockModel struct {
	cfg           UnlockConfig
	st            styles
	width, height int
	pass          field
	busy          bool
	failures      int
	waitUntil     time.Time
	errText       string
	done          bool
	cancelled     bool
}

// NewUnlock returns an UnlockModel.
func NewUnlock(cfg UnlockConfig) UnlockModel {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return UnlockModel{cfg: cfg, st: newStyles(cfg.Theme), pass: field{secret: true}}
}

// Unlocked reports whether Unlock succeeded.
func (m UnlockModel) Unlocked() bool { return m.done }

// Cancelled reports whether the user cancelled.
func (m UnlockModel) Cancelled() bool { return m.cancelled }

// Failures returns the number of wrong passphrases entered.
func (m UnlockModel) Failures() int { return m.failures }

// Init implements tea.Model.
func (m UnlockModel) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (m UnlockModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.done || m.cancelled {
		return m, nil
	}
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.PasteMsg:
		if !m.busy {
			m.pass.insert(msg.Content)
		}
	case unlockResultMsg:
		return m.handleResult(msg.err)
	case unlockTickMsg:
		if m.waiting() {
			return m, unlockTick()
		}
	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m UnlockModel) waiting() bool { return m.cfg.Now().Before(m.waitUntil) }

func unlockTick() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return unlockTickMsg{} })
}

func (m UnlockModel) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "esc":
		m.pass.wipe()
		m.cancelled = true
		return m, m.finish(OnboardingCancelled{})
	case "enter":
		return m.submit()
	}
	if !m.busy {
		m.pass.handleKey(msg)
	}
	return m, nil
}

func (m UnlockModel) submit() (tea.Model, tea.Cmd) {
	if m.busy || m.waiting() || m.cfg.Unlock == nil {
		return m, nil
	}
	if m.pass.runes() == 0 {
		m.errText = "Enter your passphrase."
		return m, nil
	}
	secret := m.pass.bytes()
	m.pass.wipe()
	m.busy, m.errText = true, ""
	unlock := m.cfg.Unlock
	return m, func() tea.Msg {
		err := unlock(secret)
		clear(secret)
		return unlockResultMsg{err: err}
	}
}

func (m UnlockModel) handleResult(err error) (tea.Model, tea.Cmd) {
	m.busy = false
	switch {
	case err == nil:
		m.done = true
		return m, m.finish(Unlocked{})
	case errors.Is(err, ErrWrongPassphrase):
		m.failures++
		m.errText = "Wrong passphrase. Try again."
		if m.failures < unlockFreeAttempts {
			return m, nil
		}
		delay := min(unlockBaseDelay<<min(m.failures-unlockFreeAttempts, 8), unlockMaxDelay)
		m.waitUntil = m.cfg.Now().Add(delay)
		return m, unlockTick()
	}
	m.errText = "Cannot unlock: " + describeBackendError(err) + "."
	return m, nil
}

func (m UnlockModel) finish(msg tea.Msg) tea.Cmd {
	if m.cfg.QuitWhenDone {
		return tea.Quit
	}
	return func() tea.Msg { return msg }
}

// View implements tea.Model.
func (m UnlockModel) View() tea.View {
	if m.width <= 0 || m.height <= 0 {
		return cardView("")
	}
	st := m.st
	hint := cleanLine(m.cfg.Hint, 200)
	if hint == "" {
		hint = "Enter the passphrase that protects your identity on this device."
	}
	return cardView(renderCard(st, m.width, m.height, "Unlock qchat", hint, func(inner int) []string {
		lines := []string{st.muted.Render("Passphrase"), m.pass.render(st, !m.busy, inner), ""}
		switch {
		case m.busy:
			lines = append(lines, st.muted.Render("Unlocking…"))
		case m.waiting():
			left := m.waitUntil.Sub(m.cfg.Now()).Round(time.Second)
			lines = append(lines, st.warn.Render(truncate(fmt.Sprintf("Too many attempts. Try again in %s.", max(left, time.Second)), inner)))
		case m.errText != "":
			for _, l := range wrapLines(m.errText, inner) {
				lines = append(lines, st.danger.Render(l))
			}
		default:
			lines = append(lines, "")
		}
		return append(lines, "", st.faint.Render(truncate("enter unlock · esc quit", inner)))
	}))
}
