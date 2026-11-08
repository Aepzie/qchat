package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Aepzie/qchat/internal/crypto/safety"
	"github.com/Aepzie/qchat/internal/identity"
	"github.com/Aepzie/qchat/internal/tui"
)

// clock is the fixed "now" of every screenshot.
var clock = time.Date(2026, 11, 7, 14, 32, 0, 0, time.UTC)

// at returns a time minutes before clock.
func at(minutesAgo int) time.Time {
	return clock.Add(-time.Duration(minutesAgo) * time.Minute)
}

// person is a fictional identity of the demo.
type person struct {
	name string
	id   identity.ID
	key  []byte
}

// newPerson derives a stable, well-formed identity ID from a seed, so the
// screenshots do not change between runs.
func newPerson(name, seed string) person {
	key := sha256.Sum256([]byte("qchat-demo-signing-key:" + seed))
	id := identity.ID(sha256.Sum256([]byte("qchat-demo-identity:" + seed)))
	return person{name: name, id: id, key: key[:]}
}

// compact is the canonical form the interface uses: "qc1-" and 52
// characters without separators.
func (p person) compact() string {
	return identity.IDPrefix + strings.ReplaceAll(strings.TrimPrefix(p.id.String(), identity.IDPrefix), "-", "")
}

func (p person) short() string { return p.id.ShortString() }

var (
	self     = newPerson("Robin", "robin")
	mara     = newPerson("Mara", "mara")
	jonas    = newPerson("Jonas", "jonas")
	lena     = newPerson("Lena", "lena")
	theo     = newPerson("Theo", "theo")
	stranger = newPerson("", "stranger")
	inviter  = newPerson("", "inviter")
)

// groupKey derives a stable group ID.
func groupKey(seed string) string {
	sum := sha256.Sum256([]byte("qchat-demo-group:" + seed))
	const hex = "0123456789abcdef"
	var b strings.Builder
	b.WriteString("grp-")
	for _, c := range sum {
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

var (
	nordlichtID = groupKey("nordlicht")
	boulderID   = groupKey("boulder")
)

// demoBackend implements tui.Backend and its optional interfaces with
// fixed, fictional data.
type demoBackend struct {
	mu       sync.Mutex
	contacts []tui.ContactInfo
	groups   []tui.GroupInfo
	history  map[string][]tui.MessageInfo
	settings map[string]string
}

var (
	_ tui.Backend         = (*demoBackend)(nil)
	_ tui.SettingsBackend = (*demoBackend)(nil)
	_ tui.SearchBackend   = (*demoBackend)(nil)
	_ tui.FileBackend     = (*demoBackend)(nil)
	_ tui.TimerBackend    = (*demoBackend)(nil)
)

func contact(p person, verified, keyChanged bool, unread int) tui.ContactInfo {
	return tui.ContactInfo{ID: p.compact(), ShortID: p.short(), DisplayName: p.name, Verified: verified, KeyChanged: keyChanged, Unread: unread}
}

func member(p person, admin, isSelf bool) tui.GroupMember {
	m := tui.GroupMember{ID: p.compact(), ShortID: p.short(), Admin: admin, Self: isSelf}
	if !isSelf && p.name != "" {
		m.DisplayName = p.name
	}
	return m
}

func in(id string, minutesAgo int, text string) tui.MessageInfo {
	return tui.MessageInfo{ID: id, Text: text, Sent: at(minutesAgo), Received: at(minutesAgo)}
}

func out(id string, minutesAgo int, text string, status tui.MessageStatus, route tui.SendRoute) tui.MessageInfo {
	return tui.MessageInfo{ID: id, Outgoing: true, Text: text, Sent: at(minutesAgo), Status: status, Route: route}
}

func from(p person, msg tui.MessageInfo) tui.MessageInfo {
	msg.From = p.compact()
	return msg
}

// newDemoBackend returns the demo data. theme is stored as the ui.theme
// setting, so the interface starts with it.
func newDemoBackend(theme string) *demoBackend {
	b := &demoBackend{
		contacts: []tui.ContactInfo{
			contact(mara, true, false, 0),
			contact(jonas, false, false, 2),
			contact(lena, false, true, 0),
			contact(theo, true, false, 0),
		},
		settings: map[string]string{tui.SettingTheme: theme, tui.SettingMarkdown: "on"},
	}
	members := []tui.GroupMember{member(self, true, true), member(mara, true, false), member(jonas, false, false), member(lena, false, false)}
	slices.SortFunc(members, func(a, c tui.GroupMember) int { return strings.Compare(a.ID, c.ID) })
	b.groups = []tui.GroupInfo{
		{ID: nordlichtID, Name: "Team Nordlicht", Members: members, Unread: 3},
		{ID: boulderID, Name: "Bouldering Sunday", Invite: true, Members: []tui.GroupMember{
			member(self, false, true), member(inviter, true, false), member(stranger, false, false),
		}},
	}

	poster := in("m-6", 9, "nordlicht-poster-final.pdf")
	poster.File = &tui.FileInfo{Name: "nordlicht-poster-final.pdf", Size: 2_481_152, MIME: "application/pdf", State: tui.FileReceiving, Done: 37, Total: 52}

	b.history = map[string][]tui.MessageInfo{
		mara.compact(): {
			in("m-1", 41, "Morning! Is the **relay** back up?"),
			out("m-2", 39, "Yes, on `qchat-server 0.8` now. Still to do:\n- rotate the server pin\n- update the docs", tui.StatusSent, tui.RouteIdentified),
			in("m-3", 30, "Perfect. Here's the poster for **Friday**:"),
			poster,
		},
		jonas.compact(): {
			in("j-1", 95, "Are we still on for the Nordlicht review tomorrow?"),
			out("j-2", 90, "Yes, 10:00 at the usual place.", tui.StatusSent, tui.RouteSealed),
			in("j-3", 6, "I'll bring the printed **agenda**."),
			in("j-4", 5, "And the `v2` slides."),
		},
		lena.compact(): {
			in("l-1", 240, "New phone, who dis 😄"),
			out("l-2", 236, "Ha! Let me check the safety number first.", tui.StatusSent, tui.RouteSealed),
		},
		theo.compact(): {
			in("t-1", 600, "Thanks for the invite link!"),
		},
		nordlichtID: {
			from(mara, in("g-1", 55, "Kick-off for **Nordlicht** is Friday at 18:00.")),
			from(jonas, in("g-2", 52, "I'll book the room. Who brings the projector?")),
			out("g-3", 50, "I will. Agenda:\n\n1. demo of the new relay\n2. poster review\n3. pizza", tui.StatusSent, tui.RouteSealed),
			from(lena, in("g-4", 21, "Count me in 🙌")),
			from(mara, in("g-5", 4, "Poster draft is in our chat with Robin, comments welcome.")),
			from(jonas, in("g-6", 2, "Room 2.14 is booked ✔")),
		},
		boulderID: {
			from(inviter, in("b-1", 70, "Welcome! We climb every Sunday at 11.")),
		},
	}
	return b
}

func (b *demoBackend) Self() tui.SelfInfo {
	return tui.SelfInfo{DisplayName: self.name, ID: self.compact(), ShortID: self.short()}
}

func (b *demoBackend) Contacts() ([]tui.ContactInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.contacts), nil
}

func (b *demoBackend) History(id string, limit int) ([]tui.MessageInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	msgs := b.history[id]
	return slices.Clone(msgs[max(0, len(msgs)-limit):]), nil
}

func (b *demoBackend) AddContact(_ context.Context, id, name string) (tui.ContactInfo, error) {
	return tui.ContactInfo{}, errors.New("not available in the demo")
}

func (b *demoBackend) RenameContact(string, string) error { return nil }
func (b *demoBackend) RemoveContact(string) error         { return nil }

// Send fails for messages that mention "offline", never answers for
// messages that mention "projector", so they stay in the sending state, and
// otherwise succeeds over sealed sender.
func (b *demoBackend) Send(ctx context.Context, id, text string) (tui.MessageInfo, error) {
	switch {
	case strings.Contains(text, "offline"):
		return tui.MessageInfo{}, errors.New("relay unreachable")
	case strings.Contains(text, "projector"):
		<-ctx.Done()
		return tui.MessageInfo{}, ctx.Err()
	}
	return tui.MessageInfo{ID: "sent-" + text, Outgoing: true, Text: text, Sent: clock, Status: tui.StatusSent, Route: tui.RouteSealed}, nil
}

func (b *demoBackend) Verification(id string) (tui.VerificationInfo, error) {
	var other person
	for _, p := range []person{mara, jonas, lena, theo} {
		if p.compact() == id {
			other = p
		}
	}
	info := tui.VerificationInfo{
		SafetyNumber: safety.Number(self.id, self.key, other.id, other.key),
		QRPayload:    safety.QRPayload(self.id, self.key, other.id, other.key),
	}
	for _, c := range b.contacts {
		if c.ID == id {
			info.Verified, info.KeyChanged = c.Verified, c.KeyChanged
		}
	}
	return info, nil
}

func (b *demoBackend) MarkVerified(string, bool) error { return nil }
func (b *demoBackend) MarkRead(string) error           { return nil }

func (b *demoBackend) Groups() ([]tui.GroupInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.groups), nil
}

func (b *demoBackend) CreateGroup(context.Context, string, []string) (tui.GroupInfo, error) {
	return tui.GroupInfo{}, errors.New("not available in the demo")
}

func (b *demoBackend) ChangeGroup(context.Context, string, tui.GroupChange) (tui.GroupInfo, error) {
	return tui.GroupInfo{}, errors.New("not available in the demo")
}

func (b *demoBackend) GetSetting(name string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.settings[name], nil
}

func (b *demoBackend) SetSetting(name, value string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings[name] = value
	return nil
}

func (b *demoBackend) Search(_ context.Context, query, conversationID string, limit int) ([]tui.SearchHit, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var hits []tui.SearchHit
	for conv, msgs := range b.history {
		if conversationID != "" && conv != conversationID {
			continue
		}
		for _, msg := range msgs {
			if !strings.Contains(strings.ToLower(msg.Text), strings.ToLower(query)) {
				continue
			}
			when := msg.Received
			if msg.Outgoing {
				when = msg.Sent
			}
			hits = append(hits, tui.SearchHit{ConversationID: conv, MessageID: msg.ID, Outgoing: msg.Outgoing, From: msg.From, Text: msg.Text, At: when})
		}
	}
	slices.SortFunc(hits, func(a, c tui.SearchHit) int { return c.At.Compare(a.At) })
	return hits[:min(len(hits), limit)], nil
}

func (b *demoBackend) SendFile(context.Context, string, string) (tui.MessageInfo, error) {
	return tui.MessageInfo{}, errors.New("not available in the demo")
}

func (b *demoBackend) SaveFile(context.Context, string, string, string) (string, error) {
	return "", errors.New("not available in the demo")
}

func (b *demoBackend) SetTimer(context.Context, string, time.Duration) error { return nil }

func (b *demoBackend) Timer(conversationID string) (time.Duration, error) {
	if conversationID == mara.compact() {
		return 24 * time.Hour, nil
	}
	return 0, nil
}
