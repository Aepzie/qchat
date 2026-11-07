// Package app is the application layer of the qchat client. It connects the
// unlocked profile (identity and encrypted database) with the relay session
// and implements tui.Backend on top of both.
//
// Messages are end-to-end encrypted with the Phase 3 construction of
// docs/design/phase-3-forward-secrecy.md: a session per contact, started
// asynchronously from the contact's prekeys (package handshake) and
// continued with the KEM double ratchet (package ratchet), carried in the
// envelopes of package e2e. The App keeps its own prekeys stocked on the
// relay (see prekeys.go) and implements the session rules (see sessions.go).
// Groups (docs/design/phase-4-groups.md) are built on top: signed controls
// and sender keys travel over the pairwise sessions, group messages are
// encrypted once with the sender's sender key and fanned out by the relay
// (see groups.go for the rules, groupapi.go for the interface side).
//
// Behaviour worth knowing:
//
//   - Messages from identities that are not contacts are message requests.
//     Their text is kept in memory only and never written to disk; it is
//     persisted when the user adds the sender as a contact, and lost when
//     the client exits before that. The ratchet session with the sender is
//     stored, so the conversation can continue after the sender is added.
//   - Removing a contact deletes its messages but keeps the ratchet
//     session, so a later message from that identity is still readable
//     (as a message request).
//   - Unread counts are kept in memory and start at zero on every launch.
//   - Payloads that do not decrypt or verify, and replayed messages, are
//     dropped silently; they never reach the interface.
//   - The relay stores every message until the recipient acknowledges it.
//     The App acknowledges a delivery once it has been durably processed,
//     or once it is certain never to become readable (malformed, forged,
//     replayed, undecryptable). It does not acknowledge deliveries it could
//     not process because of a local failure, such as a database error: the
//     relay delivers those again after the next authentication.
//   - A contact's bundle is refreshed from the relay whenever the user adds
//     an existing contact again, starts a session, or receives a session
//     start. A newer bundle (higher serial) with a different encryption key
//     marks the contact as changed and unverified; a bundle with an equal or
//     lower serial that differs from the stored one is ignored, because only
//     the relay could produce such a rollback.
package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/craguS/qchat/internal/client"
	"github.com/craguS/qchat/internal/group"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/profile"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/store/clientdb"
	"github.com/craguS/qchat/internal/transport"
	"github.com/craguS/qchat/internal/tui"
)

const (
	// requestTimeout bounds one relay round trip made by the App itself.
	requestTimeout = 15 * time.Second
	// eventBuffer is the capacity of the channels the App feeds.
	eventBuffer = 64
	// maxRequestSenders and maxRequestMessages bound the memory held by
	// message requests from unknown senders.
	maxRequestSenders  = 64
	maxRequestMessages = 100
)

// Requester is the authenticated relay session as the App uses it.
// *client.Session implements it.
type Requester interface {
	// Request sends a request and returns the response frame.
	Request(ctx context.Context, t protocol.FrameType, body any) (protocol.Frame, error)
	// Ack tells the relay that the delivery with the given queue ID has
	// been processed.
	Ack(queueID uint64) error
}

// App owns the unlocked profile while the client runs. It is safe for
// concurrent use.
type App struct {
	prof    *profile.Profile
	invite  string
	self    *identity.Bundle
	selfRaw []byte
	now     func() time.Time

	sessMu sync.RWMutex
	sess   Requester

	tuiEvents chan client.Event
	chat      chan tui.ChatEvent
	done      chan struct{}
	stopOnce  sync.Once
	runOnce   sync.Once

	emitMu sync.RWMutex
	closed bool

	// groupMu serialises every change of group states and sender keys and
	// the processing of deliveries, so that group input is applied in
	// order; pending holds group input that waits (see groups.go). It is
	// taken before ratchetMu.
	groupMu sync.Mutex
	pending []pendingGroup

	// ratchetMu serialises every use of the stored ratchet sessions and of
	// shadows and handshakes, so that a session is never loaded, advanced
	// and written back by two goroutines at once. It is taken before mu.
	ratchetMu  sync.Mutex
	shadows    map[identity.ID]shadowSession
	handshakes map[identity.ID][]time.Time

	// maintMu makes prekey maintenance single-flight; bg tracks the
	// goroutines running it; maintRuns counts finished runs.
	maintMu   sync.Mutex
	bg        sync.WaitGroup
	maintRuns atomic.Int64

	mu       sync.Mutex
	unread   map[identity.ID]int
	requests map[identity.ID][]clientdb.Message
	inflight map[messageKey]struct{}
	// groupUnread counts unread group messages; bundles caches the bundles
	// of group members who are not contacts.
	groupUnread map[group.ID]int
	bundles     map[identity.ID]*identity.Bundle
	// onboarding holds control histories received for groups the user is
	// being added to; groupStatus the relay result of group messages sent
	// in this run; backlogUntil when the backlog after connecting is
	// considered processed (wall clock).
	// groupOutOfSync records whether the last message received in a group
	// was sent from a different group state than the own.
	groupOutOfSync map[group.ID]bool
	onboarding     map[onboardKey][][]byte
	groupStatus    map[messageKey]uint8
	backlogUntil   time.Time
	dropped        int
	denied         *client.RegistrationDenied
}

// New returns an App for an unlocked profile. invite is the invite code
// sent when the identity registers with the relay; it may be empty. Attach
// the session with UseSession before the interface starts.
func New(p *profile.Profile, invite string) (*App, error) {
	if p == nil || p.Identity == nil || p.DB == nil {
		return nil, errors.New("app: profile is not unlocked")
	}
	raw, err := p.Bundle(time.Now())
	if err != nil {
		return nil, err
	}
	self, err := identity.ParseBundleForID(raw, p.Identity.ID())
	if err != nil {
		return nil, fmt.Errorf("app: own bundle is invalid: %w", err)
	}
	return &App{
		prof:           p,
		invite:         invite,
		self:           self,
		selfRaw:        raw,
		now:            time.Now,
		tuiEvents:      make(chan client.Event, eventBuffer),
		chat:           make(chan tui.ChatEvent, eventBuffer),
		done:           make(chan struct{}),
		unread:         map[identity.ID]int{},
		requests:       map[identity.ID][]clientdb.Message{},
		inflight:       map[messageKey]struct{}{},
		groupUnread:    map[group.ID]int{},
		bundles:        map[identity.ID]*identity.Bundle{},
		onboarding:     map[onboardKey][][]byte{},
		groupOutOfSync: map[group.ID]bool{},
		groupStatus:    map[messageKey]uint8{},
		shadows:        map[identity.ID]shadowSession{},
		handshakes:     map[identity.ID][]time.Time{},
	}, nil
}

// UseSession sets the relay session used for key lookups and sending.
func (a *App) UseSession(s Requester) {
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	a.sess = s
}

func (a *App) session() Requester {
	a.sessMu.RLock()
	defer a.sessMu.RUnlock()
	return a.sess
}

// Authenticator returns the credentials the session uses to register and
// authenticate the profile's identity.
func (a *App) Authenticator() client.Authenticator {
	return authenticator{ident: a.prof.Identity, bundle: a.selfRaw, invite: a.invite}
}

// AuthOnly returns credentials that authenticate ident but carry no bundle
// to register. They are meant for a session that authenticates without
// registering, such as the one that looks up the relay's copy of the own
// bundle while a profile is recovered.
func AuthOnly(ident *identity.Identity) client.Authenticator {
	return authenticator{ident: ident}
}

// TUIEvents returns the session events for tui.Config.Events. Run forwards
// every session event except deliveries, which it handles itself, and
// closes the channel when it returns.
func (a *App) TUIEvents() <-chan client.Event { return a.tuiEvents }

// ChatEvents returns the channel for tui.Config.ChatEvents. It is closed
// when Run returns.
func (a *App) ChatEvents() <-chan tui.ChatEvent { return a.chat }

// RegistrationDenied returns the relay's refusal to register the identity,
// if the session reported one.
func (a *App) RegistrationDenied() (client.RegistrationDenied, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.denied == nil {
		return client.RegistrationDenied{}, false
	}
	return *a.denied, true
}

// Run consumes session events until ctx is cancelled or events is closed.
// Whenever the session becomes Connected, and every
// prekeyMaintenanceInterval while Run runs, it maintains the own prekeys on
// the relay in the background. It must be called at most once.
func (a *App) Run(ctx context.Context, events <-chan client.Event) {
	defer a.shutdown()
	stop := context.AfterFunc(ctx, a.stopEmitting)
	defer stop()
	ticker := time.NewTicker(prekeyMaintenanceInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.startMaintenance(ctx)
		case ev, ok := <-events:
			if !ok {
				return
			}
			if !a.handleEvent(ctx, ev) {
				continue
			}
			select {
			case a.tuiEvents <- ev:
			case <-ctx.Done():
				return
			}
		}
	}
}

// handleEvent processes an event and reports whether it should be forwarded
// to the interface.
func (a *App) handleEvent(ctx context.Context, ev client.Event) bool {
	switch e := ev.(type) {
	case client.Delivery:
		a.noteDelivery()
		a.handleDelivery(ctx, e)
		return false
	case client.StateChanged:
		if e.State == client.Connected {
			a.noteConnected()
			a.startMaintenance(ctx)
		}
	case client.RegistrationDenied:
		a.mu.Lock()
		a.denied = &e
		a.mu.Unlock()
	}
	return true
}

// stopEmitting releases every emit blocked on a stalled interface.
func (a *App) stopEmitting() {
	a.stopOnce.Do(func() { close(a.done) })
}

func (a *App) shutdown() {
	a.runOnce.Do(func() {
		a.stopEmitting()
		a.bg.Wait()
		close(a.tuiEvents)
		a.emitMu.Lock()
		a.closed = true
		close(a.chat)
		a.emitMu.Unlock()
	})
}

// emit delivers ev to the interface. It blocks while the interface is
// behind, and gives up once Run's context is cancelled or Run has returned.
func (a *App) emit(ev tui.ChatEvent) {
	a.emitMu.RLock()
	defer a.emitMu.RUnlock()
	if a.closed {
		return
	}
	select {
	case a.chat <- ev:
	case <-a.done:
	}
}

// Self describes the local identity.
func (a *App) Self() tui.SelfInfo {
	id := a.prof.Identity.ID()
	return tui.SelfInfo{DisplayName: a.prof.DisplayName(), ID: canonicalID(id), ShortID: id.ShortString()}
}

// canonicalID returns the form of id the interface uses as a contact key:
// the prefix and 52 base32 characters without separators.
func canonicalID(id identity.ID) string {
	return identity.IDPrefix + strings.ReplaceAll(strings.TrimPrefix(id.String(), identity.IDPrefix), "-", "")
}

// authenticator implements client.Authenticator for a profile identity.
type authenticator struct {
	ident  *identity.Identity
	bundle []byte
	invite string
}

func (a authenticator) ID() [32]byte   { return a.ident.ID() }
func (a authenticator) Bundle() []byte { return a.bundle }
func (a authenticator) Invite() string { return a.invite }
func (a authenticator) SignAuth(serverFP transport.Fingerprint, nonce, binding []byte) ([]byte, error) {
	return a.ident.SignAuth(serverFP, nonce, binding)
}
