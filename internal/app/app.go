// Package app is the application layer of the qchat client. It connects the
// unlocked profile (identity and encrypted database) with the relay session
// and implements tui.Backend on top of both.
//
// Behaviour worth knowing:
//
//   - Messages from identities that are not contacts are message requests.
//     In Phase 2 they are kept in memory only and never written to disk;
//     they are persisted when the user adds the sender as a contact, and
//     lost when the client exits before that.
//   - Unread counts are kept in memory and start at zero on every launch.
//   - Payloads that do not decrypt or verify, and replayed messages, are
//     dropped silently; they never reach the interface.
//   - A contact's bundle is refreshed from the relay whenever the user adds
//     an existing contact again. A newer bundle (higher serial) with a
//     different encryption key marks the contact as changed and unverified;
//     a bundle with an equal or lower serial that differs from the stored
//     one is ignored, because only the relay could produce such a rollback.
package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/craguS/qchat/internal/client"
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

// Requester sends a request to the relay over the authenticated session and
// returns the response frame. *client.Session implements it.
type Requester interface {
	Request(ctx context.Context, t protocol.FrameType, body any) (protocol.Frame, error)
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

	mu       sync.Mutex
	unread   map[identity.ID]int
	requests map[identity.ID][]clientdb.Message
	inflight map[messageKey]struct{}
	dropped  int
	denied   *client.RegistrationDenied
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
		prof:      p,
		invite:    invite,
		self:      self,
		selfRaw:   raw,
		now:       time.Now,
		tuiEvents: make(chan client.Event, eventBuffer),
		chat:      make(chan tui.ChatEvent, eventBuffer),
		done:      make(chan struct{}),
		unread:    map[identity.ID]int{},
		requests:  map[identity.ID][]clientdb.Message{},
		inflight:  map[messageKey]struct{}{},
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
// It must be called at most once.
func (a *App) Run(ctx context.Context, events <-chan client.Event) {
	defer a.shutdown()
	stop := context.AfterFunc(ctx, a.stopEmitting)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
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
		a.handleDelivery(ctx, e)
		return false
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
