package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/Aepzie/qchat/internal/client"
	"github.com/Aepzie/qchat/internal/crypto/sealbox"
	"github.com/Aepzie/qchat/internal/e2e"
	"github.com/Aepzie/qchat/internal/handshake"
	"github.com/Aepzie/qchat/internal/identity"
	"github.com/Aepzie/qchat/internal/prekey"
	"github.com/Aepzie/qchat/internal/protocol"
	"github.com/Aepzie/qchat/internal/ratchet"
	"github.com/Aepzie/qchat/internal/store/clientdb"
	"github.com/Aepzie/qchat/internal/tui"
)

// Session rules
//
// There is at most one stored session per peer (clientdb.Session). An
// incoming envelope is routed as follows (see route):
//
//   - Without Init it is decrypted with the stored session; without a
//     stored session it can never be read and is dropped.
//   - With an Init and no stored session, the Init is accepted and a new
//     responder session is created.
//   - With the Init that created the stored responder session (the peer
//     attaches it until it hears back), the stored session decrypts it.
//   - With a different Init: a session that has carried messages in both
//     directions is never replaced (the envelope is dropped). An
//     unestablished responder session is replaced, since the peer evidently
//     started over. An own initiator session that has not received anything
//     yet is a simultaneous start, resolved with handshake.Winner: if the
//     peer's session wins, it replaces the own one; if the own session wins,
//     the peer's message is still decrypted with a shadow session (below)
//     and the own session is kept. The peer discards its losing session
//     when the own Init reaches it.
//
// A replacement only takes effect when the first message under the new
// session has decrypted, which is also the only proof that the derived key
// is right (KEM decapsulation uses implicit rejection). The one-time
// prekey the Init used is deleted in the same transaction that stores the
// message and the new session, which also records the Init in the replay
// set (clientdb.CommitReceiveInit); a session start already recorded there
// is rejected, so a replayed Init can neither replace a session nor start a
// deleted one again.
//
// A shadow session is the responder side of a peer's losing simultaneous
// start. It lives in memory only and is used only to read the messages the
// peer sent before it adopted the winning session; it is never used to send.
//
// Session starts cost private-key operations and may consume one-time
// prekeys, so envelopes that need an Accept are limited to handshakeBurst
// per sender per handshakeWindow; beyond that they are dropped.
//
// For a responder session, PendingInit (meant for an initiator's own Init)
// instead holds a responder mark: the SHA-256 of the Init that created the
// session followed by one byte that is 1 once the App has sent on the
// session. An initiator session holds its own Init there until it has
// received a message, and nothing afterwards.

const (
	// maxShadowSessions bounds the shadow sessions kept in memory.
	maxShadowSessions = 64
	// handshakeBurst and handshakeWindow rate limit Init processing per
	// sender; maxHandshakeSenders bounds the memory of that limiter.
	// Session starts that arrive sealed share one bucket (the zero ID) of
	// sealedHandshakeBurst instead: their sender is only a claim until the
	// Init verifies, so a forgery must not spend the claimed sender's
	// budget.
	handshakeBurst       = 5
	sealedHandshakeBurst = 4 * handshakeBurst
	handshakeWindow      = time.Minute
	maxHandshakeSenders  = 1024
	// responderMarkSize is the size of a responder mark.
	responderMarkSize = sha256.Size + 1
	// initRefreshAge is the age after which an own session that never
	// received anything is started again before sending, a day short of
	// handshake.MaxInitAge so that its Init is still accepted on arrival.
	initRefreshAge = handshake.MaxInitAge - 24*time.Hour
)

var (
	// errUndecryptable reports an envelope that no session can decrypt.
	errUndecryptable = errors.New("app: no session can decrypt this message")
	// errHandshakeLimited reports a session start beyond the rate limit.
	errHandshakeLimited = errors.New("app: too many session starts from this sender")
	// errStaleSender reports a session start carrying a sender bundle that
	// is older than, or conflicts with, the stored contact bundle.
	errStaleSender = errors.New("app: session start carries an outdated sender bundle")
	// errDuplicateRequest and errRequestsFull report message requests that
	// are not kept.
	errDuplicateRequest = errors.New("app: duplicate message request")
	errRequestsFull     = errors.New("app: too many message requests")
)

// transientError marks a failure that may not recur, such as a database
// error. A delivery that failed this way is not acknowledged, so the relay
// delivers it again.
type transientError struct{ err error }

func (e transientError) Error() string { return e.err.Error() }
func (e transientError) Unwrap() error { return e.err }

func transient(err error) error { return transientError{err} }

func isTransient(err error) bool {
	var t transientError
	return errors.As(err, &t)
}

// dbError classifies a database error: duplicates, replayed session starts,
// missing rows and invalid records are permanent, everything else transient.
func dbError(err error) error {
	if err == nil || errors.Is(err, clientdb.ErrDuplicate) || errors.Is(err, clientdb.ErrNotFound) ||
		errors.Is(err, clientdb.ErrInvalid) || errors.Is(err, clientdb.ErrCorrupt) || errors.Is(err, clientdb.ErrInitSeen) {
		return err
	}
	return transient(err)
}

// shadowSession is the in-memory responder state of a peer's losing
// simultaneous start.
type shadowSession struct {
	digest [sha256.Size]byte
	state  []byte
}

// responderMark encodes the PendingInit value of a responder session.
func responderMark(digest [sha256.Size]byte, sent bool) []byte {
	mark := make([]byte, responderMarkSize)
	copy(mark, digest[:])
	if sent {
		mark[sha256.Size] = 1
	}
	return mark
}

// readResponderMark decodes a responder mark; anything else reads as an
// unknown Init and no sent message.
func readResponderMark(b []byte) (digest [sha256.Size]byte, sent bool) {
	if len(b) != responderMarkSize {
		return digest, false
	}
	copy(digest[:], b)
	return digest, b[sha256.Size] == 1
}

// established reports whether s has carried messages in both directions
// as far as this side can tell: an initiator session that has received a
// message, or a responder session this side has sent on.
func established(s clientdb.Session) bool {
	if s.Initiator {
		return s.Confirmed
	}
	_, sent := readResponderMark(s.PendingInit)
	return sent
}

// route says how an incoming envelope is decrypted.
type route uint8

const (
	routeDrop route = iota
	routeExisting
	routeAccept
	routeShadow
)

// route applies the session rules to an envelope from the peer from with
// the given Init (nil if none). cur is the stored session, if found.
func (a *App) route(cur clientdb.Session, found bool, from identity.ID, init []byte) route {
	if init == nil {
		if found {
			return routeExisting
		}
		return routeDrop
	}
	if !found {
		return routeAccept
	}
	digest := sha256.Sum256(init)
	if sh, ok := a.shadows[from]; ok && sh.digest == digest {
		return routeShadow
	}
	if !cur.Initiator {
		if own, _ := readResponderMark(cur.PendingInit); own == digest {
			return routeExisting
		}
		if established(cur) {
			return routeDrop
		}
		return routeAccept
	}
	if cur.Confirmed {
		return routeDrop
	}
	if handshake.Winner(a.prof.Identity.ID(), from) == from {
		return routeAccept
	}
	return routeShadow
}

// opened is a decrypted message with the session changes that must be
// committed together with it.
type opened struct {
	// next is the session row to store with the message.
	next clientdb.Session
	// consumedOPK is the own one-time prekey to delete, or 0.
	consumedOPK uint32
	plaintext   e2e.Plaintext
	// sender is the bundle from an accepted Init, nil otherwise.
	sender *identity.Bundle
	// seen is the replay set entry of an accepted Init, nil otherwise. It is
	// recorded in the same transaction as the message, and a start already
	// in the replay set is rejected (clientdb.ErrInitSeen).
	seen *clientdb.SeenInit
	// shadow is the shadow session to keep, if the message was read with
	// one.
	shadow *shadowSession
}

// loadSession returns the stored session with peer, if any.
func (a *App) loadSession(ctx context.Context, peer identity.ID) (clientdb.Session, bool, error) {
	s, err := a.prof.DB.GetSession(ctx, peer)
	if errors.Is(err, clientdb.ErrNotFound) {
		return clientdb.Session{}, false, nil
	}
	if err != nil {
		return clientdb.Session{}, false, err
	}
	return s, true, nil
}

// open decrypts an envelope from from, counting a session start against
// the limiter bucket limit (see allowHandshake). a.ratchetMu must be held.
// Errors are permanent unless isTransient says otherwise.
func (a *App) open(ctx context.Context, from identity.ID, env e2e.Envelope, limit identity.ID) (opened, error) {
	cur, found, err := a.loadSession(ctx, from)
	if err != nil {
		return opened{}, dbError(err)
	}
	switch a.route(cur, found, from, env.Init) {
	case routeExisting:
		return a.openExisting(cur, env)
	case routeAccept:
		return a.openAccepted(ctx, from, env, limit)
	case routeShadow:
		return a.openShadow(ctx, from, cur, env, limit)
	default:
		return opened{}, errUndecryptable
	}
}

// openExisting decrypts with the stored session cur.
func (a *App) openExisting(cur clientdb.Session, env e2e.Envelope) (opened, error) {
	st, err := ratchet.Unmarshal(cur.State)
	if err != nil {
		return opened{}, err
	}
	defer st.Destroy()
	pt, err := decryptPlaintext(st, env)
	if err != nil {
		return opened{}, err
	}
	next, err := a.advanced(cur, st)
	if err != nil {
		clear(pt.Body)
		return opened{}, err
	}
	return opened{next: next, plaintext: pt}, nil
}

// openAccepted accepts the envelope's Init as a new responder session and
// decrypts with it.
func (a *App) openAccepted(ctx context.Context, from identity.ID, env e2e.Envelope, limit identity.ID) (opened, error) {
	st, acc, seen, err := a.acceptInit(ctx, from, env.Init, limit)
	if err != nil {
		return opened{}, err
	}
	defer st.Destroy()
	pt, err := decryptPlaintext(st, env)
	if err != nil {
		return opened{}, err
	}
	state, err := st.Marshal()
	if err != nil {
		clear(pt.Body)
		return opened{}, transient(err)
	}
	now := a.now()
	next := clientdb.Session{
		Peer:        from,
		State:       state,
		Confirmed:   true,
		PendingInit: responderMark(sha256.Sum256(env.Init), false),
		Created:     now,
		Updated:     now,
	}
	return opened{next: next, consumedOPK: acc.OPKID, plaintext: pt, sender: acc.Sender, seen: seen}, nil
}

// openShadow decrypts a message of the peer's losing session start and
// leaves the stored session cur unchanged.
func (a *App) openShadow(ctx context.Context, from identity.ID, cur clientdb.Session, env e2e.Envelope, limit identity.ID) (opened, error) {
	digest := sha256.Sum256(env.Init)
	var (
		st   *ratchet.State
		acc  *handshake.Accepted
		seen *clientdb.SeenInit
		err  error
	)
	if sh, ok := a.shadows[from]; ok && sh.digest == digest {
		st, err = ratchet.Unmarshal(sh.state)
	} else {
		st, acc, seen, err = a.acceptInit(ctx, from, env.Init, limit)
	}
	if err != nil {
		return opened{}, err
	}
	defer st.Destroy()
	pt, err := decryptPlaintext(st, env)
	if err != nil {
		return opened{}, err
	}
	state, err := st.Marshal()
	if err != nil {
		clear(pt.Body)
		return opened{}, transient(err)
	}
	o := opened{next: cur, plaintext: pt, shadow: &shadowSession{digest: digest, state: state}}
	if acc != nil {
		o.consumedOPK, o.sender, o.seen = acc.OPKID, acc.Sender, seen
	}
	return o, nil
}

// acceptInit verifies a peer's Init, checks its sender bundle against the
// stored contact and returns the new responder ratchet state together with
// the replay set entry to record when the first message is committed.
func (a *App) acceptInit(ctx context.Context, from identity.ID, init []byte, limit identity.ID) (*ratchet.State, *handshake.Accepted, *clientdb.SeenInit, error) {
	st, acc, retireAt, err := a.acceptInitState(ctx, from, init, limit)
	if err != nil {
		return nil, nil, nil, err
	}
	expires := acc.Created.Add(handshake.MaxInitAge)
	if !retireAt.IsZero() {
		expires = retireAt
	}
	return st, acc, &clientdb.SeenInit{SPKID: acc.SPKID, Key: acc.ReplayKey, Expires: expires}, nil
}

// acceptInitState is acceptInit without the replay set entry; it also
// returns the RetireAt of the signed prekey the Init used.
func (a *App) acceptInitState(ctx context.Context, from identity.ID, init []byte, limit identity.ID) (*ratchet.State, *handshake.Accepted, time.Time, error) {
	if !a.allowHandshake(limit) {
		return nil, nil, time.Time{}, errHandshakeLimited
	}
	var retireAt time.Time
	var lookupErr error
	note := func(err error) {
		if !errors.Is(err, clientdb.ErrNotFound) && !errors.Is(err, clientdb.ErrCorrupt) && !errors.Is(err, prekey.ErrMalformedPrivate) {
			lookupErr = err
		}
	}
	var signed, oneTime *sealbox.PrivateKey
	defer func() {
		for _, k := range []*sealbox.PrivateKey{signed, oneTime} {
			if k != nil {
				k.Destroy()
			}
		}
	}()
	lookup := func(kind clientdb.PrekeyKind, slot **sealbox.PrivateKey, retire *time.Time) handshake.PrekeyLookup {
		return func(keyID uint32) (*sealbox.PrivateKey, []byte, error) {
			k, raw, retireAt, err := a.loadPrekey(ctx, kind, keyID)
			if err != nil {
				note(err)
				return nil, nil, err
			}
			if *slot != nil {
				(*slot).Destroy()
			}
			*slot, *retire = k, retireAt
			return k, raw, nil
		}
	}
	var unused time.Time
	acc, err := handshake.AcceptAt(a.prof.Identity, from, init,
		lookup(clientdb.PrekeySigned, &signed, &retireAt), lookup(clientdb.PrekeyOneTime, &oneTime, &unused), a.now())
	switch {
	case lookupErr != nil:
		return nil, nil, time.Time{}, transient(lookupErr)
	case errors.Is(err, identity.ErrDestroyed):
		return nil, nil, time.Time{}, transient(err)
	case err != nil:
		return nil, nil, time.Time{}, err
	}
	defer clear(acc.SK[:])
	if err := a.checkSender(ctx, from, acc.Sender); err != nil {
		return nil, nil, time.Time{}, err
	}
	st, err := ratchet.New(ratchet.Params{Self: a.prof.Identity.ID(), Peer: from, SK: acc.SK, Role: ratchet.Responder, OwnInitialKey: signed})
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	return st, acc, retireAt, nil
}

// checkSender accepts the sender bundle of an Init if from is not a
// contact, if it is the stored bundle, or if it is newer (higher serial).
// An older or conflicting bundle is rejected: only the relay replaying an
// old Init could produce one.
func (a *App) checkSender(ctx context.Context, from identity.ID, sender *identity.Bundle) error {
	c, err := a.prof.DB.GetContact(ctx, from)
	switch {
	case errors.Is(err, clientdb.ErrNotFound):
		return nil
	case err != nil:
		return transient(err)
	case bytes.Equal(c.Bundle, sender.Raw) || sender.Serial > c.BundleSerial:
		return nil
	default:
		return errStaleSender
	}
}

// handshakeBurstFor returns the burst of the limiter bucket key.
func handshakeBurstFor(key identity.ID) int {
	if key.IsZero() {
		return sealedHandshakeBurst
	}
	return handshakeBurst
}

// allowHandshake records a session start in the limiter bucket sender (the
// relay-reported sender, or the zero ID for sealed deliveries) and reports
// whether it is within the rate limit. a.ratchetMu must be held.
func (a *App) allowHandshake(sender identity.ID) bool {
	now := a.now()
	recent := func(times []time.Time) []time.Time {
		kept := times[:0]
		for _, t := range times {
			if now.Sub(t) < handshakeWindow && !t.After(now) {
				kept = append(kept, t)
			}
		}
		return kept
	}
	times, known := a.handshakes[sender]
	times = recent(times)
	if !known && len(a.handshakes) >= maxHandshakeSenders {
		for id, ts := range a.handshakes {
			if len(recent(ts)) == 0 {
				delete(a.handshakes, id)
			}
		}
		if len(a.handshakes) >= maxHandshakeSenders {
			return false
		}
	}
	if len(times) >= handshakeBurstFor(sender) {
		a.handshakes[sender] = times
		return false
	}
	a.handshakes[sender] = append(times, now)
	return true
}

// keepShadow stores a shadow session. a.ratchetMu must be held.
func (a *App) keepShadow(peer identity.ID, sh shadowSession) {
	if _, ok := a.shadows[peer]; !ok && len(a.shadows) >= maxShadowSessions {
		for id := range a.shadows {
			delete(a.shadows, id)
			break
		}
	}
	a.shadows[peer] = sh
}

// decryptPlaintext decrypts an envelope's ciphertext, strips its padding and
// parses it. Invalid padding fails like a failed decryption.
func decryptPlaintext(st *ratchet.State, env e2e.Envelope) (e2e.Plaintext, error) {
	raw, err := st.Decrypt(env.Header, env.Ciphertext)
	if err != nil {
		return e2e.Plaintext{}, err
	}
	defer clear(raw)
	return e2e.ParsePaddedPlaintext(raw)
}

// advanced returns cur with the state of st, as it must be stored after st
// encrypted or decrypted a message.
func (a *App) advanced(cur clientdb.Session, st *ratchet.State) (clientdb.Session, error) {
	state, err := st.Marshal()
	if err != nil {
		return clientdb.Session{}, transient(err)
	}
	next := cur
	next.State = state
	next.Updated = a.now()
	if st.ReceivedAny() {
		next.Confirmed = true
		if next.Initiator {
			next.PendingInit = nil
		}
	}
	return next, nil
}

// fileOpened commits a decrypted message. It reports whether the delivery
// may be acknowledged, and returns the events to show once a.ratchetMu has
// been released (emitting may block on a slow interface).
func (a *App) fileOpened(ctx context.Context, from identity.ID, o opened) (bool, []tui.ChatEvent) {
	now := a.now()
	var flags uint8
	if e2e.ClockSkewed(o.plaintext.Sent, now) {
		flags |= clientdb.FlagClockSkew
	}
	record := clientdb.Message{
		Peer:     from,
		MsgID:    o.plaintext.MsgID,
		Dir:      clientdb.Incoming,
		Sent:     o.plaintext.Sent,
		Received: now,
		Body:     string(o.plaintext.Body),
		Status:   clientdb.StatusReceived,
		Flags:    flags,
		Expires:  a.expiryFor(ctx, from, now),
	}
	unknown, err := a.commitIncoming(ctx, o, record)
	if err != nil {
		a.countDropped()
		return !isTransient(err), nil
	}
	if o.shadow != nil {
		a.keepShadow(from, *o.shadow)
	}
	var events []tui.ChatEvent
	if o.sender != nil && !unknown && a.adoptBundle(from, o.sender) {
		events = append(events, tui.ContactKeyChanged{ContactID: canonicalID(from)})
	}
	events = append(events, tui.IncomingMessage{ContactID: canonicalID(from), Message: a.messageInfo(record), UnknownSender: unknown})
	return true, events
}

// commitIncoming stores a decrypted message with its session changes. For
// a contact this is one transaction (CommitReceive, or CommitReceiveInit
// for the first message of an accepted Init, which also records the Init in
// the replay set). For an unknown sender the Init is recorded first, then
// the session is stored and the one-time prekey deleted, while the message
// itself becomes an in-memory message request; recording first means a
// crash in between can only lose that session, never let a replay in. It
// reports whether the sender is unknown.
func (a *App) commitIncoming(ctx context.Context, o opened, m clientdb.Message) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err := a.prof.DB.GetContact(ctx, m.Peer)
	switch {
	case errors.Is(err, clientdb.ErrNotFound):
		return true, a.commitRequestLocked(ctx, o, m)
	case err != nil:
		return false, transient(err)
	}
	if o.seen != nil {
		err = a.prof.DB.CommitReceiveInit(ctx, o.next, m, o.consumedOPK, *o.seen)
	} else {
		err = a.prof.DB.CommitReceive(ctx, o.next, m, o.consumedOPK)
	}
	if err != nil {
		return false, dbError(err)
	}
	a.unread[m.Peer]++
	return false, nil
}

func (a *App) commitRequestLocked(ctx context.Context, o opened, m clientdb.Message) error {
	pending, exists := a.requests[m.Peer]
	for _, r := range pending {
		if r.MsgID == m.MsgID {
			return errDuplicateRequest
		}
	}
	if (!exists && len(a.requests) >= maxRequestSenders) || len(pending) >= maxRequestMessages {
		return errRequestsFull
	}
	seen, err := a.prof.DB.HasMessage(ctx, m.Peer, m.MsgID)
	if err != nil {
		return transient(err)
	}
	if seen {
		return clientdb.ErrDuplicate
	}
	if o.seen != nil {
		replayed, err := a.prof.DB.MarkInitSeen(ctx, o.seen.SPKID, o.seen.Key, o.seen.Expires)
		if err != nil {
			return dbError(err)
		}
		if replayed {
			return clientdb.ErrInitSeen
		}
	}
	if err := a.prof.DB.PutSession(ctx, o.next); err != nil {
		return dbError(err)
	}
	if o.consumedOPK != 0 {
		_ = a.prof.DB.DeletePrekeySecret(ctx, clientdb.PrekeyOneTime, o.consumedOPK)
	}
	a.requests[m.Peer] = append(pending, m)
	return nil
}

// commitSession stores the session changes of a decrypted message that is
// not filed as a conversation message (group control and sender key
// messages): the Init in the replay set first, then the session, then the
// deletion of the consumed one-time prekey, like a message request.
// a.ratchetMu must be held.
func (a *App) commitSession(ctx context.Context, from identity.ID, o opened) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if o.seen != nil {
		replayed, err := a.prof.DB.MarkInitSeen(ctx, o.seen.SPKID, o.seen.Key, o.seen.Expires)
		if err != nil {
			return dbError(err)
		}
		if replayed {
			return clientdb.ErrInitSeen
		}
	}
	if err := a.prof.DB.PutSession(ctx, o.next); err != nil {
		return dbError(err)
	}
	if o.consumedOPK != 0 {
		_ = a.prof.DB.DeletePrekeySecret(ctx, clientdb.PrekeyOneTime, o.consumedOPK)
	}
	if o.shadow != nil {
		a.keepShadow(from, *o.shadow)
	}
	return nil
}

// adoptBundle stores a verified bundle of the contact id if it is newer than
// the stored one (see applyBundle) and reports whether the contact's
// encryption key changed.
func (a *App) adoptBundle(id identity.ID, fresh *identity.Bundle) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	ctx := context.Background()
	c, err := a.prof.DB.GetContact(ctx, id)
	if err != nil {
		return false
	}
	serial := c.BundleSerial
	keyChanged := applyBundle(&c, fresh, a.now())
	if c.BundleSerial == serial {
		return false
	}
	return a.prof.DB.PutContact(ctx, c) == nil && keyChanged
}

// sealOutgoing encrypts pt for the contact c, starting a session first if
// there is none, and commits the advanced session together with record
// before returning the relay payload, so that no ciphertext ever leaves
// the device without its state being stored. A nil record stores the
// session alone, for messages that are not shown in the conversation (group
// control and sender key messages). A non-empty reason explains why no
// session could be started (nothing was stored then); err reports local
// failures. c need not be stored: a group member that is not a contact is
// passed with its verified bundle.
//
// An own session that has not received anything for so long that the peer
// would reject its Init as stale (initRefreshAge) is replaced by a new one.
// For a sealed route a new session is started only from prekeys fetched
// earlier (sealedSessionStart), never with a fetch right before the send.
func (a *App) sealOutgoing(ctx context.Context, c clientdb.Contact, pt e2e.Plaintext, record *clientdb.Message, route sendRoute) (payload []byte, reason string, err error) {
	id := identity.ID(c.ID)
	usable := func() (clientdb.Session, bool, error) {
		cur, found, err := a.loadSession(ctx, id)
		if found && cur.Initiator && !cur.Confirmed && a.now().Sub(cur.Created) > initRefreshAge {
			found = false
		}
		return cur, found, err
	}
	a.ratchetMu.Lock()
	cur, found, err := usable()
	if err != nil {
		a.ratchetMu.Unlock()
		return nil, "", err
	}
	if !found {
		a.ratchetMu.Unlock()
		start := a.startSession
		if route.sealed {
			start = a.sealedSessionStart
		}
		started, reason, err := start(ctx, c)
		if reason != "" || err != nil {
			return nil, reason, err
		}
		a.ratchetMu.Lock()
		if cur, found, err = usable(); err != nil {
			a.ratchetMu.Unlock()
			return nil, "", err
		}
		if !found {
			cur = started
		}
	}
	defer a.ratchetMu.Unlock()

	st, err := ratchet.Unmarshal(cur.State)
	if err != nil {
		return nil, "", err
	}
	defer st.Destroy()
	plain, err := e2e.MarshalPaddedPlaintext(pt)
	if err != nil {
		return nil, "", err
	}
	defer clear(plain)
	header, ciphertext, err := st.Encrypt(plain)
	if err != nil {
		return nil, "", err
	}
	env := e2e.Envelope{Header: header, Ciphertext: ciphertext}
	if cur.Initiator && !st.ReceivedAny() {
		env.Init = cur.PendingInit
	}
	if payload, err = e2e.MarshalEnvelope(env); err != nil {
		return nil, "", err
	}
	next, err := a.advanced(cur, st)
	if err != nil {
		return nil, "", err
	}
	if !next.Initiator {
		digest, _ := readResponderMark(next.PendingInit)
		next.PendingInit = responderMark(digest, true)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if record == nil {
		if err := a.prof.DB.PutSession(ctx, next); err != nil {
			return nil, "", err
		}
		return payload, "", nil
	}
	if err := a.prof.DB.CommitSend(ctx, next, *record); err != nil {
		return nil, "", err
	}
	a.inflight[messageKey{peer: id, msgID: record.MsgID}] = struct{}{}
	return payload, "", nil
}

// startSession fetches the prekey bundle of the contact c from the relay
// and returns a new initiator session, not yet stored. A non-empty reason
// explains a relay-side failure.
func (a *App) startSession(ctx context.Context, c clientdb.Contact) (clientdb.Session, string, error) {
	resp, reason := a.requestPrekeys(ctx, identity.ID(c.ID))
	if reason != "" {
		return clientdb.Session{}, reason, nil
	}
	return a.sessionFromPrekeys(ctx, c, resp)
}

// requestPrekeys fetches the prekey bundle of id from the relay. A
// non-empty reason explains a failure.
func (a *App) requestPrekeys(ctx context.Context, id identity.ID) (protocol.PrekeyResponse, string) {
	sess := a.session()
	if sess == nil {
		return protocol.PrekeyResponse{}, "not connected"
	}
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	frame, err := sess.Request(rctx, protocol.TypePrekeyRequest, protocol.PrekeyRequest{ID: id[:]})
	var remote *client.RemoteError
	if errors.As(err, &remote) && remote.Code == protocol.ErrCodeNotFound {
		return protocol.PrekeyResponse{}, "this contact has no keys on the server yet; they need to connect once"
	}
	if reason := relayFailure(err); reason != "" {
		return protocol.PrekeyResponse{}, reason
	}
	resp, err := protocol.DecodeBody[protocol.PrekeyResponse](frame, protocol.TypePrekeyResponse)
	if err != nil {
		return protocol.PrekeyResponse{}, "unexpected answer from the server"
	}
	return resp, ""
}

// sessionFromPrekeys returns a new initiator session with the contact c
// from its prekey bundle resp, not yet stored. A non-empty reason explains
// a bundle that cannot be used.
func (a *App) sessionFromPrekeys(ctx context.Context, c clientdb.Contact, resp protocol.PrekeyResponse) (clientdb.Session, string, error) {
	id := identity.ID(c.ID)
	fresh, err := identity.ParseBundleForID(resp.Bundle, id)
	if err != nil {
		return clientdb.Session{}, "the server returned keys that do not belong to this contact", nil
	}
	identityRaw := c.Bundle
	if !bytes.Equal(resp.Bundle, c.Bundle) && fresh.Serial > c.BundleSerial {
		identityRaw = resp.Bundle
		if a.adoptBundle(id, fresh) {
			a.emit(tui.ContactKeyChanged{ContactID: canonicalID(id)})
		}
	}
	now := a.now()
	peer, err := handshake.ParseBundle(id, identityRaw, resp.SignedPrekey, resp.OneTimePrekey, now)
	if errors.Is(err, prekey.ErrExpired) {
		return clientdb.Session{}, "this contact's keys on the server have expired; they need to connect again", nil
	}
	if err != nil {
		return clientdb.Session{}, "the server returned keys that do not belong to this contact", nil
	}
	ini, err := handshake.InitiateAt(a.prof.Identity, a.selfRaw, peer, now)
	if err != nil {
		return clientdb.Session{}, "", err
	}
	defer clear(ini.SK[:])
	st, err := ratchet.New(ratchet.Params{Self: a.prof.Identity.ID(), Peer: id, SK: ini.SK, Role: ratchet.Initiator, PeerInitialPub: ini.PeerInitialPub})
	if err != nil {
		return clientdb.Session{}, "", err
	}
	defer st.Destroy()
	state, err := st.Marshal()
	if err != nil {
		return clientdb.Session{}, "", err
	}
	return clientdb.Session{Peer: id, State: state, Initiator: true, PendingInit: ini.Init, Created: now, Updated: now}, "", nil
}
