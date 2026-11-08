package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/craguS/qchat/internal/client"
	"github.com/craguS/qchat/internal/e2e"
	"github.com/craguS/qchat/internal/group"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/sealed"
	"github.com/craguS/qchat/internal/senderkey"
	"github.com/craguS/qchat/internal/store/clientdb"
	"github.com/craguS/qchat/internal/tui"
)

// Sealed sender rules (docs/design/phase-5-metadata.md, "Sealed sender")
//
// Access keys:
//
//   - Every profile has one random sealed.AccessKey, created on the first
//     run of a version with sealed sender (also for existing profiles) and
//     stored in the encrypted settings. Its verifier is uploaded only on
//     the authenticated session, after every authentication, with
//     AllowUnidentified off. The key and its proof are never used on the
//     authenticated session.
//   - The App takes part in sealed sender once an anonymous session is
//     attached (UseAnonymousSession); without one it neither shares its key
//     nor sends sealed. Keys it receives are still stored.
//   - The key is shared over the pairwise ratchet session as
//     e2e.KindAccessKey with every contact and every member of an accepted
//     group, once the session is confirmed, and never with someone who is
//     only a message request. Which key was last shared with whom is stored
//     ("sealed.out.<id>"), so it is sent once per key and peer, piggybacked
//     on the next message exchanged with that peer.
//   - A received key is stored ("sealed.in.<id>") only when it arrives on
//     a verified pairwise session from a contact or a member of an accepted
//     group; anything else is ignored. A newer key replaces the old one.
//   - Removing a contact, leaving a group or removing a member rotates the
//     key: the new verifier replaces the old one at the relay at once, and
//     the new key is redistributed to the remaining peers over time, one
//     peer at a time with a random pause in between (shareDelay), and
//     earlier with any message exchanged meanwhile. Until a peer has the
//     new key its sealed sends to the user fail.
//
// Sending: with an anonymous session attached and the recipient's key
// known, a pairwise envelope is wrapped with sealed.Seal and sent with
// SealedSend on the anonymous session, proving access with the key's
// verifier. Only while no key is known (the first contact) is a message
// sent identified with Send, and it is marked so the interface can say so.
// Once a key is known, messages go sealed only: a sealed send that fails is
// reported as a failure and never retried identified, and the same bytes
// are never sent on another path. A refusal by the relay (NotFound,
// RateLimited, Internal) marks the key stale ("sealed.st.<id>") until a new
// key arrives or a sealed send succeeds again. A new session for a sealed
// route never fetches prekeys right before the send: it uses prekeys
// fetched earlier (prefetchPrekeys, after connecting and in the
// background), and fails until they are there.
//
// Group messages go with SealedSendMulti, one store-once payload for all,
// only when the key of every other member is known; otherwise the whole
// fan-out is identified (SendMulti), since the same ciphertext on both
// connections would link them. A sealed fan-out includes the user's own ID
// with the own verifier, entries sorted by ID, so the recipient list does
// not single out the sender; the echo is recognised by the sender in its
// decrypted header and acknowledged without being shown.
//
// Receiving: a delivery with the zero sender must carry a sealed envelope or
// a group envelope; anything else is dropped. A sealed envelope is opened
// with sealed.Open and the inner pairwise envelope is routed by the claimed
// sender, exactly as an identified delivery from that sender, which is the
// sender handed to handshake.Accept. The claim is never shown or acted on
// before the inner layer verified it: the ratchet AEAD and the Init
// signature are bound to the sender ID, so a false claim fails to decrypt
// and the delivery is dropped (and acknowledged) without any change to
// sessions, contacts or shadows, and nothing is sent. Session starts that
// arrive sealed count against one shared limiter bucket, not the claimed
// sender's. An identified delivery carrying a sealed envelope is accepted
// only if the claimed sender is the relay-reported one. A sealed group
// envelope is routed by the sender in its decrypted header among all
// current members; the sender's signature over the envelope authenticates
// it.
//
// Without Tor the anonymous connection comes from the same address as the
// authenticated one, so the relay can link both by address and timing; the
// sender then stays hidden only from the stored queue rows and from the
// protocol itself.

const (
	// settingAccessKey holds the own access key.
	settingAccessKey = "self.access_key"
	// peerKeyPrefix, sharedKeyPrefix and staleKeyPrefix start the names of
	// the settings holding a peer's access key, the own key last shared
	// with a peer, and whether the relay refused a peer's key.
	peerKeyPrefix   = "sealed.in."
	sharedKeyPrefix = "sealed.out."
	staleKeyPrefix  = "sealed.st."
	// maxShareDelay bounds the random pause between two peers when the
	// own key is redistributed after a rotation.
	maxShareDelay = 5 * time.Minute
	// maxPrefetchDelay bounds the random pause before prekeys are fetched
	// for a sealed session start, so that the fetch is not tied to a send.
	maxPrefetchDelay = 2 * time.Minute
	// prefetchMaxAge is how long prefetched prekeys are used.
	prefetchMaxAge = 24 * time.Hour
)

// Flags of outgoing messages recording how they were sent. They use the
// high bits of clientdb.Message.Flags, which the database stores as given.
const (
	flagSentSealed     uint8 = 1 << 6
	flagSentIdentified uint8 = 1 << 7
)

// Reasons shown for sealed sends that did not go out.
const (
	reasonSealedRefused   = "could not deliver sealed — waiting for updated key"
	reasonSealedPreparing = "preparing a sealed session with this contact; try again shortly"
)

// idName encodes an ID for a setting name: 52 lowercase base32 characters.
var idName = base32.StdEncoding.WithPadding(base32.NoPadding)

func idSetting(prefix string, id identity.ID) string {
	return prefix + strings.ToLower(idName.EncodeToString(id[:]))
}

// prefetched are prekeys fetched ahead of a sealed session start.
type prefetched struct {
	resp protocol.PrekeyResponse
	at   time.Time
}

// randomDelay returns a uniformly random duration below limit.
func randomDelay(limit time.Duration) time.Duration {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil || limit <= 0 {
		return limit
	}
	return time.Duration(binary.BigEndian.Uint64(b[:]) % uint64(limit))
}

// loadOrCreateAccessKey returns the stored own access key, creating and
// storing a new one if there is none or the stored value is invalid.
func loadOrCreateAccessKey(ctx context.Context, db *clientdb.DB) (sealed.AccessKey, error) {
	raw, err := db.GetSetting(ctx, settingAccessKey)
	if err == nil {
		if key, err := sealed.ParseAccessKey(raw); err == nil {
			return key, nil
		}
	} else if !errors.Is(err, clientdb.ErrNotFound) {
		return sealed.AccessKey{}, err
	}
	key, err := sealed.NewAccessKey()
	if err != nil {
		return sealed.AccessKey{}, err
	}
	if err := db.PutSetting(ctx, settingAccessKey, key[:]); err != nil {
		return sealed.AccessKey{}, err
	}
	return key, nil
}

// UseAnonymousSession sets the anonymous relay session (client.Options
// with Anonymous) used for sealed sends. Its Request should connect lazily
// and wait for the connection. Without one every message is sent
// identified.
func (a *App) UseAnonymousSession(s Requester) {
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	a.anon = s
}

func (a *App) anonSession() Requester {
	a.sessMu.RLock()
	defer a.sessMu.RUnlock()
	return a.anon
}

// SealedSenderConnected tells the interface whether the anonymous session
// is connected (tui.SealedSenderChanged). Repeated reports of the same
// state are not forwarded.
func (a *App) SealedSenderConnected(connected bool) {
	a.mu.Lock()
	changed := a.anonUp != connected
	a.anonUp = connected
	a.mu.Unlock()
	if changed {
		a.emit(tui.SealedSenderChanged{Connected: connected})
	}
}

// ownAccessKey returns the current own access key.
func (a *App) ownAccessKey() sealed.AccessKey {
	a.keyMu.RLock()
	defer a.keyMu.RUnlock()
	return a.accessKey
}

// publishAccessKey uploads the verifier of the own access key on the
// authenticated session.
func (a *App) publishAccessKey(ctx context.Context) error {
	sess := a.session()
	if sess == nil {
		return ErrOffline
	}
	verifier := a.ownAccessKey().Verifier()
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	_, err := sess.Request(rctx, protocol.TypeSetAccessKey, protocol.SetAccessKey{Verifier: verifier[:]})
	return err
}

// RotateAccessKey replaces the own access key and uploads the new
// verifier, which revokes the old key at the relay at once. The new key
// reaches the peers piggybacked on later messages and through a paced
// background redistribution (see the rules above). A failed upload is
// returned; the new key is kept and uploaded after the next
// authentication.
func (a *App) RotateAccessKey(ctx context.Context) error {
	key, err := sealed.NewAccessKey()
	if err != nil {
		return err
	}
	if err := a.prof.DB.PutSetting(ctx, settingAccessKey, key[:]); err != nil {
		return err
	}
	a.keyMu.Lock()
	a.accessKey = key
	a.keyMu.Unlock()
	a.redistribute()
	return a.publishAccessKey(ctx)
}

// revokeAccessKey rotates the own access key in the background after a
// peer lost the right to it (a removed contact or member, a left group),
// if the App takes part in sealed sender.
func (a *App) revokeAccessKey() {
	if a.anonSession() == nil {
		return
	}
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		ctx, cancel := a.lifetime()
		defer cancel()
		_ = a.RotateAccessKey(ctx)
	}()
}

// redistribute shares the own key with every peer in the background, one
// at a time with a random pause of up to shareDelay() in between, until
// the App stops.
func (a *App) redistribute() {
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		ctx, cancel := a.lifetime()
		defer cancel()
		peers, err := a.sharingPeers(ctx)
		if err != nil {
			return
		}
		for _, id := range peers {
			t := time.NewTimer(a.shareDelay())
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			a.shareAccessKey(ctx, id)
		}
	}()
}

// lifetime returns a context that ends when the App stops emitting.
func (a *App) lifetime() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-a.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// acceptedGroups returns the stored groups the user is an accepted member
// of.
func (a *App) acceptedGroups(ctx context.Context) ([]groupEntry, error) {
	list, err := a.prof.DB.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	var out []groupEntry
	for _, g := range list {
		e, err := parseGroupEntry(g.State, g.Left)
		if err == nil && !e.left && !e.invite && e.state.IsMember(a.selfID()) {
			out = append(out, e)
		}
	}
	return out, nil
}

// sharingPeers returns every contact and every member of an accepted
// group, without the user.
func (a *App) sharingPeers(ctx context.Context) ([]identity.ID, error) {
	contacts, err := a.prof.DB.ListContacts(ctx)
	if err != nil {
		return nil, err
	}
	groups, err := a.acceptedGroups(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[identity.ID]bool{a.selfID(): true}
	var out []identity.ID
	add := func(id identity.ID) {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, c := range contacts {
		add(c.ID)
	}
	for _, e := range groups {
		for _, id := range e.state.Members {
			add(id)
		}
	}
	return out, nil
}

// mayShareWith reports whether id is a contact or a member of an accepted
// group: the peers access keys are exchanged with.
func (a *App) mayShareWith(ctx context.Context, id identity.ID) bool {
	if id == a.selfID() {
		return false
	}
	if a.isContact(ctx, id) {
		return true
	}
	groups, err := a.acceptedGroups(ctx)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(groups, func(e groupEntry) bool { return e.state.IsMember(id) })
}

// peerAccessKey returns the stored access key of id, if any.
func (a *App) peerAccessKey(ctx context.Context, id identity.ID) (sealed.AccessKey, bool, error) {
	raw, err := a.prof.DB.GetSetting(ctx, idSetting(peerKeyPrefix, id))
	if errors.Is(err, clientdb.ErrNotFound) {
		return sealed.AccessKey{}, false, nil
	}
	if err != nil {
		return sealed.AccessKey{}, false, err
	}
	key, err := sealed.ParseAccessKey(raw)
	if err != nil {
		return sealed.AccessKey{}, false, nil
	}
	return key, true, nil
}

// setStale records whether the relay refused the stored access key of id.
func (a *App) setStale(ctx context.Context, id identity.ID, stale bool) {
	var value []byte
	if stale {
		value = []byte{1}
	} else if !a.keyStale(ctx, id) {
		return
	}
	_ = a.prof.DB.PutSetting(ctx, idSetting(staleKeyPrefix, id), value)
}

// keyStale reports whether the relay refused the stored access key of id.
func (a *App) keyStale(ctx context.Context, id identity.ID) bool {
	raw, err := a.prof.DB.GetSetting(ctx, idSetting(staleKeyPrefix, id))
	return err == nil && len(raw) > 0
}

// shareAccessKey sends the own access key to id over the pairwise session
// unless no anonymous session is attached (the App does not take part in
// sealed sender then), the key has been shared already, id is neither a
// contact nor a member of an accepted group, or there is no confirmed
// session with id. Failures are retried at the next opportunity.
func (a *App) shareAccessKey(ctx context.Context, id identity.ID) {
	if a.anonSession() == nil {
		return
	}
	own := a.ownAccessKey()
	if shared, err := a.prof.DB.GetSetting(ctx, idSetting(sharedKeyPrefix, id)); err == nil && subtle.ConstantTimeCompare(shared, own[:]) == 1 {
		return
	}
	if !a.mayShareWith(ctx, id) {
		return
	}
	cur, found, err := a.loadSession(ctx, id)
	if err != nil || !found || !cur.Confirmed {
		return
	}
	if reason := a.sendPairwise(ctx, id, e2e.KindAccessKey, own[:]); reason != "" {
		return
	}
	_ = a.prof.DB.PutSetting(ctx, idSetting(sharedKeyPrefix, id), own[:])
}

// fileAccessKey stores the access key received from the authenticated peer
// from and commits the session changes of its message. A key from someone
// who is neither a contact nor a member of an accepted group, or a
// malformed one, is ignored. a.groupMu and a.ratchetMu must be held.
func (a *App) fileAccessKey(ctx context.Context, from identity.ID, o opened) received {
	key, err := sealed.ParseAccessKey(o.plaintext.Body)
	if err == nil && a.mayShareWith(ctx, from) {
		if err := a.prof.DB.PutSetting(ctx, idSetting(peerKeyPrefix, from), key[:]); err != nil {
			a.countDropped()
			return received{outcome: outcomeRetry}
		}
		a.setStale(ctx, from, false)
	} else {
		a.countDropped()
	}
	if err := a.commitSession(ctx, from, o); err != nil {
		a.countDropped()
		return received{outcome: outcomeOf(err)}
	}
	return received{outcome: outcomeDone, peer: &from}
}

// sendRoute is how a pairwise message is handed to the relay.
type sendRoute struct {
	sealed bool
	proof  [sealed.VerifierSize]byte
}

// flag returns the message flag recording r.
func (r sendRoute) flag() uint8 {
	if r.sealed {
		return flagSentSealed
	}
	return flagSentIdentified
}

// routeTo decides how to send to id: sealed if an anonymous session is
// attached and id's access key is known, identified otherwise.
func (a *App) routeTo(ctx context.Context, id identity.ID) (sendRoute, error) {
	if a.anonSession() == nil {
		return sendRoute{}, nil
	}
	key, found, err := a.peerAccessKey(ctx, id)
	if err != nil || !found {
		return sendRoute{}, err
	}
	return sendRoute{sealed: true, proof: key.Verifier()}, nil
}

// routeOf returns how a stored outgoing message was sent, from its flags.
func routeOf(flags uint8) tui.SendRoute {
	switch {
	case flags&flagSentSealed != 0:
		return tui.RouteSealed
	case flags&flagSentIdentified != 0:
		return tui.RouteIdentified
	default:
		return tui.RouteUnknown
	}
}

// deliverPairwise hands a pairwise envelope for the contact c to the relay
// along route and returns the stored status with a short reason for
// failures. A sealed route never falls back to an identified send.
func (a *App) deliverPairwise(ctx context.Context, c clientdb.Contact, route sendRoute, payload []byte) (uint8, string) {
	id := identity.ID(c.ID)
	if !route.sealed {
		return a.deliver(ctx, id, payload)
	}
	anon := a.anonSession()
	if anon == nil {
		return clientdb.StatusFailed, "not connected (sealed sender)"
	}
	bundle, err := identity.ParseBundleForID(c.Bundle, id)
	if err != nil {
		return clientdb.StatusFailed, "the contact's keys are invalid"
	}
	envelope, err := sealed.Seal(a.selfID(), bundle, payload)
	if err != nil {
		return clientdb.StatusFailed, "could not seal the message"
	}
	frame, err := anon.Request(ctx, protocol.TypeSealedSend, protocol.SealedSend{To: id[:], AccessProof: route.proof[:], Payload: envelope})
	if refusedSealed(err) {
		a.setStale(ctx, id, true)
		return clientdb.StatusFailed, reasonSealedRefused
	}
	if reason := relayFailure(err); reason != "" {
		return clientdb.StatusFailed, reason + " (sealed sender)"
	}
	result, err := protocol.DecodeBody[protocol.SendResult](frame, protocol.TypeSendResult)
	if err != nil || result.Status != protocol.SendAccepted {
		return clientdb.StatusFailed, "unexpected answer from the server"
	}
	a.setStale(ctx, id, false)
	return clientdb.StatusDelivered, ""
}

// refusedSealed reports whether the relay refused a sealed send in a way
// that suggests the access key is no longer valid.
func refusedSealed(err error) bool {
	var remote *client.RemoteError
	return errors.As(err, &remote) && refusedCode(remote.Code)
}

func refusedCode(code protocol.ErrorCode) bool {
	return code == protocol.ErrCodeNotFound || code == protocol.ErrCodeRateLimited || code == protocol.ErrCodeInternal
}

// groupProofs returns the access proofs of every recipient in to, if an
// anonymous session is attached and every recipient's key is known, and
// nil otherwise: a group fan-out is sealed for all or for none.
func (a *App) groupProofs(ctx context.Context, to []identity.ID) map[identity.ID][sealed.VerifierSize]byte {
	if a.anonSession() == nil {
		return nil
	}
	proofs := make(map[identity.ID][sealed.VerifierSize]byte, len(to))
	for _, id := range to {
		key, found, err := a.peerAccessKey(ctx, id)
		if err != nil || !found {
			return nil
		}
		proofs[id] = key.Verifier()
	}
	return proofs
}

// sealedMulti sends a group envelope with SealedSendMulti to the members
// in to and to the user, proving access with proofs and the own verifier,
// entries sorted by ID. It returns the members the relay did not store it
// for and, if the request failed as a whole, a reason. Members whose key
// the relay refused are marked stale.
func (a *App) sealedMulti(ctx context.Context, to []identity.ID, proofs map[identity.ID][sealed.VerifierSize]byte, payload []byte) ([]identity.ID, string) {
	anon := a.anonSession()
	if anon == nil {
		return to, "not connected (sealed sender)"
	}
	self := a.selfID()
	own := a.ownAccessKey().Verifier()
	entries := []protocol.SealedRecipient{{To: self[:], AccessProof: own[:]}}
	for _, id := range to {
		proof := proofs[id]
		entries = append(entries, protocol.SealedRecipient{To: bytes.Clone(id[:]), AccessProof: proof[:]})
	}
	slices.SortFunc(entries, func(x, y protocol.SealedRecipient) int { return bytes.Compare(x.To, y.To) })
	frame, err := anon.Request(ctx, protocol.TypeSealedSendMulti, protocol.SealedSendMulti{Entries: entries, Payload: payload})
	if refusedSealed(err) {
		for _, id := range to {
			a.setStale(ctx, id, true)
		}
		return to, reasonSealedRefused
	}
	if reason := relayFailure(err); reason != "" {
		return to, reason + " (sealed sender)"
	}
	missed, codes, reason := multiOutcome(frame, to)
	for i, id := range missed {
		if refusedCode(codes[i]) {
			a.setStale(ctx, id, true)
		}
	}
	return missed, reason
}

// identifiedMulti sends a group envelope with SendMulti to the members in
// to and returns what sealedMulti returns.
func (a *App) identifiedMulti(ctx context.Context, to []identity.ID, payload []byte) ([]identity.ID, string) {
	sess := a.session()
	if sess == nil {
		return to, "not connected"
	}
	ids := make([][]byte, len(to))
	for i, id := range to {
		ids[i] = id[:]
	}
	frame, err := sess.Request(ctx, protocol.TypeSendMulti, protocol.SendMulti{To: ids, Payload: payload})
	if reason := relayFailure(err); reason != "" {
		return to, reason
	}
	missed, _, reason := multiOutcome(frame, to)
	return missed, reason
}

// multiOutcome decodes a SendMultiResult and returns the recipients of to
// it names as failed with their error codes, or every recipient and a
// reason if the answer is invalid.
func multiOutcome(frame protocol.Frame, to []identity.ID) ([]identity.ID, []protocol.ErrorCode, string) {
	result, err := protocol.DecodeBody[protocol.SendMultiResult](frame, protocol.TypeSendMultiResult)
	if err != nil || result.Status != protocol.SendAccepted {
		return to, make([]protocol.ErrorCode, len(to)), "unexpected answer from the server"
	}
	var missed []identity.ID
	var codes []protocol.ErrorCode
	for i, raw := range result.Failed {
		if len(raw) != identity.IDSize || !slices.Contains(to, identity.ID(raw)) {
			continue
		}
		code := protocol.ErrCodeNotFound
		if i < len(result.Reasons) {
			code = result.Reasons[i]
		}
		missed, codes = append(missed, identity.ID(raw)), append(codes, code)
	}
	return missed, codes, ""
}

// ownHeaderCandidate returns the header key of the user's current sender
// key generation in the group gid, so that the echo of an own sealed group
// message can be recognised.
func (a *App) ownHeaderCandidate(ctx context.Context, gid group.ID, epoch uint64) (senderkey.HeaderCandidate, bool) {
	s, err := a.ownSender(ctx, gid)
	if err != nil || s == nil {
		return senderkey.HeaderCandidate{}, false
	}
	defer s.Destroy()
	dist, err := s.Distribution(epoch)
	if err != nil {
		return senderkey.HeaderCandidate{}, false
	}
	defer clear(dist)
	r, err := senderkey.NewReceiver(dist, a.selfID())
	if err != nil {
		return senderkey.HeaderCandidate{}, false
	}
	defer r.Destroy()
	c, err := r.HeaderCandidate()
	return c, err == nil
}

// receiveSealed processes a delivery without a relay-known sender: it must
// carry a sealed pairwise envelope or a group envelope. a.groupMu must be
// held.
func (a *App) receiveSealed(ctx context.Context, d client.Delivery) received {
	if senderkey.IsGroupEnvelope(d.Payload) {
		r := a.receiveGroupEnvelope(ctx, identity.ID{}, d.Payload)
		out := received{outcome: r.outcome, changed: r.changed, events: r.events}
		if r.outcome == outcomeWait {
			out.hold = &pendingGroup{queueID: d.QueueID, envelope: bytes.Clone(d.Payload)}
		}
		return out
	}
	if !sealed.IsEnvelope(d.Payload) {
		a.countDropped()
		return received{outcome: outcomeDone}
	}
	return a.receiveSealedPairwise(ctx, d, nil)
}

// receiveSealedPairwise opens a sealed pairwise envelope and processes the
// inner envelope as a delivery from the claimed sender. relayFrom is the
// relay-reported sender of an identified delivery, which the claim must
// match, and nil for a sealed delivery. a.groupMu must be held.
func (a *App) receiveSealedPairwise(ctx context.Context, d client.Delivery, relayFrom *identity.ID) received {
	opened, err := sealed.Open(a.prof.Identity, d.Payload)
	if errors.Is(err, identity.ErrDestroyed) {
		return received{outcome: outcomeRetry}
	}
	if err != nil || opened.ClaimedSender == a.selfID() || (relayFrom != nil && opened.ClaimedSender != *relayFrom) {
		a.countDropped()
		return received{outcome: outcomeDone}
	}
	env, err := e2e.ParseEnvelope(opened.Inner)
	clear(opened.Inner)
	if err != nil {
		a.countDropped()
		return received{outcome: outcomeDone}
	}
	limit := identity.ID{}
	if relayFrom != nil {
		limit = *relayFrom
	}
	return a.openAndFile(ctx, d.QueueID, opened.ClaimedSender, env, limit)
}

// sealedSessionStart returns a new initiator session with c for a sealed
// route from prefetched prekeys. Without fresh ones it schedules a
// background fetch and returns a reason: prekeys are never fetched right
// before a sealed send.
func (a *App) sealedSessionStart(ctx context.Context, c clientdb.Contact) (clientdb.Session, string, error) {
	id := identity.ID(c.ID)
	a.mu.Lock()
	p, ok := a.prefetched[id]
	delete(a.prefetched, id)
	a.mu.Unlock()
	if !ok || a.now().Sub(p.at) > prefetchMaxAge {
		a.schedulePrefetch(id)
		return clientdb.Session{}, reasonSealedPreparing, nil
	}
	started, reason, err := a.sessionFromPrekeys(ctx, c, p.resp)
	if reason != "" {
		a.schedulePrefetch(id)
	}
	return started, reason, err
}

// schedulePrefetch fetches prekeys of id after a random pause of up to
// prefetchDelay(), in the background, unless a fetch is pending already.
func (a *App) schedulePrefetch(id identity.ID) {
	a.mu.Lock()
	if a.prefetching[id] {
		a.mu.Unlock()
		return
	}
	a.prefetching[id] = true
	a.mu.Unlock()
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		defer func() {
			a.mu.Lock()
			delete(a.prefetching, id)
			a.mu.Unlock()
		}()
		ctx, cancel := a.lifetime()
		defer cancel()
		t := time.NewTimer(a.prefetchDelay())
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		a.prefetchOne(ctx, id)
	}()
}

// prefetchOne fetches and keeps prekeys of id.
func (a *App) prefetchOne(ctx context.Context, id identity.ID) {
	resp, reason := a.requestPrekeys(ctx, id)
	if reason != "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prefetched[id] = prefetched{resp: resp, at: a.now()}
}

// prefetchPrekeys fetches prekeys for every peer whose access key is known
// but with whom there is no session, so that a sealed session start later
// does not need a fetch right before the send. It runs after connecting,
// as part of maintenance.
func (a *App) prefetchPrekeys(ctx context.Context) {
	if a.anonSession() == nil {
		return
	}
	peers, err := a.sharingPeers(ctx)
	if err != nil {
		return
	}
	for _, id := range peers {
		a.mu.Lock()
		_, have := a.prefetched[id]
		a.mu.Unlock()
		if have {
			continue
		}
		if _, found, err := a.peerAccessKey(ctx, id); err != nil || !found {
			continue
		}
		if _, found, err := a.loadSession(ctx, id); err != nil || found {
			continue
		}
		a.prefetchOne(ctx, id)
	}
}
