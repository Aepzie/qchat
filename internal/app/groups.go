package app

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/craguS/qchat/internal/e2e"
	"github.com/craguS/qchat/internal/group"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/senderkey"
	"github.com/craguS/qchat/internal/store/clientdb"
	"github.com/craguS/qchat/internal/tui"
)

// Group rules
//
// Groups follow docs/design/phase-4-groups.md, including the changes after
// the security review. Membership changes are signed controls (package
// group) sent pairwise over the ratchet sessions as e2e.KindGroupControl;
// every member's sending key is a sender key (package senderkey) handed to
// the other members pairwise as e2e.KindSenderKey; a group message is one
// group envelope, sent to all other members at once with SendMulti. Kinds 2
// and 3 are accepted only over pairwise sessions and group text
// (e2e.KindGroupText) only inside group envelopes.
//
// Members need not be contacts. The bundle of a member who is not a contact
// is fetched from the relay when it is first needed and kept in memory; a
// bundle always hashes to its ID, so the relay cannot substitute one. Every
// member must be registered with the relay before it is put into a group.
// A group created by, or joined through, someone who is not a contact is an
// invitation: it is stored and receives messages, but the user cannot send
// to it until it is accepted (or declines by leaving).
//
// Controls:
//
//   - A control is accepted only from its actor (the authenticated pairwise
//     peer) and only if group.Apply accepts it against the stored state. A
//     create for a group ID that is known (also after leaving) and a create
//     that does not list the user are dropped.
//   - A control for a later epoch than the next one waits (below). A control
//     for the current epoch that applies to the previous state conflicts
//     with the control applied last; group.Resolve picks the winner, and if
//     the new control wins the group moves to its result instead. A control
//     for an earlier epoch is stale and dropped.
//   - An add control reaches the new member after the group's full control
//     history; the new member replays it and accepts the group only if the
//     replay followed by the add ends in a state that lists it.
//   - On a remove or leave every remaining member deletes the departed
//     member's sender keys and every receiver distributed for an earlier
//     epoch, starts a new own generation if it has one (stored before
//     anything is sent) and distributes it to the remaining members only.
//     Processing holds groupMu throughout, so no group message is sent in
//     between. A member that is removed, or leaves, deletes all sender keys
//     of the group at once and keeps its history read only.
//   - On an add every member that has a sender key sends its current
//     generation to the new member only. A change that is reverted by a
//     conflict is handled like the opposite change, so a member whose add was
//     reverted is treated as removed and keys rotate.
//   - Failed fan-outs are reported as a notice and not retried.
//
// Sender keys: the creator starts its first generation with the group;
// every other member before it first sends. Before every message the
// generation is replaced if NeedsRotation says so. Own generations strictly
// increase, also across leaving and rejoining (groupEntry.ownGeneration).
// A distribution is accepted only from a current member, while the user is
// a member, for an epoch no earlier than the latest removal and a
// generation above every generation installed for that member; an
// installed generation is never overwritten. At most
// maxInstalledGenerations generations are kept per member.
//
// Group messages are accepted only from a current member that is also the
// relay's sender, decrypted with a receiver installed at or after the
// latest removal, and filed once per (group, sender, message ID).
//
// Waiting: deliveries may arrive out of order across pairwise sessions and
// the group fan-out (a message before its sender key, a sender key or
// control before the control that makes it applicable). Such input is kept
// in memory (at most maxPendingGroup items) and retried whenever a group
// state or sender key is stored. A group envelope keeps its relay delivery
// unacknowledged meanwhile, so it survives a restart; a pairwise group
// message has advanced its ratchet session already, so only its decrypted
// body is kept and it is lost if the client exits before it applies (the
// same holds for control history received for onboarding). An item is
// acknowledged and dropped once it applied, once it can never apply, after
// pendingMaxAge, or when the relay delivered it more than
// pendingMaxDeliveries times.
//
// After every (re)connection, group messages are held back until the
// relay's backlog has been processed (see backlogSettle), so that controls
// queued while offline apply before the user sends.

const (
	// maxPendingGroup bounds the deliveries waiting for group input.
	maxPendingGroup = 256
	// pendingMaxAge and pendingMaxDeliveries bound how long a delivery
	// waits.
	pendingMaxAge        = time.Hour
	pendingMaxDeliveries = 5
	// maxBundleCache bounds the bundles of non-contact members kept in
	// memory.
	maxBundleCache = 1024
	// maxOnboarding and maxOnboardingBytes bound the control histories
	// received for groups the user is being added to.
	maxOnboarding      = 8
	maxOnboardingBytes = 1 << 20
)

// Errors returned to the interface for groups. Their text is shown to the
// user.
var (
	ErrUnknownGroup   = errors.New("no such group")
	ErrLeftGroup      = errors.New("you are no longer a member of this group")
	ErrAloneInGroup   = errors.New("nobody else is in this group")
	ErrNotGroupMember = errors.New("not a member of this group")
	ErrInvitation     = errors.New("accept the invitation first with /group accept, or decline it with /group leave")
)

// groupResult is the outcome of processing group input.
type groupResult struct {
	outcome outcome
	// changed reports a stored group state or sender key, after which
	// waiting input is retried.
	changed bool
	events  []tui.ChatEvent
}

func doneResult(events ...tui.ChatEvent) groupResult {
	return groupResult{outcome: outcomeDone, events: events}
}

func (a *App) dropResult(events ...tui.ChatEvent) groupResult {
	a.countDropped()
	return groupResult{outcome: outcomeDone, events: events}
}

func waitResult() groupResult { return groupResult{outcome: outcomeWait} }

// pendingGroup is input waiting for a group state or sender key.
type pendingGroup struct {
	queueID uint64
	first   time.Time
	// deliveries counts how often the relay delivered it.
	deliveries int
	from       identity.ID
	// envelope is a group envelope; otherwise kind and body are the
	// decrypted pairwise message and bundle the sender bundle of its Init,
	// if any.
	envelope []byte
	kind     e2e.Kind
	body     []byte
	bundle   *identity.Bundle
}

// onboardKey names a control history received from an adder.
type onboardKey struct {
	from  identity.ID
	group group.ID
}

func (a *App) selfID() identity.ID { return a.prof.Identity.ID() }

// loadGroup returns the stored group id.
func (a *App) loadGroup(ctx context.Context, id group.ID) (groupEntry, bool, error) {
	g, err := a.prof.DB.GetGroup(ctx, id)
	if errors.Is(err, clientdb.ErrNotFound) {
		return groupEntry{}, false, nil
	}
	if err != nil {
		return groupEntry{}, false, err
	}
	e, err := parseGroupEntry(g.State, g.Left)
	if err != nil {
		return groupEntry{}, false, err
	}
	return e, true, nil
}

// storeGroup stores e. The join time is kept from the stored row while the
// user stays a member.
func (a *App) storeGroup(ctx context.Context, e groupEntry) error {
	blob, err := marshalGroupEntry(e)
	if err != nil {
		return err
	}
	joined := a.now()
	if g, err := a.prof.DB.GetGroup(ctx, e.state.GroupID); err == nil && !g.Left {
		joined = g.Joined
	}
	return a.prof.DB.PutGroup(ctx, clientdb.Group{ID: e.state.GroupID, State: blob, Joined: joined, Left: e.left})
}

// memberBundle returns the verified bundle of id: the stored contact
// bundle, the sender bundle of an Init (initBundle, may be nil), a cached
// bundle, or one fetched from the relay.
func (a *App) memberBundle(ctx context.Context, id identity.ID, initBundle *identity.Bundle) (*identity.Bundle, error) {
	if id == a.selfID() {
		return a.self, nil
	}
	c, err := a.prof.DB.GetContact(ctx, id)
	switch {
	case err == nil:
		if b, err := identity.ParseBundleForID(c.Bundle, id); err == nil {
			return b, nil
		}
	case !errors.Is(err, clientdb.ErrNotFound):
		return nil, err
	}
	if initBundle != nil && initBundle.ID == id {
		a.cacheBundle(initBundle)
		return initBundle, nil
	}
	a.mu.Lock()
	b, ok := a.bundles[id]
	a.mu.Unlock()
	if ok {
		return b, nil
	}
	b, err = a.fetchBundle(ctx, id)
	if err != nil {
		return nil, err
	}
	a.cacheBundle(b)
	return b, nil
}

func (a *App) cacheBundle(b *identity.Bundle) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.bundles) >= maxBundleCache {
		clear(a.bundles)
	}
	a.bundles[b.ID] = b
}

// isContact reports whether id is a stored contact.
func (a *App) isContact(ctx context.Context, id identity.ID) bool {
	_, err := a.prof.DB.GetContact(ctx, id)
	return err == nil
}

// memberContact returns the contact record used to send pairwise to a
// group member: the stored contact, or an unstored one carrying the
// member's verified bundle.
func (a *App) memberContact(ctx context.Context, id identity.ID) (clientdb.Contact, error) {
	c, err := a.prof.DB.GetContact(ctx, id)
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, clientdb.ErrNotFound) {
		return clientdb.Contact{}, err
	}
	b, err := a.memberBundle(ctx, id, nil)
	if err != nil {
		return clientdb.Contact{}, err
	}
	return clientdb.Contact{ID: id, Bundle: b.Raw, BundleSerial: b.Serial}, nil
}

// sendPairwise sends a group control or sender key message to id over the
// pairwise session and returns a short reason if it was not handed to the
// relay.
func (a *App) sendPairwise(ctx context.Context, id identity.ID, kind e2e.Kind, body []byte) string {
	ctx, cancel := context.WithTimeout(ctx, 2*requestTimeout)
	defer cancel()
	c, err := a.memberContact(ctx, id)
	if err != nil {
		return err.Error()
	}
	pt, err := e2e.NewPlaintext(kind, body, a.now())
	if err != nil {
		return err.Error()
	}
	payload, reason, err := a.sealOutgoing(ctx, c, pt, nil)
	switch {
	case err != nil:
		return err.Error()
	case reason != "":
		return reason
	}
	if status, reason := a.deliver(ctx, id, payload); status == clientdb.StatusFailed {
		return reason
	}
	return ""
}

// fanOut sends body to every identity in to except the user and returns a
// notice naming those it could not reach, or "".
func (a *App) fanOut(ctx context.Context, to []identity.ID, kind e2e.Kind, bodies ...[]byte) string {
	var failed []string
	for _, id := range to {
		if id == a.selfID() {
			continue
		}
		for _, body := range bodies {
			if reason := a.sendPairwise(ctx, id, kind, body); reason != "" {
				failed = append(failed, a.memberLabel(ctx, id)+" ("+reason+")")
				break
			}
		}
	}
	if len(failed) == 0 {
		return ""
	}
	return "Could not reach " + strings.Join(failed, ", ") + "."
}

// memberLabel names a member in notices: its contact name or short ID.
func (a *App) memberLabel(ctx context.Context, id identity.ID) string {
	if id == a.selfID() {
		return "you"
	}
	if c, err := a.prof.DB.GetContact(ctx, id); err == nil {
		if name := shownName(c); name != "" {
			return name
		}
	}
	return id.ShortString()
}

// ownSender loads the own sender key of a group, if any.
func (a *App) ownSender(ctx context.Context, id group.ID) (*senderkey.Sender, error) {
	raw, err := a.prof.DB.GetOwnSenderKey(ctx, id)
	if errors.Is(err, clientdb.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return senderkey.UnmarshalSender(raw)
}

// startSender starts the next own sender key generation of the group of e
// and stores it, after recording the generation in e (also stored), so
// that a generation number is never used twice.
func (a *App) startSender(ctx context.Context, e *groupEntry) (*senderkey.Sender, error) {
	e.ownGeneration++
	if err := a.storeGroup(ctx, *e); err != nil {
		return nil, err
	}
	s, err := senderkey.NewSender(e.state.GroupID, a.selfID(), e.ownGeneration)
	if err != nil {
		return nil, err
	}
	if err := a.putSender(ctx, s); err != nil {
		s.Destroy()
		return nil, err
	}
	return s, nil
}

func (a *App) putSender(ctx context.Context, s *senderkey.Sender) error {
	raw, err := s.Marshal()
	if err != nil {
		return err
	}
	defer clear(raw)
	return a.prof.DB.PutOwnSenderKey(ctx, s.Group(), raw)
}

// distribute sends the current distribution of s to the members to and
// returns a notice for failures.
func (a *App) distribute(ctx context.Context, s *senderkey.Sender, epoch uint64, to []identity.ID) string {
	dist, err := s.Distribution(epoch)
	if err != nil {
		return "Could not share your group key: " + err.Error() + "."
	}
	defer clear(dist)
	return a.fanOut(ctx, to, e2e.KindSenderKey, dist)
}

// others returns the members of st except the user.
func (a *App) others(st group.State) []identity.ID {
	self := a.selfID()
	return slices.DeleteFunc(slices.Clone(st.Members), func(id identity.ID) bool { return id == self })
}

// missing returns the IDs of from that are not in in.
func missing(from, in []identity.ID) []identity.ID {
	var out []identity.ID
	for _, id := range from {
		if !slices.Contains(in, id) {
			out = append(out, id)
		}
	}
	return out
}

// groupPlan is what remains to be sent after a group change was stored.
type groupPlan struct {
	state group.State
	// rotated is a new own sender key generation to distribute to every
	// other member; introduce lists new members that get the current one.
	rotated   bool
	introduce []identity.ID
}

// commitChange stores the move of a group from cur to next by control
// (raw encoding), applying the key rules for departed and new members, and
// returns what remains to be sent. With replaceLast the control replaces
// the last one of the history (a conflict that control won) instead of
// being appended. a.groupMu must be held.
func (a *App) commitChange(ctx context.Context, cur groupEntry, next group.State, control []byte, replaceLast bool) (groupPlan, error) {
	id := next.GroupID
	e := cur
	e.state = next
	e.history = slices.Clone(cur.history)
	if replaceLast && len(e.history) > 0 {
		e.history[len(e.history)-1] = control
	} else {
		prev := cur.state
		e.previous = &prev
		e.history = append(e.history, control)
	}
	if len(e.history) > maxHistory {
		return groupPlan{}, errors.New("app: group history is full")
	}
	plan := groupPlan{state: next}
	if !next.IsMember(a.selfID()) {
		e.left, e.installed = true, map[identity.ID][]installedGen{}
		if err := a.prof.DB.DeleteGroupSenderKeys(ctx, id); err != nil && !errors.Is(err, clientdb.ErrNotFound) {
			return groupPlan{}, err
		}
		return plan, a.storeGroup(ctx, e)
	}
	removed := missing(cur.state.Members, next.Members)
	if len(removed) > 0 {
		if err := a.dropReceivers(ctx, &e, removed); err != nil {
			return groupPlan{}, err
		}
		old, err := a.ownSender(ctx, id)
		if err != nil {
			return groupPlan{}, err
		}
		if old != nil {
			old.Destroy()
			s, err := a.startSender(ctx, &e)
			if err != nil {
				return groupPlan{}, err
			}
			s.Destroy()
			plan.rotated = true
		}
	}
	if err := a.storeGroup(ctx, e); err != nil {
		return groupPlan{}, err
	}
	if !plan.rotated {
		plan.introduce = missing(next.Members, cur.state.Members)
	}
	return plan, nil
}

// dropReceivers deletes every sender key of the departed members and every
// receiver installed for an epoch before the latest removal, and updates
// e.installed.
func (a *App) dropReceivers(ctx context.Context, e *groupEntry, departed []identity.ID) error {
	id := e.state.GroupID
	for _, m := range departed {
		if err := a.prof.DB.DeleteMemberSenderKeys(ctx, id, m); err != nil && !errors.Is(err, clientdb.ErrNotFound) {
			return err
		}
		delete(e.installed, m)
	}
	for m, gens := range e.installed {
		kept := gens[:0:0]
		for _, g := range gens {
			r, err := a.loadReceiver(ctx, id, m, g.gen)
			if err != nil {
				return err
			}
			if r != nil && r.GroupEpoch() >= e.state.LastRemovalEpoch {
				kept = append(kept, g)
				r.Destroy()
				continue
			}
			if r != nil {
				r.Destroy()
			}
			if err := a.prof.DB.DeleteMemberSenderKey(ctx, id, m, g.gen); err != nil && !errors.Is(err, clientdb.ErrNotFound) {
				return err
			}
		}
		if len(kept) == 0 {
			delete(e.installed, m)
			continue
		}
		e.installed[m] = kept
	}
	return nil
}

// loadReceiver loads a stored receiver, or nil if there is none or it is
// corrupt.
func (a *App) loadReceiver(ctx context.Context, id group.ID, member identity.ID, gen uint32) (*senderkey.Receiver, error) {
	raw, err := a.prof.DB.GetMemberSenderKey(ctx, id, member, gen)
	if errors.Is(err, clientdb.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	r, err := senderkey.UnmarshalReceiver(raw)
	if err != nil {
		return nil, nil
	}
	return r, nil
}

// carryOut sends the sender keys a stored change calls for and returns a
// notice for failures.
func (a *App) carryOut(ctx context.Context, plan groupPlan) string {
	if !plan.rotated && len(plan.introduce) == 0 {
		return ""
	}
	s, err := a.ownSender(ctx, plan.state.GroupID)
	if err != nil || s == nil {
		return ""
	}
	defer s.Destroy()
	if plan.rotated {
		return a.distribute(ctx, s, plan.state.Epoch, a.others(plan.state))
	}
	return a.distribute(ctx, s, plan.state.Epoch, plan.introduce)
}

// describeControl returns the notice shown for an accepted control.
func (a *App) describeControl(ctx context.Context, c *group.Control, next group.State) string {
	actor := a.memberLabel(ctx, c.Actor)
	target := a.memberLabel(ctx, c.Target)
	switch c.Op {
	case group.OpCreate:
		return actor + " created the group " + next.Name + "."
	case group.OpAdd:
		return actor + " added " + target + "."
	case group.OpRemove:
		return actor + " removed " + target + "."
	case group.OpPromote:
		return actor + " made " + target + " an admin."
	case group.OpDemote:
		return actor + " took admin rights from " + target + "."
	case group.OpRename:
		return actor + " renamed the group to " + next.Name + "."
	case group.OpLeave:
		return actor + " left the group."
	}
	return "The group changed."
}

func joinNotices(notices ...string) string {
	return strings.Join(slices.DeleteFunc(notices, func(s string) bool { return s == "" }), " ")
}

// applyGroupPayload processes a decrypted pairwise group message from the
// authenticated peer from. a.groupMu must be held, a.ratchetMu must not.
func (a *App) applyGroupPayload(ctx context.Context, from identity.ID, kind e2e.Kind, body []byte, initBundle *identity.Bundle) groupResult {
	if kind == e2e.KindSenderKey {
		return a.acceptDistribution(ctx, from, body)
	}
	msg, err := parseControlMessage(body)
	if err != nil {
		return a.dropResult()
	}
	if len(msg.History) > 0 && !a.keepHistory(from, msg.History) {
		return a.dropResult()
	}
	if len(msg.Control) == 0 {
		return doneResult()
	}
	return a.applyRemoteControl(ctx, from, msg.Control, initBundle)
}

// keepHistory appends controls received for onboarding from from. It
// reports false for input that is not a run of controls of one group or
// exceeds the bounds.
func (a *App) keepHistory(from identity.ID, controls [][]byte) bool {
	var gid group.ID
	size := 0
	for i, raw := range controls {
		c, err := group.ParseControl(raw)
		if err != nil || (i > 0 && c.GroupID != gid) {
			return false
		}
		gid = c.GroupID
		size += len(raw)
	}
	key := onboardKey{from: from, group: gid}
	a.mu.Lock()
	defer a.mu.Unlock()
	have, ok := a.onboarding[key]
	if !ok && len(a.onboarding) >= maxOnboarding {
		for k := range a.onboarding {
			delete(a.onboarding, k)
			break
		}
	}
	for _, raw := range have {
		size += len(raw)
	}
	if size > maxOnboardingBytes || len(have)+len(controls) > maxHistory {
		delete(a.onboarding, key)
		return false
	}
	a.onboarding[key] = append(have, controls...)
	return true
}

// takeHistory returns and forgets the onboarding history from from for gid.
func (a *App) takeHistory(from identity.ID, gid group.ID) [][]byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := onboardKey{from: from, group: gid}
	h := a.onboarding[key]
	delete(a.onboarding, key)
	return h
}

// bundleLookup returns the bundle function group.VerifyHistory and
// group.VerifyJoin take.
func (a *App) bundleLookup(ctx context.Context, known *identity.Bundle) func(identity.ID) (*identity.Bundle, error) {
	return func(id identity.ID) (*identity.Bundle, error) { return a.memberBundle(ctx, id, known) }
}

// controlEvent wraps a notice for the group of next.
func controlEvent(next group.State, notice string) tui.ChatEvent {
	return tui.GroupChanged{GroupID: groupKey(next.GroupID), Notice: notice}
}

// applyRemoteControl processes a group control from from.
func (a *App) applyRemoteControl(ctx context.Context, from identity.ID, raw []byte, initBundle *identity.Bundle) groupResult {
	c, err := group.ParseControl(raw)
	if err != nil || c.Actor != from {
		return a.dropResult()
	}
	cur, found, err := a.loadGroup(ctx, c.GroupID)
	if err != nil {
		return waitResult()
	}
	actor, err := a.memberBundle(ctx, from, initBundle)
	switch {
	case errors.Is(err, ErrUnknownIdentity) || errors.Is(err, ErrBadKey):
		return a.dropResult()
	case err != nil:
		return waitResult()
	}
	self := a.selfID()
	switch {
	case c.Op == group.OpCreate:
		if found {
			return a.dropResult()
		}
		next, err := group.Apply(nil, c, actor)
		if err != nil || !next.IsMember(self) {
			return a.dropResult()
		}
		return a.join(ctx, from, groupEntry{}, next, [][]byte{raw}, c)
	case !found || cur.left:
		if c.Op != group.OpAdd || c.Target != self {
			if found {
				return a.dropResult()
			}
			return waitResult()
		}
		history := a.takeHistory(from, c.GroupID)
		if len(history) == 0 {
			return a.dropResult()
		}
		full := append(slices.Clone(history), raw)
		next, err := group.VerifyJoin(full, self, from, a.bundleLookup(ctx, initBundle))
		if err != nil || !next.IsMember(self) {
			return a.dropResult()
		}
		prior, err := group.VerifyHistory(history, a.bundleLookup(ctx, initBundle))
		if err != nil {
			return a.dropResult()
		}
		if found {
			if err := a.prof.DB.DeleteGroupSenderKeys(ctx, c.GroupID); err != nil && !errors.Is(err, clientdb.ErrNotFound) {
				return waitResult()
			}
		}
		base := groupEntry{state: prior, history: history[:len(history):len(history)]}
		if found {
			base.ownGeneration = cur.ownGeneration
		}
		return a.join(ctx, from, base, next, full, c)
	case c.Epoch > cur.state.Epoch+1:
		return waitResult()
	case group.CanResolveAgainst(cur.state, c):
		return a.resolveConflict(ctx, cur, c, actor)
	case c.Epoch <= cur.state.Epoch:
		return a.dropResult()
	}
	next, err := group.Apply(&cur.state, c, actor)
	if err != nil {
		return a.dropResult()
	}
	plan, err := a.commitChange(ctx, cur, next, raw, false)
	if err != nil {
		return waitResult()
	}
	notice := joinNotices(a.describeControl(ctx, c, next), a.carryOut(ctx, plan))
	if !next.IsMember(self) && c.Op != group.OpLeave {
		notice = joinNotices(notice, "You can no longer send or read messages in this group.")
	}
	return groupResult{outcome: outcomeDone, changed: true, events: []tui.ChatEvent{controlEvent(next, notice)}}
}

// join stores a group the user was just put into, from the state base
// before the control c to next, with the full history.
func (a *App) join(ctx context.Context, from identity.ID, base groupEntry, next group.State, history [][]byte, c *group.Control) groupResult {
	e := groupEntry{
		state:         next,
		history:       history,
		previous:      &base.state,
		ownGeneration: base.ownGeneration,
		installed:     map[identity.ID][]installedGen{},
		invite:        !a.isContact(ctx, from),
	}
	if c.Op == group.OpCreate {
		e.previous = nil
	}
	if err := a.storeGroup(ctx, e); err != nil {
		return waitResult()
	}
	notice := a.describeControl(ctx, c, next)
	if e.invite {
		notice = joinNotices(notice, a.memberLabel(ctx, from)+" is not in your contacts, so this is an invitation. "+
			"Accept it with /group accept before you write, or decline with /group leave.")
	}
	return groupResult{outcome: outcomeDone, changed: true, events: []tui.ChatEvent{controlEvent(next, notice)}}
}

// resolveConflict handles a control for the epoch the group is already at:
// it conflicts with the control applied last, and the winner by
// group.ApplyOrResolve stands.
func (a *App) resolveConflict(ctx context.Context, cur groupEntry, c *group.Control, actor *identity.Bundle) groupResult {
	if cur.previous == nil || len(cur.history) == 0 {
		return a.dropResult()
	}
	last, err := group.ParseControl(cur.history[len(cur.history)-1])
	if err != nil || bytes.Equal(last.Raw, c.Raw) {
		return a.dropResult()
	}
	next, winner, err := group.ApplyOrResolve(*cur.previous, last, c, actor)
	if err != nil || winner != c {
		return a.dropResult()
	}
	plan, err := a.commitChange(ctx, cur, next, c.Raw, true)
	if err != nil {
		return waitResult()
	}
	notice := joinNotices("Two changes to the group conflicted; this one stands: "+a.describeControl(ctx, c, next), a.carryOut(ctx, plan))
	return groupResult{outcome: outcomeDone, changed: true, events: []tui.ChatEvent{controlEvent(next, notice)}}
}

// acceptDistribution stores the sender key generation a member distributed
// and freezes the member's older generations.
func (a *App) acceptDistribution(ctx context.Context, from identity.ID, body []byte) groupResult {
	info, err := senderkey.ParseDistribution(body)
	if err != nil {
		return a.dropResult()
	}
	e, found, err := a.loadGroup(ctx, info.GroupID)
	switch {
	case err != nil || !found:
		return waitResult()
	case e.left || !e.state.IsMember(a.selfID()) || from == a.selfID():
		return a.dropResult()
	case !e.state.IsMember(from) && info.GroupEpoch > e.state.Epoch:
		return waitResult()
	case !e.state.IsMember(from) || info.GroupEpoch < e.state.LastRemovalEpoch:
		return a.dropResult()
	case info.Generation <= e.lastInstalled(from):
		return a.dropResult()
	}
	_, err = a.prof.DB.GetMemberSenderKey(ctx, info.GroupID, from, info.Generation)
	switch {
	case err == nil:
		return a.dropResult()
	case !errors.Is(err, clientdb.ErrNotFound):
		return waitResult()
	}
	r, err := senderkey.NewReceiver(body, from)
	if err != nil {
		return a.dropResult()
	}
	defer r.Destroy()
	raw, err := r.Marshal()
	if err != nil {
		return a.dropResult()
	}
	defer clear(raw)
	now := a.now().Unix()
	gens := slices.Clone(e.installed[from])
	for i := range gens {
		if gens[i].frozenAt == 0 {
			if err := a.freezeReceiver(ctx, info.GroupID, from, gens[i].gen); err != nil {
				return waitResult()
			}
			gens[i].frozenAt = now
		}
	}
	gens = append(gens, installedGen{gen: info.Generation})
	for len(gens) > maxInstalledGenerations {
		if err := a.prof.DB.DeleteMemberSenderKey(ctx, info.GroupID, from, gens[0].gen); err != nil && !errors.Is(err, clientdb.ErrNotFound) {
			return waitResult()
		}
		gens = gens[1:]
	}
	if err := a.prof.DB.PutMemberSenderKey(ctx, info.GroupID, from, info.Generation, raw); err != nil {
		return waitResult()
	}
	e.installed[from] = gens
	if err := a.storeGroup(ctx, e); err != nil {
		_ = a.prof.DB.DeleteMemberSenderKey(ctx, info.GroupID, from, info.Generation)
		return waitResult()
	}
	return groupResult{outcome: outcomeDone, changed: true}
}

// freezeReceiver freezes a stored receiver so that its chain no longer
// advances.
func (a *App) freezeReceiver(ctx context.Context, gid group.ID, member identity.ID, gen uint32) error {
	r, err := a.loadReceiver(ctx, gid, member, gen)
	if err != nil || r == nil {
		return err
	}
	defer r.Destroy()
	r.Freeze()
	raw, err := r.Marshal()
	if err != nil {
		return err
	}
	defer clear(raw)
	return a.prof.DB.PutMemberSenderKey(ctx, gid, member, gen, raw)
}

// pruneGroupKeys deletes generations frozen longer than
// senderkey.RotationAge and skipped message keys older than that.
func (a *App) pruneGroupKeys(ctx context.Context) error {
	a.groupMu.Lock()
	defer a.groupMu.Unlock()
	list, err := a.prof.DB.ListGroups(ctx)
	if err != nil {
		return err
	}
	now := a.now()
	cutoff := now.Add(-senderkey.RotationAge)
	for _, g := range list {
		e, err := parseGroupEntry(g.State, g.Left)
		if err != nil || e.left {
			continue
		}
		changed := false
		for m, gens := range e.installed {
			kept := gens[:0:0]
			for _, ig := range gens {
				if ig.frozenAt != 0 && ig.frozenAt < cutoff.Unix() {
					if err := a.prof.DB.DeleteMemberSenderKey(ctx, g.ID, m, ig.gen); err != nil && !errors.Is(err, clientdb.ErrNotFound) {
						return err
					}
					changed = true
					continue
				}
				kept = append(kept, ig)
				if err := a.pruneReceiver(ctx, g.ID, m, ig.gen, cutoff); err != nil {
					return err
				}
			}
			if len(kept) == 0 {
				delete(e.installed, m)
				continue
			}
			e.installed[m] = kept
		}
		if changed {
			if err := a.storeGroup(ctx, e); err != nil {
				return err
			}
		}
	}
	return nil
}

// pruneReceiver deletes the skipped keys of a receiver derived before
// cutoff.
func (a *App) pruneReceiver(ctx context.Context, gid group.ID, member identity.ID, gen uint32, cutoff time.Time) error {
	r, err := a.loadReceiver(ctx, gid, member, gen)
	if err != nil || r == nil {
		return err
	}
	defer r.Destroy()
	if r.PruneSkipped(cutoff) == 0 {
		return nil
	}
	raw, err := r.Marshal()
	if err != nil {
		return err
	}
	defer clear(raw)
	return a.prof.DB.PutMemberSenderKey(ctx, gid, member, gen, raw)
}

// undecryptable is the notice for a group message that cannot be read.
func (a *App) undecryptable(ctx context.Context, gid group.ID, sender identity.ID, why string) tui.ChatEvent {
	return tui.GroupChanged{GroupID: groupKey(gid), Notice: "A message from " + a.memberLabel(ctx, sender) + " could not be decrypted: " + why + "."}
}

// headerCandidates returns the header keys of every installed generation of
// from in the groups the user is a member of. Group envelopes are routed
// only among the generations of the member the relay names as the sender.
func (a *App) headerCandidates(ctx context.Context, from identity.ID) ([]senderkey.HeaderCandidate, error) {
	list, err := a.prof.DB.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	var out []senderkey.HeaderCandidate
	for _, g := range list {
		if g.Left {
			continue
		}
		e, err := parseGroupEntry(g.State, g.Left)
		if err != nil || !e.state.IsMember(from) {
			continue
		}
		for _, ig := range e.installed[from] {
			r, err := a.loadReceiver(ctx, g.ID, from, ig.gen)
			if err != nil {
				return nil, err
			}
			if r == nil {
				continue
			}
			c, err := r.HeaderCandidate()
			r.Destroy()
			if err == nil {
				out = append(out, c)
			}
		}
	}
	return out, nil
}

// receiveGroupEnvelope decrypts and files a group message relayed from
// from. a.groupMu must be held.
func (a *App) receiveGroupEnvelope(ctx context.Context, from identity.ID, payload []byte) groupResult {
	candidates, err := a.headerCandidates(ctx, from)
	if err != nil {
		return groupResult{outcome: outcomeRetry}
	}
	idx, hdr, err := senderkey.OpenHeader(payload, candidates)
	for i := range candidates {
		clear(candidates[i].Key[:])
	}
	switch {
	case errors.Is(err, senderkey.ErrNoHeaderKey):
		return waitResult()
	case err != nil || idx < 0 || hdr.Sender != from:
		return a.dropResult()
	}
	gid, sender, gen := hdr.Group, hdr.Sender, hdr.Generation
	e, found, err := a.loadGroup(ctx, gid)
	switch {
	case err != nil:
		return groupResult{outcome: outcomeRetry}
	case !found || e.left || !e.state.IsMember(a.selfID()) || !e.state.IsMember(sender) || !e.hasInstalled(sender, gen):
		return a.dropResult()
	}
	r, err := a.loadReceiver(ctx, gid, sender, gen)
	switch {
	case err != nil:
		return groupResult{outcome: outcomeRetry}
	case r == nil:
		return a.dropResult()
	}
	defer r.Destroy()
	if r.GroupEpoch() < e.state.LastRemovalEpoch {
		return a.dropResult()
	}
	plain, hdr, err := r.Decrypt(payload)
	switch {
	case errors.Is(err, senderkey.ErrReplay):
		return a.dropResult()
	case errors.Is(err, senderkey.ErrFrozen):
		return a.dropResult(a.undecryptable(ctx, gid, sender, "it uses a group key that was replaced"))
	case err != nil:
		return a.dropResult(a.undecryptable(ctx, gid, sender, "it is damaged or forged"))
	}
	pt, err := e2e.ParsePlaintext(plain)
	clear(plain)
	if err != nil || pt.Kind != e2e.KindGroupText {
		return a.dropResult()
	}
	defer clear(pt.Body)
	state, err := r.Marshal()
	if err != nil {
		return groupResult{outcome: outcomeRetry}
	}
	defer clear(state)
	now := a.now()
	var flags uint8
	if e2e.ClockSkewed(pt.Sent, now) {
		flags |= clientdb.FlagClockSkew
	}
	m := clientdb.GroupMessage{Group: gid, Sender: sender, MsgID: pt.MsgID, Dir: clientdb.Incoming, Sent: pt.Sent,
		Received: now, Body: string(pt.Body), Status: clientdb.StatusReceived, Flags: flags}
	a.mu.Lock()
	err = a.prof.DB.CommitGroupReceive(ctx, gid, sender, gen, state, m)
	if err == nil {
		a.groupUnread[gid]++
	}
	a.mu.Unlock()
	if err != nil {
		if isTransient(dbError(err)) {
			return groupResult{outcome: outcomeRetry}
		}
		return a.dropResult()
	}
	outOfSync := hdr.StateBinding != e.state.Binding()
	a.mu.Lock()
	a.groupOutOfSync[gid] = outOfSync
	a.mu.Unlock()
	events := []tui.ChatEvent{a.groupMessageEvent(m, outOfSync)}
	if outOfSync && hdr.GroupEpoch == e.state.Epoch {
		events = append(events, tui.GroupChanged{GroupID: groupKey(gid), Notice: "Group out of sync: " + a.memberLabel(ctx, sender) +
			" sees a different membership at the same point. Compare /group members; an admin can fix it with a new change."})
	}
	return doneResult(events...)
}

// holdLocked keeps waiting input and reports whether it has waited too
// long, in which case it is dropped and must be acknowledged. a.groupMu
// must be held.
func (a *App) holdLocked(p pendingGroup) bool {
	now := a.now()
	if p.queueID != 0 {
		for i := range a.pending {
			if a.pending[i].queueID != p.queueID {
				continue
			}
			a.pending[i].deliveries++
			if a.pending[i].deliveries > pendingMaxDeliveries || now.Sub(a.pending[i].first) > pendingMaxAge {
				a.pending = slices.Delete(a.pending, i, i+1)
				a.countDropped()
				return true
			}
			return false
		}
	}
	p.first, p.deliveries = now, 1
	if len(a.pending) >= maxPendingGroup {
		a.pending = slices.Delete(a.pending, 0, 1)
	}
	a.pending = append(a.pending, p)
	return false
}

// retryPendingLocked retries waiting input until nothing more applies and
// returns the queue IDs to acknowledge and the events to show. Input that
// has waited longer than pendingMaxAge is dropped. Controls are retried before sender keys and
// messages. a.groupMu must be held.
func (a *App) retryPendingLocked(ctx context.Context, again bool) ([]uint64, []tui.ChatEvent) {
	var acks []uint64
	var events []tui.ChatEvent
	now := a.now()
	expired := func(p pendingGroup) bool {
		if now.Sub(p.first) <= pendingMaxAge {
			return false
		}
		a.countDropped()
		acks = append(acks, p.queueID)
		return true
	}
	a.pending = slices.DeleteFunc(a.pending, expired)
	slices.SortStableFunc(a.pending, func(x, y pendingGroup) int { return pendingRank(x) - pendingRank(y) })
	for again {
		again = false
		kept := a.pending[:0]
		for _, p := range a.pending {
			var r groupResult
			if p.envelope != nil {
				r = a.receiveGroupEnvelope(ctx, p.from, p.envelope)
			} else {
				r = a.applyGroupPayload(ctx, p.from, p.kind, p.body, p.bundle)
			}
			events = append(events, r.events...)
			again = again || r.changed
			switch r.outcome {
			case outcomeWait, outcomeRetry:
				kept = append(kept, p)
			case outcomeDone:
				acks = append(acks, p.queueID)
			}
		}
		clear(a.pending[len(kept):])
		a.pending = kept
	}
	return acks, events
}

// pendingRank orders waiting input: controls, then sender keys, then
// messages.
func pendingRank(p pendingGroup) int {
	switch {
	case p.envelope != nil:
		return 2
	case p.kind == e2e.KindSenderKey:
		return 1
	}
	return 0
}
