package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Aepzie/qchat/internal/client"
	"github.com/Aepzie/qchat/internal/e2e"
	"github.com/Aepzie/qchat/internal/filexfer"
	"github.com/Aepzie/qchat/internal/store/clientdb"
	"github.com/Aepzie/qchat/internal/tui"
)

// writeFile writes n random bytes to a new file called name.
func writeFile(t *testing.T, name string, n int) (string, []byte) {
	t.Helper()
	content := make([]byte, n)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, content
}

// sendFile offers a file and sends its chunks synchronously.
func (u *fakeUser) sendFile(conv, path string) tui.MessageInfo {
	u.t.Helper()
	u.app.filePace = 0
	job, info, err := u.app.offerFile(context.Background(), conv, path)
	if err != nil {
		u.t.Fatalf("offerFile: %v", err)
	}
	if job == nil {
		u.t.Fatalf("offer not sent: %+v", info)
	}
	u.app.sendChunks(job)
	return info
}

// deliver hands deliveries to u and returns the events shown.
func (u *fakeUser) deliver(ds []client.Delivery) []tui.ChatEvent {
	u.t.Helper()
	for _, d := range ds {
		u.app.handleDelivery(context.Background(), d)
	}
	return u.drainEvents()
}

func eventsOf[T tui.ChatEvent](events []tui.ChatEvent) []T {
	var out []T
	for _, ev := range events {
		if e, ok := ev.(T); ok {
			out = append(out, e)
		}
	}
	return out
}

// lastFileState returns the state of the last FileChanged event.
func lastFileState(t *testing.T, events []tui.ChatEvent) tui.FileState {
	t.Helper()
	changes := eventsOf[tui.FileChanged](events)
	if len(changes) == 0 {
		t.Fatal("no file event")
	}
	return changes[len(changes)-1].File.State
}

// pairedUsers returns two users who are contacts of each other with an
// established session.
func pairedUsers(t *testing.T) (*fakeRelay, *fakeUser, *fakeUser) {
	t.Helper()
	r := newFakeRelay()
	alice, bob := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
	alice.add(bob)
	bob.add(alice)
	alice.send(bob, "hi")
	bob.receive()
	bob.send(alice, "hello")
	alice.receive()
	return r, alice, bob
}

func (u *fakeUser) transfers() []clientdb.FileTransfer {
	u.t.Helper()
	list, err := u.prof.DB.ListFileTransfers(context.Background())
	if err != nil {
		u.t.Fatal(err)
	}
	return list
}

func TestFileTransferOutOfOrder(t *testing.T) {
	r, alice, bob := pairedUsers(t)
	path, content := writeFile(t, "holiday photo.jpg", 2*filexfer.ChunkSize+777)
	sent := alice.sendFile(bob.cid(), path)
	if sent.File == nil || sent.File.Name != "holiday photo.jpg" || sent.Text != "holiday photo.jpg" || sent.Status != tui.StatusSent {
		t.Fatalf("sent message %+v", sent)
	}

	queue := r.take(bob.id)
	if len(queue) != 4 {
		t.Fatalf("%d deliveries, want an offer and 3 chunks", len(queue))
	}
	offerEvents := bob.deliver(queue[:1])
	in := eventsOf[tui.IncomingMessage](offerEvents)
	if len(in) != 1 || in[0].Message.File == nil || in[0].Message.File.State != tui.FileReceiving || in[0].Message.File.Size != int64(len(content)) {
		t.Fatalf("offer events %+v", offerEvents)
	}
	reversed := slices.Clone(queue[1:])
	slices.Reverse(reversed)
	events := bob.deliver(reversed)
	if got := lastFileState(t, events); got != tui.FileComplete {
		t.Fatalf("final state %v", got)
	}
	acks := r.acksOf(bob.id)
	for _, d := range queue {
		if !slices.Contains(acks, d.QueueID) {
			t.Errorf("delivery %d not acknowledged (acks %v)", d.QueueID, acks)
		}
	}

	hist, err := bob.app.History(alice.cid(), 10)
	if err != nil {
		t.Fatal(err)
	}
	last := hist[len(hist)-1]
	if last.File == nil || last.File.State != tui.FileComplete || last.File.Done != 3 || last.File.Total != 3 {
		t.Fatalf("history %+v", last)
	}
	out := t.TempDir()
	saved, err := bob.app.SaveFile(context.Background(), alice.cid(), last.ID, out)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(saved); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("saved content differs (%v)", err)
	}
	again, err := bob.app.SaveFile(context.Background(), alice.cid(), last.ID, out)
	if err != nil || again == saved {
		t.Fatalf("second save %s, %v; must not overwrite %s", again, err, saved)
	}
	own, err := alice.app.SaveFile(context.Background(), bob.cid(), sent.ID, t.TempDir())
	if err != nil {
		t.Fatalf("sender saving its own file: %v", err)
	}
	if got, _ := os.ReadFile(own); !bytes.Equal(got, content) {
		t.Fatal("sender's copy differs")
	}
	if ts := alice.transfers(); len(ts) != 1 || ts[0].State != clientdb.FileComplete {
		t.Fatalf("alice's transfer %+v", ts)
	}
}

// sendRaw seals a message of any kind from u to the contact to and hands
// it to the relay, as a modified client could.
func (u *fakeUser) sendRaw(to *fakeUser, kind e2e.Kind, body []byte) {
	u.t.Helper()
	c, err := u.app.getContact(context.Background(), to.id)
	if err != nil {
		u.t.Fatal(err)
	}
	pt, err := e2e.NewPlaintext(kind, body, u.app.now())
	if err != nil {
		u.t.Fatal(err)
	}
	payload, reason, err := u.app.sealOutgoing(context.Background(), c, pt, nil, sendRoute{})
	if err != nil || reason != "" {
		u.t.Fatalf("seal: %v %s", err, reason)
	}
	if status, reason := u.app.deliver(context.Background(), to.id, payload); status == clientdb.StatusFailed {
		u.t.Fatal(reason)
	}
}

func TestTamperedChunkIsDropped(t *testing.T) {
	r, alice, bob := pairedUsers(t)
	path, content := writeFile(t, "a.bin", filexfer.ChunkSize+5)
	alice.sendFile(bob.cid(), path)
	queue := r.take(bob.id)
	bob.deliver(queue[:1])
	offer := offerOf(t, bob)

	forged := make([]byte, filexfer.SealedLen(&offer, 0))
	body, err := filexfer.MarshalChunk(filexfer.Chunk{FileID: offer.FileID, Index: 0, Total: offer.Chunks, Sealed: forged})
	if err != nil {
		t.Fatal(err)
	}
	alice.sendRaw(bob, e2e.KindFileChunk, body)
	before := bob.dropped()
	bob.deliver(r.take(bob.id))
	if bob.dropped() != before+1 {
		t.Fatalf("forged chunk not dropped (dropped %d -> %d)", before, bob.dropped())
	}
	if ts := bob.transfers(); ts[0].State != clientdb.FileReceiving || ts[0].Done != 0 {
		t.Fatalf("transfer after forged chunk %+v", ts[0])
	}
	events := bob.deliver(queue[1:])
	if got := lastFileState(t, events); got != tui.FileComplete {
		t.Fatalf("state after the real chunks %v", got)
	}
	saved, err := bob.app.SaveFile(context.Background(), alice.cid(), hex.EncodeToString(bob.transfers()[0].MsgID[:]), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(saved); !bytes.Equal(got, content) {
		t.Fatal("content differs")
	}
}

// offerOf returns the offer of u's only transfer.
func offerOf(t *testing.T, u *fakeUser) filexfer.Offer {
	t.Helper()
	ts := u.transfers()
	if len(ts) != 1 {
		t.Fatalf("%d transfers", len(ts))
	}
	o, err := filexfer.ParseOffer(ts[0].Offer)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestWrongFileHashFails(t *testing.T) {
	r, alice, bob := pairedUsers(t)
	path, _ := writeFile(t, "a.bin", 100)
	alice.app.filePace = 0
	store, err := alice.app.fileStore()
	if err != nil {
		t.Fatal(err)
	}
	contact, err := alice.app.getContact(context.Background(), bob.id)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := filexfer.NewOffer("a.bin", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	local, _ := newLocalID()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	err = store.Import(local, &offer, f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	offer.SHA256[0] ^= 1
	body, err := filexfer.MarshalOffer(offer)
	if err != nil {
		t.Fatal(err)
	}
	job := &fileJob{conv: conversationRef{id: bob.id}, contact: contact, offer: offer, transfer: clientdb.FileTransfer{
		Conv: bob.id, Sender: alice.id, FileID: offer.FileID, Local: local, Dir: clientdb.Outgoing, Offer: body, State: clientdb.FileSending, Created: alice.app.now()}}
	if _, err := alice.app.offerPairwiseFile(context.Background(), job, body); err != nil {
		t.Fatal(err)
	}
	alice.app.sendChunks(job)
	events := bob.deliver(r.take(bob.id))
	if got := lastFileState(t, events); got != tui.FileFailed {
		t.Fatalf("state %v, want failed", got)
	}
	ts := bob.transfers()
	if _, err := bob.app.SaveFile(context.Background(), alice.cid(), hex.EncodeToString(ts[0].MsgID[:]), t.TempDir()); !errors.Is(err, ErrFileNotReady) {
		t.Fatalf("saving a failed file: %v", err)
	}
	bobStore, _ := bob.app.fileStore()
	if bobStore.Has(filexfer.LocalID(ts[0].Local)) {
		t.Error("a file that failed verification was kept")
	}
}

func TestFileSizeLimit(t *testing.T) {
	_, alice, bob := pairedUsers(t)
	big := filepath.Join(t.TempDir(), "big.bin")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(filexfer.MaxFileSize + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := alice.app.SendFile(context.Background(), bob.cid(), big); err == nil {
		t.Fatal("a file above the limit was sent")
	}
	empty, _ := writeFile(t, "empty.txt", 0)
	if _, err := alice.app.SendFile(context.Background(), bob.cid(), empty); err == nil {
		t.Fatal("an empty file was sent")
	}
	if _, err := alice.app.SendFile(context.Background(), bob.cid(), t.TempDir()); !errors.Is(err, ErrNotAFile) {
		t.Fatalf("sending a directory: %v", err)
	}
	if len(alice.transfers()) != 0 {
		t.Error("refused files left transfer records")
	}
}

func TestFileFromStrangerIsDropped(t *testing.T) {
	r := newFakeRelay()
	alice, bob := newFakeUser(t, r, "Alice"), newFakeUser(t, r, "Bob")
	alice.add(bob)
	path, _ := writeFile(t, "x.txt", 10)
	alice.sendFile(bob.cid(), path)
	events := bob.deliver(r.take(bob.id))
	if len(eventsOf[tui.IncomingMessage](events)) != 0 || len(bob.transfers()) != 0 {
		t.Fatalf("a stranger's file was accepted: %+v", events)
	}
	if bob.dropped() != 2 {
		t.Errorf("dropped %d, want the offer and the chunk", bob.dropped())
	}
}

func TestPartialTransferExpires(t *testing.T) {
	r, alice, bob := pairedUsers(t)
	path, _ := writeFile(t, "a.bin", 3*filexfer.ChunkSize)
	alice.sendFile(bob.cid(), path)
	queue := r.take(bob.id)
	bob.deliver(queue[:2])
	bob.app.sweep(context.Background())
	if ts := bob.transfers(); ts[0].State != clientdb.FileReceiving || ts[0].Done != 1 {
		t.Fatalf("transfer %+v", ts[0])
	}
	local := filexfer.LocalID(bob.transfers()[0].Local)
	part := filepath.Join(bob.dir, "files", "incoming", local.String()+".part")
	if _, err := os.Stat(part); err != nil {
		t.Fatal(err)
	}

	r.clock.Advance(transferMaxAge + time.Minute)
	bob.app.sweep(context.Background())
	events := bob.drainEvents()
	if got := lastFileState(t, events); got != tui.FileExpired {
		t.Fatalf("state %v, want expired", got)
	}
	if _, err := os.Stat(part); !os.IsNotExist(err) {
		t.Errorf("the transfer file is still there: %v", err)
	}
	bob.deliver(queue[2:])
	if ts := bob.transfers(); ts[0].State != clientdb.FileExpired {
		t.Fatalf("late chunks revived the transfer: %+v", ts[0])
	}
}

func TestGroupFileTransfer(t *testing.T) {
	r, alice, bob, carol, gid := newGroupOfThree(t)
	path, content := writeFile(t, "minutes.txt", filexfer.ChunkSize+1)
	sent := alice.sendFile(gid, path)
	if sent.File == nil || sent.Status != tui.StatusSent {
		t.Fatalf("sent %+v", sent)
	}
	for _, u := range []*fakeUser{bob, carol} {
		events := u.deliver(r.take(u.id))
		in := eventsOf[tui.IncomingMessage](events)
		if len(in) != 1 || in[0].GroupID != gid || in[0].Message.File == nil || in[0].Message.From != alice.cid() {
			t.Fatalf("%s: offer events %+v", u.prof.DisplayName(), events)
		}
		if got := lastFileState(t, events); got != tui.FileComplete {
			t.Fatalf("%s: state %v", u.prof.DisplayName(), got)
		}
		saved, err := u.app.SaveFile(context.Background(), gid, in[0].Message.ID, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(saved); !bytes.Equal(got, content) {
			t.Fatalf("%s: content differs", u.prof.DisplayName())
		}
		hist, err := u.app.History(gid, 10)
		if err != nil || hist[len(hist)-1].File == nil || hist[len(hist)-1].File.State != tui.FileComplete {
			t.Fatalf("%s: history %+v, %v", u.prof.DisplayName(), hist, err)
		}
	}
}

func TestTimerAgreement(t *testing.T) {
	r, alice, bob := pairedUsers(t)
	ctx := context.Background()
	if err := alice.app.SetTimer(ctx, bob.cid(), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	events := bob.deliver(r.take(bob.id))
	notices := eventsOf[tui.ConversationNotice](events)
	if len(notices) != 1 || notices[0].ConversationID != alice.cid() {
		t.Fatalf("notices %+v", events)
	}
	for _, u := range []*fakeUser{alice, bob} {
		other := bob
		if u == bob {
			other = alice
		}
		if d, err := u.app.Timer(other.cid()); err != nil || d != 5*time.Minute {
			t.Fatalf("%s: timer %v, %v", u.prof.DisplayName(), d, err)
		}
	}

	r.clock.Advance(time.Second)
	if err := alice.app.SetTimer(ctx, bob.cid(), time.Hour); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(time.Second)
	if err := bob.app.SetTimer(ctx, alice.cid(), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	alice.deliver(r.take(alice.id))
	bob.deliver(r.take(bob.id))
	for _, u := range []*fakeUser{alice, bob} {
		other := bob
		if u == bob {
			other = alice
		}
		if d, _ := u.app.Timer(other.cid()); d != 30*time.Second {
			t.Fatalf("%s: timer %v after crossing changes, want the later 30s", u.prof.DisplayName(), d)
		}
	}

	r.clock.Advance(time.Second)
	if err := alice.app.SetTimer(ctx, bob.cid(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := bob.app.SetTimer(ctx, alice.cid(), time.Hour); err != nil {
		t.Fatal(err)
	}
	alice.deliver(r.take(alice.id))
	bob.deliver(r.take(bob.id))
	for _, u := range []*fakeUser{alice, bob} {
		other := bob
		if u == bob {
			other = alice
		}
		if d, _ := u.app.Timer(other.cid()); d != time.Hour {
			t.Fatalf("%s: timer %v after a tie, want the longer 1h", u.prof.DisplayName(), d)
		}
	}
	if err := alice.app.SetTimer(ctx, bob.cid(), 1500*time.Millisecond); !errors.Is(err, ErrInvalidTimer) {
		t.Errorf("fractional timer: %v", err)
	}
	if err := alice.app.SetTimer(ctx, bob.cid(), MaxTimer+time.Second); !errors.Is(err, ErrInvalidTimer) {
		t.Errorf("timer above the maximum: %v", err)
	}
}

func TestSweeperDeletesExpiredMessages(t *testing.T) {
	r, alice, bob := pairedUsers(t)
	ctx := context.Background()
	if err := alice.app.SetTimer(ctx, bob.cid(), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	bob.deliver(r.take(bob.id))
	m := alice.send(bob, "this will vanish")
	path, _ := writeFile(t, "vanishing.txt", 10)
	file := alice.sendFile(bob.cid(), path)
	in := eventsOf[tui.IncomingMessage](bob.deliver(r.take(bob.id)))
	if len(in) != 2 {
		t.Fatalf("bob received %+v", in)
	}

	r.clock.Advance(29 * time.Second)
	for _, u := range []*fakeUser{alice, bob} {
		u.app.sweep(ctx)
		if gone := eventsOf[tui.MessagesExpired](u.drainEvents()); len(gone) != 0 {
			t.Fatalf("%s: expired too early: %+v", u.prof.DisplayName(), gone)
		}
	}
	r.clock.Advance(2 * time.Second)
	for _, tc := range []struct {
		u    *fakeUser
		peer *fakeUser
		ids  []string
	}{{alice, bob, []string{m.ID, file.ID}}, {bob, alice, []string{in[0].Message.ID, in[1].Message.ID}}} {
		u := tc.u
		u.app.sweep(ctx)
		gone := eventsOf[tui.MessagesExpired](u.drainEvents())
		if len(gone) != 1 || gone[0].ConversationID != tc.peer.cid() || !sameSet(gone[0].MessageIDs, tc.ids) {
			t.Fatalf("%s: expired %+v, want %v", u.prof.DisplayName(), gone, tc.ids)
		}
		hist := u.history(tc.peer)
		if !slices.Equal(hist, []string{"hi", "hello"}) {
			t.Fatalf("%s: history after sweep %q", u.prof.DisplayName(), hist)
		}
		if len(u.transfers()) != 0 {
			t.Errorf("%s: the expired file's transfer is still stored", u.prof.DisplayName())
		}
		store, _ := u.app.fileStore()
		if orphans := store.Orphans(func(filexfer.LocalID) bool { return false }); len(orphans) != 0 {
			t.Errorf("%s: files left in the store: %v", u.prof.DisplayName(), orphans)
		}
	}
	if err := alice.app.SetTimer(ctx, bob.cid(), 0); err != nil {
		t.Fatal(err)
	}
	notices := eventsOf[tui.ConversationNotice](bob.deliver(r.take(bob.id)))
	if len(notices) != 1 {
		t.Fatalf("turning the timer off: %+v", notices)
	}
	alice.send(bob, "stays")
	bob.receive()
	r.clock.Advance(time.Hour)
	bob.app.sweep(ctx)
	if got := bob.history(alice); !slices.Contains(got, "stays") {
		t.Fatalf("a message sent with the timer off was deleted: %q", got)
	}
}

func TestGroupTimerExpiry(t *testing.T) {
	r, alice, bob, carol, gid := newGroupOfThree(t)
	ctx := context.Background()
	if err := alice.app.SetTimer(ctx, gid, time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, u := range []*fakeUser{bob, carol} {
		notices := eventsOf[tui.ConversationNotice](u.deliver(r.take(u.id)))
		if len(notices) != 1 || notices[0].ConversationID != gid {
			t.Fatalf("%s: notices %+v", u.prof.DisplayName(), notices)
		}
	}
	alice.sendGroup(gid, "short lived")
	settle(t, alice, bob, carol)
	r.clock.Advance(2 * time.Minute)
	for _, u := range []*fakeUser{alice, bob, carol} {
		u.app.sweep(ctx)
		gone := eventsOf[tui.MessagesExpired](u.drainEvents())
		if len(gone) != 1 || gone[0].ConversationID != gid || len(gone[0].MessageIDs) != 1 {
			t.Fatalf("%s: expired %+v", u.prof.DisplayName(), gone)
		}
		if slices.Contains(u.groupHistory(gid), "short lived") {
			t.Fatalf("%s: the message is still stored", u.prof.DisplayName())
		}
	}
}

func (u *fakeUser) history(peer *fakeUser) []string {
	u.t.Helper()
	msgs, err := u.app.History(peer.cid(), 100)
	if err != nil {
		u.t.Fatal(err)
	}
	var texts []string
	for _, m := range msgs {
		texts = append(texts, m.Text)
	}
	return texts
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func TestRemoveContactDeletesFiles(t *testing.T) {
	r, alice, bob := pairedUsers(t)
	path, _ := writeFile(t, "a.txt", 10)
	alice.sendFile(bob.cid(), path)
	bob.deliver(r.take(bob.id))
	if len(bob.transfers()) != 1 {
		t.Fatal("no transfer")
	}
	if err := bob.app.RemoveContact(alice.cid()); err != nil {
		t.Fatal(err)
	}
	if len(bob.transfers()) != 0 {
		t.Fatal("the removed contact's file is still stored")
	}
}
