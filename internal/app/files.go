package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/Aepzie/qchat/internal/e2e"
	"github.com/Aepzie/qchat/internal/filexfer"
	"github.com/Aepzie/qchat/internal/group"
	"github.com/Aepzie/qchat/internal/identity"
	"github.com/Aepzie/qchat/internal/senderkey"
	"github.com/Aepzie/qchat/internal/store/clientdb"
	"github.com/Aepzie/qchat/internal/tui"
)

// File transfer rules (docs/design/phase-7-files.md)
//
// A file is offered with an e2e.KindFileOffer message, filed in the
// conversation like a text message (its body is the file name, flagged
// clientdb.FlagFile) together with a clientdb.FileTransfer holding the
// offer and its file key. Its chunks follow as e2e.KindFileChunk messages
// that are not shown. Both travel like any other message: over the pairwise
// session with a contact, or encrypted with the own sender key in a group.
//
// Sending: the file is read once, sealed chunk by chunk into the file store
// (so the sender can /save it too and a file that changes while it is read
// is refused), then offered, then its chunks are sent one at a time in the
// background, each after the relay answered the previous one and at most
// one per filePace, which keeps clear of the relay's per-session frame
// limit. A chunk the relay refuses is retried a few times with backoff
// before the transfer is marked failed.
//
// Receiving: offers and chunks are accepted from contacts only (pairwise)
// or from group members (as for group messages). Every chunk is
// authenticated with the file key before it is written to its slot of the
// transfer file; a chunk is written before the ratchet session or sender
// key that decrypted it is stored, so a local failure leaves the delivery
// unacknowledged and it is simply written again. When every chunk is there
// the file is verified as a whole (every chunk again and the SHA-256) and
// moved into the store, or marked failed. Transfers that are still
// incomplete after transferMaxAge are expired and their data deleted.
//
// Duplicate offers (same sender and file ID) and chunks of unknown,
// finished or failed transfers are dropped.

const (
	// filePace is the shortest interval between two chunks of a transfer.
	filePace = 100 * time.Millisecond
	// fileRetries and fileRetryBackoff bound the retries of a chunk the
	// relay refused.
	fileRetries      = 5
	fileRetryBackoff = time.Second
	// transferMaxAge is how long an incomplete transfer is kept.
	transferMaxAge = 24 * time.Hour
	// recountMargin: progress is recounted from the transfer file when it
	// is this close to complete, so that a count lost in a crash cannot
	// keep a transfer from completing.
	recountMargin = 8
	// progressSteps is how many progress events a transfer emits at most.
	progressSteps = 20
)

// Errors returned to the interface for files. Their text is shown to the
// user.
var (
	ErrNoSuchFile   = errors.New("no such file in this conversation")
	ErrFileNotReady = errors.New("this file has not arrived completely")
	ErrNotAFile     = errors.New("not a regular file")
)

// conversationRef is a parsed contact or group ID.
type conversationRef struct {
	id    [32]byte
	group bool
}

func parseConversation(s string) (conversationRef, error) {
	if isGroupKey(s) {
		gid, err := parseGroupKey(s)
		return conversationRef{id: gid, group: true}, err
	}
	id, err := parseContactID(s)
	return conversationRef{id: id}, err
}

// conversationKey returns the interface's ID of a conversation.
func conversationKey(id [32]byte, isGroup bool) string {
	if isGroup {
		return groupKey(group.ID(id))
	}
	return canonicalID(identity.ID(id))
}

// fileStore returns the profile's file store, opening it on first use.
func (a *App) fileStore() (*filexfer.Store, error) {
	a.filesOnce.Do(func() { a.files, a.filesErr = filexfer.OpenStore(a.prof.Dir) })
	return a.files, a.filesErr
}

// tryEmit delivers ev to the interface unless it is behind, in which case
// ev is dropped. It is used for progress, which a later event supersedes.
func (a *App) tryEmit(ev tui.ChatEvent) {
	a.emitMu.RLock()
	defer a.emitMu.RUnlock()
	if a.closed {
		return
	}
	select {
	case a.chat <- ev:
	default:
	}
}

// pause waits d and reports false if the App stopped meanwhile.
func (a *App) pause(d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-a.done:
		return false
	}
}

func newLocalID() (filexfer.LocalID, error) {
	var id filexfer.LocalID
	if _, err := rand.Read(id[:]); err != nil {
		return id, fmt.Errorf("app: reading randomness: %w", err)
	}
	return id, nil
}

func fileState(s uint8) tui.FileState {
	switch s {
	case clientdb.FileReceiving:
		return tui.FileReceiving
	case clientdb.FileComplete:
		return tui.FileComplete
	case clientdb.FileExpired:
		return tui.FileExpired
	case clientdb.FileSending:
		return tui.FileSending
	}
	return tui.FileFailed
}

// transferInfo describes a transfer for the interface.
func transferInfo(t clientdb.FileTransfer) (tui.FileInfo, bool) {
	o, err := filexfer.ParseOffer(t.Offer)
	if err != nil {
		return tui.FileInfo{}, false
	}
	clear(o.Key[:])
	return tui.FileInfo{Name: filexfer.SanitizeName(o.Name), Size: o.Size, MIME: o.MIME, State: fileState(t.State), Done: int(t.Done), Total: int(o.Chunks)}, true
}

// fileInfo returns the file offered by a message, or nil.
func (a *App) fileInfo(ctx context.Context, conv, sender [32]byte, msgID [e2e.MsgIDSize]byte) *tui.FileInfo {
	t, err := a.prof.DB.FileTransferByMessage(ctx, conv, sender, msgID)
	if err != nil {
		return nil
	}
	info, ok := transferInfo(t)
	if !ok {
		return nil
	}
	return &info
}

// fileEvent is the event for a changed transfer.
func fileEvent(t clientdb.FileTransfer) (tui.ChatEvent, bool) {
	info, ok := transferInfo(t)
	if !ok {
		return nil, false
	}
	return tui.FileChanged{ConversationID: conversationKey(t.Conv, t.Group), MessageID: hex.EncodeToString(t.MsgID[:]), File: info}, true
}

// fileJob is an offered file whose chunks are still to be sent.
type fileJob struct {
	conv     conversationRef
	contact  clientdb.Contact
	transfer clientdb.FileTransfer
	offer    filexfer.Offer
}

// SendFile offers the file at path in a conversation and sends its chunks
// in the background (see the file transfer rules).
func (a *App) SendFile(ctx context.Context, conversationID, path string) (tui.MessageInfo, error) {
	job, info, err := a.offerFile(ctx, conversationID, path)
	if err != nil || job == nil {
		return info, err
	}
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		a.sendChunks(job)
	}()
	return info, nil
}

// markSending records that the chunks of local are being sent, so that
// the sweeper leaves its files alone.
func (a *App) markSending(local filexfer.LocalID, on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if on {
		a.sending[local] = struct{}{}
		return
	}
	delete(a.sending, local)
}

// offerFile seals the file into the store, stores and sends its offer and
// returns the job for its chunks, or a nil job when the offer could not be
// sent (the returned message then says why).
func (a *App) offerFile(ctx context.Context, conversationID, path string) (*fileJob, tui.MessageInfo, error) {
	conv, err := parseConversation(conversationID)
	if err != nil {
		return nil, tui.MessageInfo{}, err
	}
	store, err := a.fileStore()
	if err != nil {
		return nil, tui.MessageInfo{}, err
	}
	job := &fileJob{conv: conv}
	if !conv.group {
		if job.contact, err = a.getContact(ctx, identity.ID(conv.id)); err != nil {
			return nil, tui.MessageInfo{}, err
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, tui.MessageInfo{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, tui.MessageInfo{}, err
	}
	if !fi.Mode().IsRegular() {
		return nil, tui.MessageInfo{}, ErrNotAFile
	}
	if err := filexfer.CheckSize(fi.Size()); err != nil {
		return nil, tui.MessageInfo{}, userFileError(err)
	}
	offer, err := filexfer.NewOffer(filepath.Base(path), fi.Size(), mime.TypeByExtension(filepath.Ext(path)))
	if err != nil {
		return nil, tui.MessageInfo{}, userFileError(err)
	}
	local, err := newLocalID()
	if err != nil {
		return nil, tui.MessageInfo{}, err
	}
	a.markSending(local, true)
	keep := false
	defer func() {
		if !keep {
			a.markSending(local, false)
		}
	}()
	if err := store.Import(local, &offer, f); err != nil {
		return nil, tui.MessageInfo{}, err
	}
	body, err := filexfer.MarshalOffer(offer)
	if err != nil {
		_ = store.Remove(local)
		return nil, tui.MessageInfo{}, err
	}
	defer clear(body)
	job.offer = offer
	job.transfer = clientdb.FileTransfer{Conv: conv.id, Group: conv.group, Sender: a.selfID(), FileID: offer.FileID, Local: local,
		Dir: clientdb.Outgoing, Offer: slices.Clone(body), State: clientdb.FileSending, Created: a.now()}
	var info tui.MessageInfo
	if conv.group {
		info, err = a.offerGroupFile(ctx, job, body)
	} else {
		info, err = a.offerPairwiseFile(ctx, job, body)
	}
	if err != nil {
		_ = store.Remove(local)
		_ = a.prof.DB.DeleteFileTransfer(context.Background(), conv.id, a.selfID(), offer.FileID)
		return nil, tui.MessageInfo{}, err
	}
	if info.Status == tui.StatusFailed {
		a.finishSend(job, clientdb.FileFailed)
		info.File = a.fileInfo(context.Background(), conv.id, a.selfID(), job.transfer.MsgID)
		return nil, info, nil
	}
	keep = true
	return job, info, nil
}

// userFileError rewords filexfer size errors for the interface.
func userFileError(err error) error {
	switch {
	case errors.Is(err, filexfer.ErrTooLarge):
		return fmt.Errorf("files are limited to %d MiB", filexfer.MaxFileSize>>20)
	case errors.Is(err, filexfer.ErrEmpty):
		return errors.New("the file is empty")
	}
	return err
}

func (a *App) offerPairwiseFile(ctx context.Context, job *fileJob, body []byte) (tui.MessageInfo, error) {
	id := identity.ID(job.conv.id)
	pt, err := e2e.NewPlaintext(e2e.KindFileOffer, body, a.now())
	if err != nil {
		return tui.MessageInfo{}, err
	}
	job.transfer.MsgID = pt.MsgID
	if err := a.prof.DB.PutFileTransfer(ctx, job.transfer); err != nil {
		return tui.MessageInfo{}, err
	}
	route, err := a.routeTo(ctx, id)
	if err != nil {
		return tui.MessageInfo{}, err
	}
	record := clientdb.Message{Peer: id, MsgID: pt.MsgID, Dir: clientdb.Outgoing, Sent: pt.Sent, Body: job.offer.Name,
		Status: clientdb.StatusSent, Flags: clientdb.FlagFile | route.flag(), Expires: a.expiryFor(ctx, id, pt.Sent)}
	payload, reason, err := a.sealOutgoing(ctx, job.contact, pt, &record, route)
	if err != nil {
		return tui.MessageInfo{}, err
	}
	if reason != "" {
		record.Status = clientdb.StatusFailed
		if err := a.prof.DB.AppendMessage(context.Background(), record); err != nil {
			return tui.MessageInfo{}, err
		}
		info := a.messageInfo(record)
		info.Error = reason
		return info, nil
	}
	key := messageKey{peer: id, msgID: record.MsgID}
	status, reason := a.deliverPairwise(ctx, job.contact, route, payload)
	record.Status = status
	a.mu.Lock()
	delete(a.inflight, key)
	updateErr := a.prof.DB.UpdateMessageStatus(context.Background(), id, record.MsgID, status)
	a.mu.Unlock()
	info := a.messageInfo(record)
	info.Error = reason
	return info, updateErr
}

func (a *App) offerGroupFile(ctx context.Context, job *fileJob, body []byte) (tui.MessageInfo, error) {
	gid := group.ID(job.conv.id)
	groupID := groupKey(gid)
	a.awaitBacklog(ctx)
	out, notice, err := a.sealGroupKind(ctx, gid, e2e.KindFileOffer, body, &clientdb.GroupMessage{Body: job.offer.Name, Flags: clientdb.FlagFile})
	if notice != "" {
		a.emit(tui.GroupChanged{GroupID: groupID, Notice: notice})
	}
	if err != nil {
		return tui.MessageInfo{}, err
	}
	job.transfer.MsgID = out.message.MsgID
	if err := a.prof.DB.PutFileTransfer(ctx, job.transfer); err != nil {
		return tui.MessageInfo{}, err
	}
	return a.deliverGroupMessage(ctx, groupID, out)
}

// sendChunks sends the chunks of an offered file and records the outcome.
func (a *App) sendChunks(job *fileJob) {
	defer a.markSending(job.transfer.Local, false)
	defer clear(job.offer.Key[:])
	store, err := a.fileStore()
	if err != nil {
		a.finishSend(job, clientdb.FileFailed)
		return
	}
	step := max(1, int(job.offer.Chunks)/progressSteps)
	for i := range job.offer.Chunks {
		if i > 0 && !a.pause(a.filePace) {
			a.finishSend(job, clientdb.FileFailed)
			return
		}
		sealed, err := store.Sealed(job.transfer.Local, &job.offer, i)
		if err != nil {
			a.finishSend(job, clientdb.FileFailed)
			return
		}
		body, err := filexfer.MarshalChunk(filexfer.Chunk{FileID: job.offer.FileID, Index: i, Total: job.offer.Chunks, Sealed: sealed})
		if err != nil || !a.sendChunk(job, body) {
			a.finishSend(job, clientdb.FileFailed)
			return
		}
		job.transfer.Done = i + 1
		if int(i+1)%step == 0 && i+1 < job.offer.Chunks {
			if ev, ok := fileEvent(job.transfer); ok {
				a.tryEmit(ev)
			}
		}
	}
	a.finishSend(job, clientdb.FileComplete)
}

// sendChunk encrypts one chunk message for the conversation and hands it
// to the relay, retrying refusals with backoff.
func (a *App) sendChunk(job *fileJob, body []byte) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*requestTimeout)
	defer cancel()
	deliver := func() bool { return false }
	if job.conv.group {
		gid := group.ID(job.conv.id)
		out, notice, err := a.sealGroupKind(ctx, gid, e2e.KindFileChunk, body, nil)
		if notice != "" {
			a.emit(tui.GroupChanged{GroupID: groupKey(gid), Notice: notice})
		}
		if err != nil {
			return false
		}
		deliver = func() bool {
			status, _, _ := a.deliverMulti(ctx, out.to, out.proofs, out.envelope)
			return status != clientdb.StatusFailed
		}
	} else {
		pt, err := e2e.NewPlaintext(e2e.KindFileChunk, body, a.now())
		if err != nil {
			return false
		}
		route, err := a.routeTo(ctx, identity.ID(job.conv.id))
		if err != nil {
			return false
		}
		payload, reason, err := a.sealOutgoing(ctx, job.contact, pt, nil, route)
		if err != nil || reason != "" {
			return false
		}
		deliver = func() bool {
			status, _ := a.deliverPairwise(ctx, job.contact, route, payload)
			return status != clientdb.StatusFailed
		}
	}
	backoff := fileRetryBackoff
	for attempt := 0; ; attempt++ {
		if deliver() {
			return true
		}
		if attempt == fileRetries || a.filePace == 0 || !a.pause(backoff) {
			return false
		}
		backoff *= 2
	}
}

// finishSend records the final state of a sent file, unless its record
// was deleted meanwhile (by a disappearing timer or a removed contact).
func (a *App) finishSend(job *fileJob, state uint8) {
	ctx := context.Background()
	t, err := a.prof.DB.GetFileTransfer(ctx, job.transfer.Conv, job.transfer.Sender, job.transfer.FileID)
	if err != nil {
		return
	}
	t.State, t.Done = state, job.transfer.Done
	if state == clientdb.FileComplete {
		t.Done = job.offer.Chunks
	}
	if a.prof.DB.PutFileTransfer(ctx, t) != nil {
		return
	}
	if ev, ok := fileEvent(t); ok {
		a.emit(ev)
	}
}

// SaveFile decrypts a stored file into a new file in dir.
func (a *App) SaveFile(ctx context.Context, conversationID, messageID, dir string) (string, error) {
	conv, err := parseConversation(conversationID)
	if err != nil {
		return "", err
	}
	raw, err := hex.DecodeString(messageID)
	if err != nil || len(raw) != e2e.MsgIDSize {
		return "", ErrNoSuchFile
	}
	msgID := [e2e.MsgIDSize]byte(raw)
	list, err := a.prof.DB.ListFileTransfers(ctx)
	if err != nil {
		return "", err
	}
	i := slices.IndexFunc(list, func(t clientdb.FileTransfer) bool {
		return t.Conv == conv.id && t.Group == conv.group && t.MsgID == msgID
	})
	if i < 0 {
		return "", ErrNoSuchFile
	}
	t := list[i]
	store, err := a.fileStore()
	if err != nil {
		return "", err
	}
	if (t.State != clientdb.FileComplete && t.Dir == clientdb.Incoming) || !store.Has(t.Local) {
		return "", ErrFileNotReady
	}
	o, err := filexfer.ParseOffer(t.Offer)
	if err != nil {
		return "", err
	}
	defer clear(o.Key[:])
	if dir == "" {
		dir = defaultSaveDir()
	}
	return store.Export(t.Local, &o, dir)
}

// defaultSaveDir is the user's Downloads directory, or the home directory
// when there is none.
func defaultSaveDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	downloads := filepath.Join(home, "Downloads")
	if fi, err := os.Stat(downloads); err == nil && fi.IsDir() {
		return downloads
	}
	return home
}

// openedExtension files a decrypted pairwise message of a Phase 7 kind.
// Files and timers are accepted from contacts only; from anyone else the
// session is stored and the content dropped. a.ratchetMu must be held.
func (a *App) openedExtension(ctx context.Context, from identity.ID, o opened) received {
	_, err := a.prof.DB.GetContact(ctx, from)
	switch {
	case errors.Is(err, clientdb.ErrNotFound):
		return a.commitOnly(ctx, from, o, true)
	case err != nil:
		return received{outcome: outcomeRetry}
	}
	switch o.plaintext.Kind {
	case e2e.KindFileOffer:
		return a.receivePairwiseOffer(ctx, from, o)
	case e2e.KindFileChunk:
		return a.receivePairwiseChunk(ctx, from, o)
	}
	d, err := parseTimerBody(o.plaintext.Body)
	if err != nil {
		return a.commitOnly(ctx, from, o, true)
	}
	r := a.commitOnly(ctx, from, o, false)
	if r.outcome == outcomeDone {
		r.events = append(r.events, a.applyTimer(ctx, from, false, from, d, o.plaintext.Sent)...)
	}
	return r
}

// commitOnly stores the session changes of a message that is not filed in
// the conversation, and counts it as dropped if drop is set.
func (a *App) commitOnly(ctx context.Context, from identity.ID, o opened, drop bool) received {
	if err := a.commitSession(ctx, from, o); err != nil {
		a.countDropped()
		return received{outcome: outcomeOf(err)}
	}
	var events []tui.ChatEvent
	if o.sender != nil && a.adoptBundle(from, o.sender) {
		events = append(events, tui.ContactKeyChanged{ContactID: canonicalID(from)})
	}
	if drop {
		a.countDropped()
	}
	return received{outcome: outcomeDone, events: events}
}

// beginTransfer checks a received offer and stores its transfer record
// and empty transfer file. It returns ok == false for an offer to drop and
// a transient error for a local failure.
func (a *App) beginTransfer(ctx context.Context, conv [32]byte, isGroup bool, sender identity.ID, msgID [e2e.MsgIDSize]byte, body []byte) (filexfer.Offer, bool, error) {
	o, err := filexfer.ParseOffer(body)
	if err != nil {
		return filexfer.Offer{}, false, nil
	}
	clear(o.Key[:])
	_, err = a.prof.DB.GetFileTransfer(ctx, conv, sender, o.FileID)
	switch {
	case err == nil:
		return filexfer.Offer{}, false, nil
	case !errors.Is(err, clientdb.ErrNotFound):
		return filexfer.Offer{}, false, transient(err)
	}
	store, err := a.fileStore()
	if err != nil {
		return filexfer.Offer{}, false, nil
	}
	local, err := newLocalID()
	if err != nil {
		return filexfer.Offer{}, false, transient(err)
	}
	if err := store.Begin(local); err != nil {
		return filexfer.Offer{}, false, transient(err)
	}
	t := clientdb.FileTransfer{Conv: conv, Group: isGroup, Sender: sender, FileID: o.FileID, MsgID: msgID, Local: local,
		Dir: clientdb.Incoming, Offer: slices.Clone(body), State: clientdb.FileReceiving, Created: a.now()}
	if err := a.prof.DB.PutFileTransfer(ctx, t); err != nil {
		_ = store.Remove(local)
		return filexfer.Offer{}, false, transient(err)
	}
	return o, true, nil
}

// abandonTransfer deletes a transfer whose offer could not be filed.
func (a *App) abandonTransfer(ctx context.Context, conv, sender [32]byte, fileID [filexfer.FileIDSize]byte) {
	t, err := a.prof.DB.GetFileTransfer(ctx, conv, sender, fileID)
	if err != nil {
		return
	}
	if store, err := a.fileStore(); err == nil {
		_ = store.Remove(t.Local)
	}
	_ = a.prof.DB.DeleteFileTransfer(ctx, conv, sender, fileID)
}

func (a *App) receivePairwiseOffer(ctx context.Context, from identity.ID, o opened) received {
	pt := o.plaintext
	offer, ok, err := a.beginTransfer(ctx, from, false, from, pt.MsgID, pt.Body)
	if err != nil {
		return received{outcome: outcomeRetry}
	}
	if !ok {
		return a.commitOnly(ctx, from, o, true)
	}
	now := a.now()
	flags := clientdb.FlagFile
	if e2e.ClockSkewed(pt.Sent, now) {
		flags |= clientdb.FlagClockSkew
	}
	record := clientdb.Message{Peer: from, MsgID: pt.MsgID, Dir: clientdb.Incoming, Sent: pt.Sent, Received: now,
		Body: filexfer.SanitizeName(offer.Name), Status: clientdb.StatusReceived, Flags: flags, Expires: a.expiryFor(ctx, from, now)}
	unknown, err := a.commitIncoming(ctx, o, record)
	if err != nil {
		a.abandonTransfer(ctx, from, from, offer.FileID)
		a.countDropped()
		if isTransient(err) {
			return received{outcome: outcomeRetry}
		}
		return received{outcome: outcomeDone}
	}
	if o.shadow != nil {
		a.keepShadow(from, *o.shadow)
	}
	var events []tui.ChatEvent
	if o.sender != nil && !unknown && a.adoptBundle(from, o.sender) {
		events = append(events, tui.ContactKeyChanged{ContactID: canonicalID(from)})
	}
	events = append(events, tui.IncomingMessage{ContactID: canonicalID(from), Message: a.messageInfo(record), UnknownSender: unknown})
	return received{outcome: outcomeDone, events: events}
}

func (a *App) receivePairwiseChunk(ctx context.Context, from identity.ID, o opened) received {
	t, offer, fresh, ok, err := a.storeChunk(ctx, from, from, o.plaintext.Body)
	if err != nil {
		return received{outcome: outcomeRetry}
	}
	r := a.commitOnly(ctx, from, o, !ok)
	if r.outcome == outcomeDone && ok {
		r.events = append(r.events, a.chunkStored(ctx, t, &offer, fresh)...)
	}
	return r
}

// storeChunk authenticates a received chunk of a transfer in conv from
// sender and writes it to the transfer file. It returns ok == false for a
// chunk to drop and an error for a local failure, after which the delivery
// must be retried.
func (a *App) storeChunk(ctx context.Context, conv, sender [32]byte, body []byte) (clientdb.FileTransfer, filexfer.Offer, bool, bool, error) {
	c, err := filexfer.ParseChunk(body)
	if err != nil {
		return clientdb.FileTransfer{}, filexfer.Offer{}, false, false, nil
	}
	t, err := a.prof.DB.GetFileTransfer(ctx, conv, sender, c.FileID)
	switch {
	case errors.Is(err, clientdb.ErrNotFound):
		return clientdb.FileTransfer{}, filexfer.Offer{}, false, false, nil
	case err != nil:
		return clientdb.FileTransfer{}, filexfer.Offer{}, false, false, err
	case t.Dir != clientdb.Incoming || t.State != clientdb.FileReceiving:
		return clientdb.FileTransfer{}, filexfer.Offer{}, false, false, nil
	}
	o, err := filexfer.ParseOffer(t.Offer)
	if err != nil {
		return clientdb.FileTransfer{}, filexfer.Offer{}, false, false, nil
	}
	store, err := a.fileStore()
	if err != nil {
		return clientdb.FileTransfer{}, filexfer.Offer{}, false, false, nil
	}
	fresh, err := store.Put(t.Local, &o, c)
	switch {
	case errors.Is(err, filexfer.ErrAuth), errors.Is(err, fs.ErrNotExist), errors.Is(err, filexfer.ErrUnsafePath):
		clear(o.Key[:])
		return clientdb.FileTransfer{}, filexfer.Offer{}, false, false, nil
	case err != nil:
		clear(o.Key[:])
		return clientdb.FileTransfer{}, filexfer.Offer{}, false, false, err
	}
	return t, o, fresh, true, nil
}

// chunkStored updates the progress of a transfer after a chunk was
// written, finishing it once every chunk is there, and returns the events
// to show. Progress itself is emitted directly and may be dropped.
func (a *App) chunkStored(ctx context.Context, t clientdb.FileTransfer, o *filexfer.Offer, fresh bool) []tui.ChatEvent {
	defer clear(o.Key[:])
	store, err := a.fileStore()
	if err != nil {
		return nil
	}
	if fresh {
		t.Done++
	}
	if !fresh || t.Done+recountMargin >= o.Chunks {
		if n, err := store.Received(t.Local, o); err == nil {
			t.Done = uint32(n)
		}
	}
	if t.Done >= o.Chunks {
		switch err := store.Finish(t.Local, o); {
		case err == nil:
			t.State = clientdb.FileComplete
		case errors.Is(err, filexfer.ErrAuth), errors.Is(err, filexfer.ErrHash):
			t.State = clientdb.FileFailed
			_ = store.Remove(t.Local)
		}
	}
	if a.prof.DB.PutFileTransfer(ctx, t) != nil {
		return nil
	}
	ev, ok := fileEvent(t)
	if !ok {
		return nil
	}
	if t.State != clientdb.FileReceiving {
		return []tui.ChatEvent{ev}
	}
	if step := max(1, o.Chunks/progressSteps); fresh && t.Done%step == 0 {
		a.tryEmit(ev)
	}
	return nil
}

// receiveGroupExtension files a decrypted group message of a Phase 7 kind
// from sender, decrypted by r (generation gen). a.groupMu must be held.
func (a *App) receiveGroupExtension(ctx context.Context, gid group.ID, sender identity.ID, gen uint32, r *senderkey.Receiver, pt e2e.Plaintext) groupResult {
	defer clear(pt.Body)
	state, err := r.Marshal()
	if err != nil {
		return groupResult{outcome: outcomeRetry}
	}
	defer clear(state)
	saveState := func() groupResult {
		if err := a.prof.DB.PutMemberSenderKey(ctx, gid, sender, gen, state); err != nil {
			if isTransient(dbError(err)) {
				return groupResult{outcome: outcomeRetry}
			}
			return a.dropResult()
		}
		return doneResult()
	}
	switch pt.Kind {
	case e2e.KindFileOffer:
		return a.receiveGroupOffer(ctx, gid, sender, gen, state, pt)
	case e2e.KindFileChunk:
		t, offer, fresh, ok, err := a.storeChunk(ctx, gid, sender, pt.Body)
		if err != nil {
			return groupResult{outcome: outcomeRetry}
		}
		if !ok {
			return a.dropResult()
		}
		res := saveState()
		if res.outcome == outcomeDone {
			res.events = a.chunkStored(ctx, t, &offer, fresh)
		}
		return res
	}
	d, err := parseTimerBody(pt.Body)
	if err != nil {
		return a.dropResult()
	}
	res := saveState()
	if res.outcome == outcomeDone {
		res.events = a.applyTimer(ctx, gid, true, sender, d, pt.Sent)
	}
	return res
}

func (a *App) receiveGroupOffer(ctx context.Context, gid group.ID, sender identity.ID, gen uint32, state []byte, pt e2e.Plaintext) groupResult {
	offer, ok, err := a.beginTransfer(ctx, gid, true, sender, pt.MsgID, pt.Body)
	if err != nil {
		return groupResult{outcome: outcomeRetry}
	}
	if !ok {
		return a.dropResult()
	}
	now := a.now()
	flags := clientdb.FlagFile
	if e2e.ClockSkewed(pt.Sent, now) {
		flags |= clientdb.FlagClockSkew
	}
	m := clientdb.GroupMessage{Group: gid, Sender: sender, MsgID: pt.MsgID, Dir: clientdb.Incoming, Sent: pt.Sent, Received: now,
		Body: filexfer.SanitizeName(offer.Name), Status: clientdb.StatusReceived, Flags: flags, Expires: a.expiryFor(ctx, gid, now)}
	a.mu.Lock()
	err = a.prof.DB.CommitGroupReceive(ctx, gid, sender, gen, state, m)
	if err == nil {
		a.groupUnread[gid]++
	}
	a.mu.Unlock()
	if err != nil {
		a.abandonTransfer(ctx, gid, sender, offer.FileID)
		if isTransient(dbError(err)) {
			return groupResult{outcome: outcomeRetry}
		}
		return a.dropResult()
	}
	return doneResult(a.groupMessageEvent(m, false))
}

// dropConversationFiles deletes every file of a conversation, for a
// removed contact.
func (a *App) dropConversationFiles(ctx context.Context, conv [32]byte, isGroup bool) {
	list, err := a.prof.DB.ListFileTransfers(ctx)
	if err != nil {
		return
	}
	for _, t := range list {
		if t.Conv == conv && t.Group == isGroup {
			a.abandonTransfer(ctx, t.Conv, t.Sender, t.FileID)
		}
	}
}

// expireTransfers expires incomplete transfers older than transferMaxAge,
// fails sends that were interrupted, and removes store files without a
// transfer record. It returns the events to show.
func (a *App) expireTransfers(ctx context.Context) []tui.ChatEvent {
	store, err := a.fileStore()
	if err != nil {
		return nil
	}
	list, err := a.prof.DB.ListFileTransfers(ctx)
	if err != nil {
		return nil
	}
	now := a.now()
	known := map[filexfer.LocalID]bool{}
	var events []tui.ChatEvent
	for _, t := range list {
		a.mu.Lock()
		_, sending := a.sending[t.Local]
		a.mu.Unlock()
		known[t.Local] = true
		switch {
		case t.State == clientdb.FileReceiving && now.Sub(t.Created) > transferMaxAge:
			t.State = clientdb.FileExpired
			_ = store.Remove(t.Local)
		case t.State == clientdb.FileSending && !sending:
			t.State = clientdb.FileFailed
		default:
			continue
		}
		if a.prof.DB.PutFileTransfer(ctx, t) != nil {
			continue
		}
		if ev, ok := fileEvent(t); ok {
			events = append(events, ev)
		}
	}
	a.mu.Lock()
	for id := range a.sending {
		known[id] = true
	}
	a.mu.Unlock()
	for _, id := range store.Orphans(func(id filexfer.LocalID) bool { return known[id] }) {
		_ = store.Remove(id)
	}
	return events
}

var _ tui.FileBackend = (*App)(nil)
