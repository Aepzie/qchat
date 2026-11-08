package tui

import (
	"context"
	"time"
)

// FileBackend is implemented by a Backend that can send and save files.
// The interface type-asserts its Backend for it; without it, /send and
// /save explain that file transfer is unavailable.
type FileBackend interface {
	// SendFile offers the file at path in a conversation (a contact or
	// group ID). It returns once the offer has been handed to the relay;
	// the content follows in the background, reported by FileChanged
	// events for the returned message.
	SendFile(ctx context.Context, conversationID, path string) (MessageInfo, error)
	// SaveFile writes the plaintext of a received or sent file, named by
	// the message that offered it, into a new file in dir ("" for the
	// default directory) and returns its path. It never replaces an
	// existing file.
	SaveFile(ctx context.Context, conversationID, messageID, dir string) (string, error)
}

// TimerBackend is implemented by a Backend that supports disappearing
// messages. The interface type-asserts its Backend for it.
type TimerBackend interface {
	// SetTimer sets the disappearing message timer of a conversation and
	// tells the other side; zero turns it off. Messages filed from then on
	// are deleted that long after they were sent or received.
	SetTimer(ctx context.Context, conversationID string, d time.Duration) error
	// Timer returns the current timer of a conversation, zero for off.
	Timer(conversationID string) (time.Duration, error)
}

// FileState is the state of a file transfer.
type FileState uint8

// File transfer states.
const (
	// FileReceiving: chunks are still arriving.
	FileReceiving FileState = iota + 1
	// FileComplete: the file arrived and was verified, or was sent.
	FileComplete
	// FileFailed: the transfer failed or the file did not verify.
	FileFailed
	// FileExpired: the transfer did not complete within a day.
	FileExpired
	// FileSending: the file is being sent.
	FileSending
)

// String returns a lowercase name for the state.
func (s FileState) String() string {
	switch s {
	case FileReceiving:
		return "receiving"
	case FileComplete:
		return "complete"
	case FileFailed:
		return "failed"
	case FileExpired:
		return "expired"
	case FileSending:
		return "sending"
	}
	return "unknown"
}

// FileInfo describes the file a message offers.
type FileInfo struct {
	// Name is the sanitised file name.
	Name string
	// Size is the file size in bytes.
	Size int64
	// MIME is the sender's media type guess; it may be empty.
	MIME  string
	State FileState
	// Done and Total count the chunks transferred so far and in all.
	Done, Total int
}

// FileChanged reports progress or a new state of a file transfer.
type FileChanged struct {
	// ConversationID is the contact or group the file belongs to.
	ConversationID string
	// MessageID is the message that offered the file.
	MessageID string
	File      FileInfo
}

// MessagesExpired reports disappearing messages that were deleted. The
// interface removes them from the conversation.
type MessagesExpired struct {
	ConversationID string
	MessageIDs     []string
}

// ConversationNotice is a system line for a conversation, such as a
// changed disappearing message timer.
type ConversationNotice struct {
	ConversationID string
	Notice         string
}

func (FileChanged) chatEvent()        {}
func (MessagesExpired) chatEvent()    {}
func (ConversationNotice) chatEvent() {}
