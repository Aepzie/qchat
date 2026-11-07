package tui

import (
	"context"
	"time"
)

// Backend is implemented by the application layer, which owns the identity,
// the contact database and the relay session. All methods may block briefly
// (disk access, a relay round trip) and are called from tea.Cmds, never from
// Update or View. Implementations must be safe for concurrent use, because
// several commands can be in flight at once.
//
// Contacts are identified by their identity ID in canonical form: "qc1-"
// followed by 52 lowercase base32 characters, without separators. The same
// string is used as ContactInfo.ID, as the contactID argument of every method
// and in every ChatEvent.
//
// Every string a Backend returns is treated as untrusted and sanitised before
// it is drawn.
type Backend interface {
	// Self describes the unlocked local identity.
	Self() SelfInfo
	// Contacts returns every contact, in the order the sidebar shows them.
	Contacts() ([]ContactInfo, error)
	// History returns up to limit of the most recent messages exchanged with a
	// contact, oldest first.
	History(contactID string, limit int) ([]MessageInfo, error)
	// AddContact looks up the identity bundle for id on the relay, checks
	// that it hashes to id, and stores the contact. An empty displayName
	// means none; the interface then shows the short ID.
	AddContact(ctx context.Context, id, displayName string) (ContactInfo, error)
	// RenameContact changes the local display name of a contact. Display
	// names never leave the device.
	RenameContact(contactID, displayName string) error
	// RemoveContact deletes a contact. Later messages from that identity
	// arrive as message requests.
	RemoveContact(contactID string) error
	// Send encrypts text for a contact and hands it to the relay. It returns
	// once the relay has answered, or with an error, and the returned
	// message carries the resulting status.
	Send(ctx context.Context, contactID, text string) (MessageInfo, error)
	// Verification returns the safety number shared with a contact.
	Verification(contactID string) (VerificationInfo, error)
	// MarkVerified records the user's decision after comparing safety
	// numbers. Either value also clears the key-changed flag, because the
	// user has now looked at the new safety number.
	MarkVerified(contactID string, verified bool) error
	// MarkRead resets the unread count of a contact.
	MarkRead(contactID string) error
}

// SelfInfo describes the local identity.
type SelfInfo struct {
	// DisplayName is the user's own name. It is stored locally only.
	DisplayName string
	// ID is the full identity ID, "qc1-" and 52 base32 characters. It is
	// what others need to /add the user, and what /whoami encodes as a QR
	// code.
	ID string
	// ShortID is an abbreviated ID for the status bar, such as "qc1-abcd-efgh".
	ShortID string
}

// ContactInfo describes one contact.
type ContactInfo struct {
	// ID is the contact's full identity ID.
	ID string
	// ShortID is an abbreviated ID for headers and lists.
	ShortID string
	// DisplayName is the name the user gave the contact; it may be empty.
	DisplayName string
	// Verified reports whether the user confirmed the safety number.
	Verified bool
	// KeyChanged reports that the contact's identity key changed since the
	// user last looked at the safety number. The interface warns until the
	// user decides again in /verify.
	KeyChanged bool
	// Unread counts messages the user has not seen.
	Unread int
}

// MessageStatus is the delivery state of a message.
type MessageStatus uint8

const (
	// StatusNone is used for incoming messages.
	StatusNone MessageStatus = iota
	// StatusSending means the message has not been answered by the relay yet.
	StatusSending
	// StatusSent means the relay accepted the message and forwarded it to a
	// connected device of the recipient.
	StatusSent
	// StatusRecipientOffline means the relay accepted the message but the
	// recipient was not connected. Phase 2 relays do not store messages, so
	// it was not delivered and will not be.
	StatusRecipientOffline
	// StatusFailed means the message could not be sent.
	StatusFailed
)

// String returns a lowercase name for the status.
func (s MessageStatus) String() string {
	switch s {
	case StatusSending:
		return "sending"
	case StatusSent:
		return "sent"
	case StatusRecipientOffline:
		return "recipient offline"
	case StatusFailed:
		return "failed"
	default:
		return "none"
	}
}

// MessageInfo is one message of a conversation.
type MessageInfo struct {
	// ID identifies the message within its conversation.
	ID string
	// Outgoing reports whether the user sent the message.
	Outgoing bool
	// Text is the message body.
	Text string
	// Sent is the time the sender's clock claims the message was written.
	Sent time.Time
	// Received is the local time an incoming message arrived. It is zero
	// for outgoing messages.
	Received time.Time
	// Status is the delivery state of an outgoing message.
	Status MessageStatus
	// Error explains StatusFailed.
	Error string
	// ClockSkew reports that Sent is more than 24 hours away from the local
	// time of arrival, so the sender's timestamp should not be trusted.
	ClockSkew bool
}

// VerificationInfo is what the user compares to verify a contact.
type VerificationInfo struct {
	// SafetyNumber is the 60-digit safety number. Spaces are allowed and
	// ignored.
	SafetyNumber string
	// QRPayload is the text encoded in the verification QR code.
	QRPayload string
	// Verified and KeyChanged mirror ContactInfo.
	Verified   bool
	KeyChanged bool
}

// ChatEvent is pushed by the application layer on Config.ChatEvents. The
// concrete types are IncomingMessage, MessageStatusChanged,
// ContactKeyChanged and ContactsChanged.
type ChatEvent interface {
	chatEvent()
}

// IncomingMessage reports a message that was decrypted and verified.
type IncomingMessage struct {
	// ContactID is the sender's identity ID.
	ContactID string
	// Message is the message itself.
	Message MessageInfo
	// UnknownSender reports that the sender is not a contact. Such messages
	// are shown under "Message requests".
	UnknownSender bool
}

// MessageStatusChanged reports a new delivery status for an outgoing message.
type MessageStatusChanged struct {
	ContactID string
	MessageID string
	Status    MessageStatus
	// Error explains StatusFailed.
	Error string
}

// ContactKeyChanged reports that a contact's identity key changed.
type ContactKeyChanged struct {
	ContactID string
}

// ContactsChanged asks the interface to reload the contact list.
type ContactsChanged struct{}

func (IncomingMessage) chatEvent()      {}
func (MessageStatusChanged) chatEvent() {}
func (ContactKeyChanged) chatEvent()    {}
func (ContactsChanged) chatEvent()      {}
