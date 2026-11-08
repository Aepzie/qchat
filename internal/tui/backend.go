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
// Groups are identified by "grp-" followed by 64 lowercase hex digits
// (GroupInfo.ID). History, Send and MarkRead accept a group ID wherever they
// accept a contact ID and then act on the group conversation.
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
	// Groups returns every group the user belongs to or has left, in the
	// order the sidebar shows them.
	Groups() ([]GroupInfo, error)
	// CreateGroup creates a group named name with the given members (full
	// identity IDs) and the user as its only admin, and tells every member.
	CreateGroup(ctx context.Context, name string, memberIDs []string) (GroupInfo, error)
	// ChangeGroup applies one membership or name change to a group and
	// tells the members. It fails if the user may not make the change.
	ChangeGroup(ctx context.Context, groupID string, change GroupChange) (GroupInfo, error)
}

// Names of the interface settings kept through SettingsBackend.
const (
	// SettingTheme holds the name of the theme chosen with /theme.
	SettingTheme = "ui.theme"
	// SettingMarkdown is "on" or "off", as chosen with /markdown.
	SettingMarkdown = "ui.markdown"
)

// SettingsBackend is implemented by a Backend that can persist interface
// preferences, such as the theme. The interface type-asserts its Backend
// for it; without it, preferences last until the client exits.
//
// Names are the Setting constants of this package. Values are short
// strings and are validated again when they are read back.
type SettingsBackend interface {
	// GetSetting returns the stored value, or "" and no error when the
	// setting was never stored.
	GetSetting(name string) (string, error)
	// SetSetting stores a value.
	SetSetting(name, value string) error
}

// SearchBackend is implemented by a Backend that can search the stored
// message history. The interface type-asserts its Backend for it; without
// it, /search explains that search is unavailable.
type SearchBackend interface {
	// Search returns up to limit stored messages whose text contains
	// query, ignoring case, newest first. conversationID is a contact or
	// group ID to search one conversation, or "" to search all of them.
	// Implementations may bound how much history they scan.
	Search(ctx context.Context, query string, conversationID string, limit int) ([]SearchHit, error)
}

// SearchHit is one message found by SearchBackend.Search.
type SearchHit struct {
	// ConversationID is the contact or group ID the message belongs to.
	ConversationID string
	// MessageID identifies the message within its conversation.
	MessageID string
	// Outgoing reports whether the user sent the message.
	Outgoing bool
	// From is the sender's identity ID for an incoming group message, and
	// empty otherwise.
	From string
	// Text is the message body, or for a long body an excerpt of it around
	// the match.
	Text string
	// At is when the message was received, or sent for an outgoing one.
	At time.Time
}

// GroupInfo describes one group.
type GroupInfo struct {
	// ID is the group ID, "grp-" and 64 hex digits.
	ID string
	// Name is the group name, chosen by its admins and shown to members.
	Name string
	// Members lists the members, the user included, sorted by ID.
	Members []GroupMember
	// Left reports that the user left or was removed. The conversation is
	// kept read only.
	Left bool
	// Invite reports that someone who is not a contact put the user into
	// the group. The user can read but not write until it accepts.
	Invite bool
	// Unread counts messages the user has not seen.
	Unread int
	// OutOfSync reports that a member's view of the group (membership,
	// admins or name) differs from the user's, so its messages may have
	// been sent to a different set of members.
	OutOfSync bool
}

// GroupMember is one member of a group.
type GroupMember struct {
	// ID is the member's full identity ID.
	ID string
	// ShortID is an abbreviated ID.
	ShortID string
	// DisplayName is the local name of a member who is a contact, or empty.
	DisplayName string
	// Admin reports whether the member may change the group.
	Admin bool
	// Self reports whether the member is the user.
	Self bool
}

// GroupOp is a change to a group.
type GroupOp uint8

// Group changes. Every change except GroupLeave needs admin rights.
const (
	// GroupAdd adds GroupChange.Member.
	GroupAdd GroupOp = iota + 1
	// GroupRemove removes GroupChange.Member.
	GroupRemove
	// GroupPromote makes GroupChange.Member an admin.
	GroupPromote
	// GroupDemote takes admin rights from GroupChange.Member.
	GroupDemote
	// GroupRename sets the name to GroupChange.Name.
	GroupRename
	// GroupLeave removes the user from the group, or declines an
	// invitation.
	GroupLeave
	// GroupAccept accepts an invitation (GroupInfo.Invite). It changes
	// nothing for the other members.
	GroupAccept
)

// GroupChange is the argument of Backend.ChangeGroup.
type GroupChange struct {
	Op GroupOp
	// Member is the full identity ID the change applies to, for add,
	// remove, promote and demote.
	Member string
	// Name is the new name, for rename.
	Name string
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
	// StatusSent means the relay accepted the message. It stores the
	// message until the recipient fetches it, whether or not the recipient
	// is connected right now.
	StatusSent
	// StatusRecipientOffline marks messages sent through a Phase 2 relay,
	// which accepted them while the recipient was not connected and did not
	// store them, so they were not delivered.
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
	// From is the sender's identity ID for an incoming group message, and
	// empty otherwise.
	From string
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
// ContactKeyChanged, ContactsChanged and GroupChanged.
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
	// are shown under "Message requests". It is never set for group
	// messages.
	UnknownSender bool
	// GroupID is set for a group message: the message belongs to that
	// group's conversation, and ContactID and Message.From name the sender.
	GroupID string
	// OutOfSync reports, for a group message, that the sender's view of the
	// group differs from the user's. The group is then shown as out of
	// sync until the next group list says otherwise.
	OutOfSync bool
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

// GroupChanged reports that a group was created, joined, changed or left.
// The interface reloads the group list and shows Notice, if any, in the
// group's conversation.
type GroupChanged struct {
	GroupID string
	Notice  string
}

func (IncomingMessage) chatEvent()      {}
func (MessageStatusChanged) chatEvent() {}
func (ContactKeyChanged) chatEvent()    {}
func (ContactsChanged) chatEvent()      {}
func (GroupChanged) chatEvent()         {}
