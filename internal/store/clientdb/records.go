package clientdb

import (
	"fmt"
	"math"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
)

// Limits enforced when values are stored.
const (
	// MaxDisplayNameRunes is the maximum length of a contact display name.
	MaxDisplayNameRunes = 64
	// MaxBodySize is the maximum size of a message body in bytes.
	MaxBodySize = 64 << 10
	// MaxBundleSize is the maximum size of a stored identity bundle in bytes.
	MaxBundleSize = 64 << 10
	// MaxSettingNameLen is the maximum length of a setting name in bytes.
	MaxSettingNameLen = 64
	// MaxSettingValueSize is the maximum size of a setting value in bytes.
	MaxSettingValueSize = 64 << 10
	// MaxPageSize is the largest number of messages Messages returns at once.
	MaxPageSize = 500
)

// Direction says whether a message was sent or received.
type Direction uint8

// Message directions.
const (
	Outgoing Direction = 1
	Incoming Direction = 2
)

// Message delivery states.
const (
	StatusSent      uint8 = 1
	StatusDelivered uint8 = 2
	StatusOffline   uint8 = 3
	StatusFailed    uint8 = 4
	StatusReceived  uint8 = 5
)

// Message flags.
const (
	// FlagClockSkew marks a message whose sender timestamp differs too much
	// from the local clock.
	FlagClockSkew uint8 = 1 << 0
	// FlagFile marks the offer of a file transfer: the body is the file
	// name and the transfer itself is a FileTransfer.
	FlagFile uint8 = 1 << 1
)

// Contact is a known peer identity.
type Contact struct {
	ID           [32]byte
	DisplayName  string
	Bundle       []byte
	BundleSerial uint64
	Verified     bool
	VerifiedAt   time.Time
	KeyChangedAt time.Time // zero if the key never changed
	AddedAt      time.Time
}

// Message is one message of a 1:1 conversation.
type Message struct {
	Peer     [32]byte
	MsgID    [16]byte
	Dir      Direction
	Sent     time.Time
	Received time.Time
	Body     string
	Status   uint8
	Flags    uint8
	// Expires is when a disappearing message is deleted (see
	// DeleteExpiredMessages); zero keeps it.
	Expires time.Time
	// Seq is the local sequence number assigned when the message was
	// appended. It is ignored by AppendMessage and is the cursor to pass as
	// "before" to Messages for the previous page.
	Seq int64
}

// contactRecord is the encrypted form of Contact.
type contactRecord struct {
	ID           []byte `cbor:"1,keyasint"`
	DisplayName  string `cbor:"2,keyasint"`
	Bundle       []byte `cbor:"3,keyasint"`
	BundleSerial uint64 `cbor:"4,keyasint"`
	Verified     bool   `cbor:"5,keyasint"`
	VerifiedAt   int64  `cbor:"6,keyasint"`
	KeyChangedAt int64  `cbor:"7,keyasint"`
	AddedAt      int64  `cbor:"8,keyasint"`
}

// messageRecord is the encrypted form of Message.
type messageRecord struct {
	Peer     []byte `cbor:"1,keyasint"`
	MsgID    []byte `cbor:"2,keyasint"`
	Dir      uint8  `cbor:"3,keyasint"`
	Sent     int64  `cbor:"4,keyasint"`
	Received int64  `cbor:"5,keyasint"`
	Body     string `cbor:"6,keyasint"`
	Status   uint8  `cbor:"7,keyasint"`
	Flags    uint8  `cbor:"8,keyasint"`
	Expires  int64  `cbor:"9,keyasint,omitempty"`
}

// settingRecord is the encrypted form of a setting.
type settingRecord struct {
	Name  string `cbor:"1,keyasint"`
	Value []byte `cbor:"2,keyasint"`
}

// canaryRecord is the plaintext of the canary row.
type canaryRecord struct {
	Magic string `cbor:"1,keyasint"`
}

const canaryMagic = "qchat clientdb canary v1"

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	var err error
	encMode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	decMode, err = cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		MaxNestedLevels:   4,
		MaxArrayElements:  16,
		MaxMapPairs:       16,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// encode serializes a record with deterministic CBOR.
func encode(v any) ([]byte, error) {
	b, err := encMode.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("clientdb: encode record: %w", err)
	}
	return b, nil
}

// decode parses a decrypted record. Malformed records are reported as
// ErrCorrupt.
func decode(b []byte, v any) error {
	if err := decMode.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return nil
}

// timeToNanos encodes t as Unix nanoseconds, with 0 for the zero time.
func timeToNanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// nanosToTime decodes a value produced by timeToNanos, in UTC.
func nanosToTime(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

var (
	minStorableTime = time.Unix(0, 1)
	maxStorableTime = time.Unix(0, math.MaxInt64)
)

// checkTime reports whether t is zero or representable as positive Unix
// nanoseconds.
func checkTime(field string, t time.Time) error {
	if t.IsZero() {
		return nil
	}
	if t.Before(minStorableTime) || t.After(maxStorableTime) {
		return fmt.Errorf("%w: %s out of range", ErrInvalid, field)
	}
	return nil
}

// ValidateDisplayName reports whether name is an acceptable display name:
// valid UTF-8, 1 to MaxDisplayNameRunes runes, no control characters.
func ValidateDisplayName(name string) error {
	if !utf8.ValidString(name) {
		return fmt.Errorf("%w: display name is not valid UTF-8", ErrInvalid)
	}
	n := utf8.RuneCountInString(name)
	if n == 0 || n > MaxDisplayNameRunes {
		return fmt.Errorf("%w: display name must be 1 to %d characters", ErrInvalid, MaxDisplayNameRunes)
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("%w: display name contains a control character", ErrInvalid)
		}
	}
	return nil
}

func (c *Contact) validate() error {
	if err := ValidateDisplayName(c.DisplayName); err != nil {
		return err
	}
	if len(c.Bundle) > MaxBundleSize {
		return fmt.Errorf("%w: bundle larger than %d bytes", ErrInvalid, MaxBundleSize)
	}
	for _, f := range []struct {
		name string
		t    time.Time
	}{{"VerifiedAt", c.VerifiedAt}, {"KeyChangedAt", c.KeyChangedAt}, {"AddedAt", c.AddedAt}} {
		if err := checkTime(f.name, f.t); err != nil {
			return err
		}
	}
	return nil
}

func (c *Contact) record() contactRecord {
	return contactRecord{
		ID:           c.ID[:],
		DisplayName:  c.DisplayName,
		Bundle:       c.Bundle,
		BundleSerial: c.BundleSerial,
		Verified:     c.Verified,
		VerifiedAt:   timeToNanos(c.VerifiedAt),
		KeyChangedAt: timeToNanos(c.KeyChangedAt),
		AddedAt:      timeToNanos(c.AddedAt),
	}
}

func (r *contactRecord) contact() (Contact, error) {
	var c Contact
	if len(r.ID) != len(c.ID) {
		return Contact{}, fmt.Errorf("%w: bad contact ID length", ErrCorrupt)
	}
	copy(c.ID[:], r.ID)
	c.DisplayName = r.DisplayName
	c.Bundle = r.Bundle
	c.BundleSerial = r.BundleSerial
	c.Verified = r.Verified
	c.VerifiedAt = nanosToTime(r.VerifiedAt)
	c.KeyChangedAt = nanosToTime(r.KeyChangedAt)
	c.AddedAt = nanosToTime(r.AddedAt)
	return c, nil
}

func validStatus(s uint8) bool { return s >= StatusSent && s <= StatusReceived }

func (m *Message) validate() error {
	if m.Dir != Outgoing && m.Dir != Incoming {
		return fmt.Errorf("%w: unknown direction %d", ErrInvalid, m.Dir)
	}
	if !validStatus(m.Status) {
		return fmt.Errorf("%w: unknown status %d", ErrInvalid, m.Status)
	}
	if len(m.Body) > MaxBodySize {
		return fmt.Errorf("%w: body larger than %d bytes", ErrInvalid, MaxBodySize)
	}
	if !utf8.ValidString(m.Body) {
		return fmt.Errorf("%w: body is not valid UTF-8", ErrInvalid)
	}
	if err := checkTime("Sent", m.Sent); err != nil {
		return err
	}
	if err := checkTime("Expires", m.Expires); err != nil {
		return err
	}
	return checkTime("Received", m.Received)
}

func (m *Message) record() messageRecord {
	return messageRecord{
		Peer:     m.Peer[:],
		MsgID:    m.MsgID[:],
		Dir:      uint8(m.Dir),
		Sent:     timeToNanos(m.Sent),
		Received: timeToNanos(m.Received),
		Body:     m.Body,
		Status:   m.Status,
		Flags:    m.Flags,
		Expires:  timeToNanos(m.Expires),
	}
}

func (r *messageRecord) message(seq int64) (Message, error) {
	var m Message
	if len(r.Peer) != len(m.Peer) || len(r.MsgID) != len(m.MsgID) {
		return Message{}, fmt.Errorf("%w: bad message identifier length", ErrCorrupt)
	}
	copy(m.Peer[:], r.Peer)
	copy(m.MsgID[:], r.MsgID)
	m.Dir = Direction(r.Dir)
	m.Sent = nanosToTime(r.Sent)
	m.Received = nanosToTime(r.Received)
	m.Body = r.Body
	m.Status = r.Status
	m.Flags = r.Flags
	m.Expires = nanosToTime(r.Expires)
	m.Seq = seq
	return m, nil
}

// validateSettingName reports whether name is 1 to MaxSettingNameLen bytes of
// lowercase ASCII letters, digits, '.', '_' or '-'.
func validateSettingName(name string) error {
	if len(name) == 0 || len(name) > MaxSettingNameLen {
		return fmt.Errorf("%w: setting name must be 1 to %d bytes", ErrInvalid, MaxSettingNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'
		if !ok {
			return fmt.Errorf("%w: setting name has invalid character %q", ErrInvalid, c)
		}
	}
	return nil
}
