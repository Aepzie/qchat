package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
)

// Version is the current wire version. Every frame carries it.
const Version uint8 = 1

// MaxFrameSize is the hard upper bound, in bytes, for an encoded frame.
// Larger inputs are rejected before any parsing takes place.
const MaxFrameSize = 1 << 20

// supportedVersions lists, in ascending order, every wire version this
// implementation speaks.
var supportedVersions = [...]uint8{Version}

// isSupportedVersion reports whether v is a wire version this implementation
// speaks.
func isSupportedVersion(v uint64) bool {
	for _, s := range supportedVersions {
		if uint64(s) == v {
			return true
		}
	}
	return false
}

// FrameType identifies the kind of a frame and therefore the type of its body.
type FrameType uint8

// Frame types defined by wire version 1.
const (
	// TypeHello is sent by the client as its first frame; body [Hello].
	TypeHello FrameType = 1
	// TypeWelcome is the server's reply to Hello; body [Welcome].
	TypeWelcome FrameType = 2
	// TypePing is a keepalive probe, sent by either side; body [Ping].
	TypePing FrameType = 3
	// TypePong answers a Ping, echoing its nonce; body [Pong].
	TypePong FrameType = 4
	// TypeError reports a failure to the peer; body [ErrorBody].
	TypeError FrameType = 5
)

// String returns the name of the frame type, or "FrameType(n)" for values
// that are not defined.
func (t FrameType) String() string {
	switch t {
	case TypeHello:
		return "Hello"
	case TypeWelcome:
		return "Welcome"
	case TypePing:
		return "Ping"
	case TypePong:
		return "Pong"
	case TypeError:
		return "Error"
	default:
		return fmt.Sprintf("FrameType(%d)", uint8(t))
	}
}

// Valid reports whether t is a frame type defined by this version of the
// protocol.
func (t FrameType) Valid() bool {
	return t >= TypeHello && t <= TypeError
}

// Frame is the unit of transmission: each WebSocket binary message carries
// exactly one encoded Frame.
//
// An empty Body is encoded by omitting key 4, so a decoded frame always has
// either a nil or a non-empty Body.
type Frame struct {
	// Version is the wire version the frame was produced under.
	Version uint8 `cbor:"1,keyasint"`
	// Type identifies the frame and the type of its body.
	Type FrameType `cbor:"2,keyasint"`
	// ID correlates a request with its response; 0 means no correlation.
	ID uint64 `cbor:"3,keyasint,omitempty"`
	// Body is the CBOR encoding of the type-specific body. To the relay it is
	// an opaque byte string.
	Body []byte `cbor:"4,keyasint,omitempty"`
}

// Sentinel errors. Errors returned by this package wrap exactly one of them,
// so callers can classify failures with [errors.Is].
var (
	// ErrFrameTooLarge reports a frame or body exceeding MaxFrameSize.
	ErrFrameTooLarge = errors.New("protocol: frame too large")
	// ErrUnsupportedVersion reports a wire version this implementation does
	// not speak, or a failed version negotiation.
	ErrUnsupportedVersion = errors.New("protocol: unsupported version")
	// ErrUnknownType reports a frame type that is not defined.
	ErrUnknownType = errors.New("protocol: unknown frame type")
	// ErrUnexpectedType reports a frame whose type differs from the one the
	// caller expected, or a body that does not belong to the frame type.
	ErrUnexpectedType = errors.New("protocol: unexpected frame type")
	// ErrMalformed reports input that is not a valid, canonical encoding, or a
	// body whose field values are out of range.
	ErrMalformed = errors.New("protocol: malformed input")
)

// versionPeek reads only the version key of a frame. The version is decoded
// as uint64 so that any unsigned integer, however large, is reported as an
// unsupported version rather than as malformed input.
type versionPeek struct {
	Version uint64 `cbor:"1,keyasint"`
}

// Encode validates f and returns its canonical encoding. It fails with
// ErrUnsupportedVersion, ErrUnknownType or ErrFrameTooLarge if f could not be
// accepted by a conforming receiver.
func Encode(f Frame) ([]byte, error) {
	if !isSupportedVersion(uint64(f.Version)) {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, f.Version)
	}
	if !f.Type.Valid() {
		return nil, fmt.Errorf("%w: %v", ErrUnknownType, f.Type)
	}
	if len(f.Body) > MaxFrameSize {
		return nil, fmt.Errorf("%w: body is %d bytes", ErrFrameTooLarge, len(f.Body))
	}
	b, err := encMode.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(b) > MaxFrameSize {
		return nil, fmt.Errorf("%w: frame is %d bytes", ErrFrameTooLarge, len(b))
	}
	return b, nil
}

// Decode parses exactly one frame from b.
//
// The size limit is enforced before parsing. The version is checked first so
// that frames from other protocol versions fail with ErrUnsupportedVersion.
// The frame is then decoded strictly: unknown fields, duplicate keys,
// indefinite-length items, tags, trailing bytes and non-canonical encodings
// are rejected with ErrMalformed, and undefined frame types with
// ErrUnknownType. The body is not inspected; use [DecodeBody] for that.
func Decode(b []byte) (Frame, error) {
	if len(b) > MaxFrameSize {
		return Frame{}, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(b))
	}
	if len(b) == 0 {
		return Frame{}, fmt.Errorf("%w: empty input", ErrMalformed)
	}

	var peek versionPeek
	if err := peekMode.Unmarshal(b, &peek); err != nil {
		return Frame{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if !isSupportedVersion(peek.Version) {
		return Frame{}, fmt.Errorf("%w: %d", ErrUnsupportedVersion, peek.Version)
	}

	var f Frame
	if err := decMode.Unmarshal(b, &f); err != nil {
		return Frame{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if !f.Type.Valid() {
		return Frame{}, fmt.Errorf("%w: %v", ErrUnknownType, f.Type)
	}
	if err := requireCanonical(b, f); err != nil {
		return Frame{}, err
	}
	return f, nil
}

// NewFrame builds a frame of type t at the current wire version, with the
// canonical encoding of body as its body. Bodies defined by this package are
// validated, and must match t: passing a [Ping] to build a TypePong frame
// fails with ErrUnexpectedType.
func NewFrame[T any](t FrameType, id uint64, body T) (Frame, error) {
	if !t.Valid() {
		return Frame{}, fmt.Errorf("%w: %v", ErrUnknownType, t)
	}
	if err := checkBody(any(body), t); err != nil {
		return Frame{}, err
	}
	raw, err := encMode.Marshal(body)
	if err != nil {
		return Frame{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(raw) > MaxFrameSize {
		return Frame{}, fmt.Errorf("%w: body is %d bytes", ErrFrameTooLarge, len(raw))
	}
	return Frame{Version: Version, Type: t, ID: id, Body: raw}, nil
}

// DecodeBody checks that f has type want and strictly decodes its body into a
// T. Like [Decode], it accepts only the canonical encoding and rejects unknown
// fields; in addition every field of the body must be present, and bodies
// defined by this package are validated (for example the length and character
// set of [ErrorBody.Message]).
func DecodeBody[T any](f Frame, want FrameType) (T, error) {
	var zero T
	if !isSupportedVersion(uint64(f.Version)) {
		return zero, fmt.Errorf("%w: %d", ErrUnsupportedVersion, f.Version)
	}
	if !want.Valid() {
		return zero, fmt.Errorf("%w: %v", ErrUnknownType, want)
	}
	if f.Type != want {
		return zero, fmt.Errorf("%w: got %v, want %v", ErrUnexpectedType, f.Type, want)
	}
	if len(f.Body) > MaxFrameSize {
		return zero, fmt.Errorf("%w: body is %d bytes", ErrFrameTooLarge, len(f.Body))
	}
	if len(f.Body) == 0 {
		return zero, fmt.Errorf("%w: %v frame has no body", ErrMalformed, f.Type)
	}

	var v T
	if err := decMode.Unmarshal(f.Body, &v); err != nil {
		return zero, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if err := requireCanonical(f.Body, v); err != nil {
		return zero, err
	}
	if err := checkBody(any(v), want); err != nil {
		return zero, err
	}
	return v, nil
}

// requireCanonical reports ErrMalformed unless b is exactly the canonical
// encoding of v. Because omitted body fields would reappear on re-encoding,
// this also guarantees that every non-omitempty field was present in b.
func requireCanonical(b []byte, v any) error {
	canon, err := encMode.Marshal(v)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if !bytes.Equal(canon, b) {
		return fmt.Errorf("%w: non-canonical encoding", ErrMalformed)
	}
	return nil
}

// typedBody is implemented by every body defined in this package.
type typedBody interface {
	frameType() FrameType
	validate() error
}

// checkBody verifies that a body defined by this package belongs to frame
// type t and holds in-range values. Values of other types are accepted
// unchanged, so callers may carry their own body types.
func checkBody(v any, t FrameType) error {
	if isNilPointer(v) {
		return fmt.Errorf("%w: nil body", ErrMalformed)
	}
	body, ok := v.(typedBody)
	if !ok {
		return nil
	}
	if body.frameType() != t {
		return fmt.Errorf("%w: %T is not a %v body", ErrUnexpectedType, v, t)
	}
	return body.validate()
}

// isNilPointer reports whether v is a nil pointer of any type.
func isNilPointer(v any) bool {
	if v == nil {
		return false
	}
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}
