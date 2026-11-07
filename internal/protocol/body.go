package protocol

import (
	"errors"
	"fmt"
)

// MaxErrorMessageLen is the maximum length, in bytes, of [ErrorBody.Message].
const MaxErrorMessageLen = 256

// MaxPingInterval is the largest keepalive interval, in seconds, that a
// [Welcome] may announce.
const MaxPingInterval = 3600

// Hello is the body of the client's first frame. It announces the range of
// wire versions the client speaks. It deliberately carries no client software
// name or version, to minimise the metadata the relay learns.
type Hello struct {
	// MinVersion is the lowest wire version the client speaks.
	MinVersion uint8 `cbor:"1,keyasint"`
	// MaxVersion is the highest wire version the client speaks.
	MaxVersion uint8 `cbor:"2,keyasint"`
}

// ClientHello returns the Hello announcing every version this implementation
// speaks.
func ClientHello() Hello {
	return Hello{
		MinVersion: supportedVersions[0],
		MaxVersion: supportedVersions[len(supportedVersions)-1],
	}
}

func (Hello) frameType() FrameType { return TypeHello }

func (h Hello) validate() error {
	if h.MinVersion == 0 || h.MinVersion > h.MaxVersion {
		return fmt.Errorf("%w: invalid version range [%d, %d]", ErrMalformed, h.MinVersion, h.MaxVersion)
	}
	return nil
}

// Welcome is the server's reply to [Hello]. It fixes the parameters of the
// session.
type Welcome struct {
	// Version is the negotiated wire version used for the rest of the session.
	Version uint8 `cbor:"1,keyasint"`
	// MaxFrameSize is the largest encoded frame, in bytes, the server accepts.
	// It never exceeds the package constant MaxFrameSize.
	MaxFrameSize uint32 `cbor:"2,keyasint"`
	// PingInterval is the keepalive interval in seconds, between 1 and
	// MaxPingInterval.
	PingInterval uint32 `cbor:"3,keyasint"`
}

func (Welcome) frameType() FrameType { return TypeWelcome }

func (w Welcome) validate() error {
	if !isSupportedVersion(uint64(w.Version)) {
		return fmt.Errorf("%w: welcome selects version %d", ErrUnsupportedVersion, w.Version)
	}
	if w.MaxFrameSize == 0 || w.MaxFrameSize > MaxFrameSize {
		return fmt.Errorf("%w: max frame size %d out of range", ErrMalformed, w.MaxFrameSize)
	}
	if w.PingInterval == 0 || w.PingInterval > MaxPingInterval {
		return fmt.Errorf("%w: ping interval %d out of range", ErrMalformed, w.PingInterval)
	}
	return nil
}

// Ping is a keepalive probe. The receiver answers with a [Pong] carrying the
// same nonce.
type Ping struct {
	// Nonce is chosen by the sender and echoed in the Pong.
	Nonce uint64 `cbor:"1,keyasint"`
}

func (Ping) frameType() FrameType { return TypePing }

func (Ping) validate() error { return nil }

// Pong answers a [Ping].
type Pong struct {
	// Nonce echoes the nonce of the Ping being answered.
	Nonce uint64 `cbor:"1,keyasint"`
}

func (Pong) frameType() FrameType { return TypePong }

func (Pong) validate() error { return nil }

// ErrorCode classifies an error reported in an [ErrorBody].
type ErrorCode uint16

// Error codes defined by wire version 1.
const (
	// ErrCodeBadRequest means the peer sent a malformed or unexpected frame.
	ErrCodeBadRequest ErrorCode = 1
	// ErrCodeUnsupportedVersion means no mutually supported wire version exists.
	ErrCodeUnsupportedVersion ErrorCode = 2
	// ErrCodeRateLimited means the peer is sending too much, too fast.
	ErrCodeRateLimited ErrorCode = 3
	// ErrCodeTooLarge means a frame exceeded the negotiated size limit.
	ErrCodeTooLarge ErrorCode = 4
	// ErrCodeInternal means the sender failed for reasons unrelated to the peer.
	ErrCodeInternal ErrorCode = 5
)

// String returns the name of the error code, or "ErrorCode(n)" for values
// that are not defined.
func (c ErrorCode) String() string {
	switch c {
	case ErrCodeBadRequest:
		return "BadRequest"
	case ErrCodeUnsupportedVersion:
		return "UnsupportedVersion"
	case ErrCodeRateLimited:
		return "RateLimited"
	case ErrCodeTooLarge:
		return "TooLarge"
	case ErrCodeInternal:
		return "Internal"
	default:
		return fmt.Sprintf("ErrorCode(%d)", uint16(c))
	}
}

// Valid reports whether c is an error code defined by this version of the
// protocol.
func (c ErrorCode) Valid() bool {
	return c >= ErrCodeBadRequest && c <= ErrCodeInternal
}

// ErrorCodeFor maps an error returned by this package to the code a peer
// should be told about. Errors not produced by this package map to
// ErrCodeInternal.
func ErrorCodeFor(err error) ErrorCode {
	switch {
	case errors.Is(err, ErrFrameTooLarge):
		return ErrCodeTooLarge
	case errors.Is(err, ErrUnsupportedVersion):
		return ErrCodeUnsupportedVersion
	case errors.Is(err, ErrMalformed), errors.Is(err, ErrUnknownType), errors.Is(err, ErrUnexpectedType):
		return ErrCodeBadRequest
	default:
		return ErrCodeInternal
	}
}

// ErrorBody reports a failure to the peer.
type ErrorBody struct {
	// Code classifies the failure; it must be a defined ErrorCode.
	Code ErrorCode `cbor:"1,keyasint"`
	// Message is a short human-readable explanation: printable ASCII only, at
	// most MaxErrorMessageLen bytes, possibly empty. It must never contain
	// secrets or user content.
	Message string `cbor:"2,keyasint"`
}

func (ErrorBody) frameType() FrameType { return TypeError }

func (e ErrorBody) validate() error {
	if !e.Code.Valid() {
		return fmt.Errorf("%w: undefined error code %d", ErrMalformed, uint16(e.Code))
	}
	if len(e.Message) > MaxErrorMessageLen {
		return fmt.Errorf("%w: error message is %d bytes", ErrMalformed, len(e.Message))
	}
	for i := 0; i < len(e.Message); i++ {
		if c := e.Message[i]; c < 0x20 || c > 0x7e {
			return fmt.Errorf("%w: error message contains byte 0x%02x", ErrMalformed, c)
		}
	}
	return nil
}
