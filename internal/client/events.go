package client

import (
	"time"

	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/transport"
)

// State is the connection state of a Session.
type State uint8

// Connection states.
const (
	// Connecting means a connection attempt (TCP, TLS and the qchat
	// handshake) is in progress.
	Connecting State = iota + 1
	// Connected means the handshake completed and keepalives are running.
	// For a session with an Authenticator it also means the connection is
	// authenticated.
	Connected
	// Disconnected means the last connection ended or an attempt failed. The
	// session will retry after a backoff delay.
	Disconnected
	// Failed means the session stopped for good and will not retry, for
	// example because the server presented the wrong public key. Run has
	// returned or is about to.
	Failed
	// Authenticating means the qchat handshake completed and the session is
	// registering and authenticating its identity. Only sessions with an
	// Authenticator enter it, between Connecting and Connected.
	Authenticating
)

// String returns a lowercase name for the state.
func (s State) String() string {
	switch s {
	case Connecting:
		return "connecting"
	case Connected:
		return "connected"
	case Disconnected:
		return "disconnected"
	case Failed:
		return "failed"
	case Authenticating:
		return "authenticating"
	default:
		return "unknown"
	}
}

// Event is something that happened to a Session. The concrete types are
// StateChanged, RTT, ServerError, SecurityAlert, Authenticated, Delivery and
// RegistrationDenied.
type Event interface {
	isEvent()
}

// StateChanged reports a transition of the connection state.
type StateChanged struct {
	// State is the new state.
	State State
	// Err explains a Disconnected or Failed state. It is nil otherwise, and
	// may be nil for a Disconnected state caused by an orderly shutdown.
	Err error
	// Attempt counts connection attempts since the last successful
	// connection, starting at 1. It is set for Connecting.
	Attempt int
	// RetryIn is the delay before the next attempt. It is set for
	// Disconnected.
	RetryIn time.Duration
	// Info describes the negotiated connection. It is set for Connected.
	Info ConnectionInfo
}

// RTT reports one keepalive round-trip time measurement. RTT events are
// dropped rather than queued when the consumer falls behind.
type RTT struct {
	time.Duration
}

// ServerError reports an Error frame received from the server. The session
// treats the connection as closed after it.
type ServerError struct {
	// Code classifies the error.
	Code protocol.ErrorCode
	// Message is the server's explanation, reduced to printable ASCII.
	Message string
}

// SecurityAlert reports that the server presented a public key other than
// the pinned one. This is what a machine-in-the-middle attack looks like, so
// the session stops and never retries on its own. It is always followed by a
// StateChanged event with State Failed.
type SecurityAlert struct {
	// Expected is the pinned fingerprint.
	Expected transport.Fingerprint
	// Presented is the fingerprint of the key the server actually used.
	Presented transport.Fingerprint
}

// Authenticated reports that the connection is authenticated as ID. It is
// followed by a StateChanged event with State Connected.
type Authenticated struct {
	// ID is the authenticated identity.
	ID [32]byte
}

// Delivery is a payload the relay routed to the local identity. Delivery
// events are never dropped.
type Delivery struct {
	// From is the sender's identity as authenticated by the relay.
	From [32]byte
	// Payload is the end-to-end encrypted ciphertext. It is a copy owned by
	// the receiver.
	Payload []byte
}

// RegistrationDenied reports that the relay refused to register the local
// bundle, for example because an invite code is missing or invalid or the
// ID is registered with a different bundle. It is permanent: the event is
// followed by a StateChanged event with State Failed.
type RegistrationDenied struct {
	// Code is the relay's error code, usually ErrCodeRegistrationDenied or
	// ErrCodeConflict.
	Code protocol.ErrorCode
	// Message is the relay's explanation, reduced to printable ASCII.
	Message string
}

func (StateChanged) isEvent()       {}
func (RTT) isEvent()                {}
func (ServerError) isEvent()        {}
func (SecurityAlert) isEvent()      {}
func (Authenticated) isEvent()      {}
func (Delivery) isEvent()           {}
func (RegistrationDenied) isEvent() {}

// TransportDescription names the transport security every qchat connection
// uses. Connections that cannot meet it are refused by package transport.
const TransportDescription = "TLS 1.3 · X25519MLKEM768"

// ConnectionInfo describes an established connection.
type ConnectionInfo struct {
	// Addr is the server address, "host:port".
	Addr string
	// Fingerprint is the pinned server key fingerprint the connection was
	// verified against.
	Fingerprint transport.Fingerprint
	// ProtocolVersion is the negotiated qchat wire version.
	ProtocolVersion uint8
	// PingInterval is the keepalive interval announced by the server.
	PingInterval time.Duration
	// MaxFrameSize is the largest frame, in bytes, the server accepts.
	MaxFrameSize uint32
	// Transport describes the transport security; see TransportDescription.
	Transport string
	// ConnectedAt is when the handshake completed.
	ConnectedAt time.Time
}
