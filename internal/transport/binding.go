package transport

import (
	"crypto/tls"
	"errors"
)

// AuthBindingLabel is the TLS exporter label (RFC 8446, section 7.5) of the
// channel binding carried by a relay authentication proof.
const AuthBindingLabel = "EXPORTER-qchat-auth-v1"

// AuthBindingSize is the length in bytes of the value returned by
// [AuthBinding].
const AuthBindingSize = 32

// errNoBinding reports a connection state from which no channel binding can
// be exported.
var errNoBinding = errors.New("transport: TLS connection state has no usable exporter")

// AuthBinding returns the channel binding of the TLS connection described by
// state: AuthBindingSize bytes exported under [AuthBindingLabel] with an
// empty context, in the style of tls-exporter (RFC 9266).
//
// Client and server derive the same value only if they share one TLS
// connection. A proof signed over it therefore cannot be relayed by a party
// that terminates the client's TLS connection and opens its own to the
// relay, even if that party holds the relay's certificate key: its two
// connections have different exporter secrets.
//
// state must describe a completed TLS 1.3 handshake; otherwise AuthBinding
// returns an error. The value is a per-connection secret and must not be
// logged.
func AuthBinding(state *tls.ConnectionState) ([]byte, error) {
	if state == nil || !state.HandshakeComplete || state.Version != tls.VersionTLS13 {
		return nil, errNoBinding
	}
	binding, err := state.ExportKeyingMaterial(AuthBindingLabel, nil, AuthBindingSize)
	if err != nil {
		return nil, errNoBinding
	}
	return binding, nil
}
