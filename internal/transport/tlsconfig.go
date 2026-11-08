package transport

import (
	"crypto/tls"
	"errors"
	"fmt"
)

// ErrPinMismatch is returned (wrapped) when the server's public key does not
// match the pinned fingerprint. This is what a machine-in-the-middle attack,
// or a server whose key was rotated, looks like to the client.
var ErrPinMismatch = errors.New("transport: server public key does not match pinned fingerprint")

// ErrWeakHandshake is returned (wrapped) when a TLS connection did not use
// TLS 1.3 with the X25519MLKEM768 hybrid post-quantum key exchange.
var ErrWeakHandshake = errors.New("transport: handshake is not TLS 1.3 with X25519MLKEM768 key exchange")

// errNoPin is returned when a client is asked to connect without a pin.
var errNoPin = errors.New("transport: no server fingerprint pinned; refusing to connect")

// PinMismatchError carries the fingerprint the server actually presented, so
// a user interface can show it next to the expected value. Fingerprints are
// public information, so including it does not leak secrets.
// errors.Is(err, ErrPinMismatch) reports true for this error.
type PinMismatchError struct {
	Expected  Fingerprint
	Presented Fingerprint
}

func (e *PinMismatchError) Error() string {
	return fmt.Sprintf("%v (expected %s, server presented %s)", ErrPinMismatch, e.Expected, e.Presented)
}

// Unwrap makes errors.Is(err, ErrPinMismatch) work.
func (e *PinMismatchError) Unwrap() error { return ErrPinMismatch }

// keyExchangeGroups is the only key exchange qchat ever negotiates.
//
// X25519MLKEM768 combines X25519 with ML-KEM-768 (FIPS 203). The session keys
// stay secret as long as either component is unbroken, so recorded traffic
// remains protected even against a future quantum computer that breaks
// X25519 ("harvest now, decrypt later").
//
// Listing it alone, on both sides, means a peer that does not support it gets
// a handshake failure instead of a silent downgrade to classical X25519.
// Because the list is set explicitly, the GODEBUG settings tlsmlkem=0 and
// tlssecpmlkem=0 (which only change Go's default list) cannot remove it.
var keyExchangeGroups = []tls.CurveID{tls.X25519MLKEM768}

// alpnProtocols advertises HTTP/1.1 only. The WebSocket upgrade handshake
// (RFC 6455) is defined over HTTP/1.1, so HTTP/2 is disabled on both sides.
// Note that net/http omits ALPN entirely for requests carrying an Upgrade
// header, so a qchat client usually sends no ALPN extension; the server then
// speaks HTTP/1.1, which is the desired outcome either way.
var alpnProtocols = []string{"http/1.1"}

// baseTLSConfig holds the settings shared by client and server.
func baseTLSConfig() *tls.Config {
	return &tls.Config{
		// TLS 1.3 only: it has no renegotiation, no static-RSA or CBC cipher
		// suites, always provides forward secrecy, and encrypts the
		// certificate so passive observers cannot see which key is in use.
		// All TLS 1.3 cipher suites offered by Go are AEADs; Go does not
		// allow configuring them, which is fine because none are weak.
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: append([]tls.CurveID(nil), keyExchangeGroups...),
		NextProtos:       append([]string(nil), alpnProtocols...),
	}
}

// checkHandshakeStrength rejects any connection that is not TLS 1.3 with the
// hybrid post-quantum key exchange. The configuration already makes anything
// else impossible; this check is defence in depth against future library
// behaviour changes or configuration mistakes.
func checkHandshakeStrength(cs tls.ConnectionState) error {
	if cs.Version != tls.VersionTLS13 {
		return fmt.Errorf("%w: negotiated version 0x%04x", ErrWeakHandshake, cs.Version)
	}
	if cs.CurveID != tls.X25519MLKEM768 {
		return fmt.Errorf("%w: negotiated key exchange %v", ErrWeakHandshake, cs.CurveID)
	}
	return nil
}

// ServerTLSConfig returns the server-side TLS configuration for cert.
//
// The server does not request client certificates: clients are authenticated
// by the end-to-end protocol above this layer, and a client certificate would
// be a stable identifier visible to the server operator.
//
// Session tickets are disabled. Every connection performs a full handshake
// with a fresh hybrid key exchange, and the server holds no long-lived ticket
// encryption keys whose theft could help an attacker.
func ServerTLSConfig(cert tls.Certificate) *tls.Config {
	cfg := baseTLSConfig()
	cfg.Certificates = []tls.Certificate{cert}
	cfg.ClientAuth = tls.NoClientCert
	cfg.SessionTicketsDisabled = true
	cfg.VerifyConnection = checkHandshakeStrength
	return cfg
}

// ClientTLSConfig returns a client TLS configuration that trusts exactly one
// server public key: the one whose SPKI SHA-256 equals pin.
//
// How the server is authenticated:
//
//   - InsecureSkipVerify disables Go's default WebPKI checks (CA chain,
//     hostname, validity dates). They are replaced, not skipped: the custom
//     VerifyConnection callback below is the only trust decision, and it
//     fails closed.
//   - The pin covers the leaf certificate's public key. The CA chain, the
//     subject and SAN names, the validity period and the certificate's own
//     self-signature are all irrelevant and ignored: anyone can forge a
//     certificate around a public key, but nobody can complete the handshake
//     without the private key.
//   - Proof of possession comes from TLS 1.3 itself. The server signs the
//     handshake transcript (CertificateVerify message) with its private key,
//     and Go verifies that signature against the leaf's public key regardless
//     of InsecureSkipVerify. Combined with the pin check, a successful
//     handshake proves the peer holds the private key for the pinned SPKI.
//
// A zero pin never connects: the returned configuration rejects every
// server. Use Dial, which additionally reports a zero pin up front.
//
// No session cache is set, so the client never resumes sessions and always
// performs a full, freshly keyed handshake.
func ClientTLSConfig(pin Fingerprint) *tls.Config {
	cfg := baseTLSConfig()
	cfg.InsecureSkipVerify = true // #nosec G402 -- WebPKI checks are replaced by the SPKI pin in VerifyConnection, which fails closed
	cfg.ClientSessionCache = nil
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		return verifyPinnedConnection(cs, pin)
	}
	return cfg
}

// verifyPinnedConnection is the client's complete trust decision.
func verifyPinnedConnection(cs tls.ConnectionState, pin Fingerprint) error {
	if pin.IsZero() {
		return errNoPin
	}
	if err := checkHandshakeStrength(cs); err != nil {
		return err
	}
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("%w: server sent no certificate", ErrPinMismatch)
	}
	presented := FingerprintOf(cs.PeerCertificates[0])
	if !presented.Equal(pin) {
		return &PinMismatchError{Expected: pin, Presented: presented}
	}
	return nil
}
