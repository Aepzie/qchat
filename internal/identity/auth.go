package identity

import (
	"errors"
	"fmt"

	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/transport"
)

// NonceSize is the length of a relay authentication challenge nonce.
const NonceSize = protocol.NonceSize

// BindingSize is the length of the TLS channel binding an authentication
// proof signs; see [transport.AuthBinding].
const BindingSize = transport.AuthBindingSize

// ErrInvalidAuth reports an authentication proof that does not verify for
// the given bundle, server, nonce and channel binding.
var ErrInvalidAuth = errors.New("identity: invalid authentication proof")

// authInput is the structure an authentication proof signs.
type authInput struct {
	Server  []byte `cbor:"1,keyasint"`
	Nonce   []byte `cbor:"2,keyasint"`
	ID      []byte `cbor:"3,keyasint"`
	Binding []byte `cbor:"4,keyasint"`
}

// authMessage returns the canonical CBOR encoding of
// {1: server SPKI fingerprint, 2: nonce, 3: ID, 4: TLS channel binding},
// the message signed under [ContextAuth].
func authMessage(serverFP transport.Fingerprint, nonce, binding []byte, id ID) ([]byte, error) {
	if serverFP == (transport.Fingerprint{}) {
		return nil, fmt.Errorf("%w: zero server fingerprint", ErrInvalidArgument)
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("%w: nonce must be %d bytes", ErrInvalidArgument, NonceSize)
	}
	if len(binding) != BindingSize {
		return nil, fmt.Errorf("%w: channel binding must be %d bytes", ErrInvalidArgument, BindingSize)
	}
	return encMode.Marshal(authInput{Server: serverFP[:], Nonce: nonce, ID: id[:], Binding: binding})
}

// SignAuth answers a relay authentication challenge: a hybrid signature
// under [ContextAuth] over CBOR{1: serverFP, 2: nonce, 3: own ID,
// 4: binding}.
//
// serverFP must be the SPKI fingerprint of the relay certificate this
// client verified on the current TLS connection (the pinned fingerprint),
// never a value received from the relay. Binding it means a malicious relay
// cannot forward a challenge from another relay and replay the proof there:
// the other relay has a different certificate and so a different
// fingerprint. The nonce, chosen fresh by the relay, prevents replay
// against the same relay, and the ID binds the proof to the identity
// authenticating.
//
// binding must be the value [transport.AuthBinding] derives from the TLS
// connection the proof is sent on. It ties the proof to that one
// connection: a party that terminates the client's TLS session, for
// example with a stolen or broken relay certificate key, and forwards the
// real relay's challenge over a connection of its own cannot use the proof,
// because the relay derives a different binding for that connection.
//
// nonce must be [NonceSize] bytes, binding [BindingSize] bytes and serverFP
// must not be zero; otherwise SignAuth returns [ErrInvalidArgument].
func (i *Identity) SignAuth(serverFP transport.Fingerprint, nonce, binding []byte) ([]byte, error) {
	msg, err := authMessage(serverFP, nonce, binding, i.id)
	if err != nil {
		return nil, err
	}
	return i.sign(ContextAuth, msg)
}

// VerifyAuth checks an authentication proof made by [Identity.SignAuth] for
// the identity of bundle b, the relay's own SPKI fingerprint serverFP, the
// nonce the relay issued on this connection and binding, the relay's own
// [transport.AuthBinding] of this connection. It returns nil only if the
// proof verifies; otherwise [ErrInvalidAuth], or [ErrInvalidArgument] for a
// nonce or binding of the wrong size, a zero fingerprint or a nil bundle.
//
// b must come from [ParseBundle] (the relay stores only verified bundles).
// The ID inside the signed message is recomputed from b's signing key
// rather than taken from b.ID, so a hand-assembled Bundle whose ID field
// disagrees with its key cannot authenticate as somebody else.
func VerifyAuth(b *Bundle, serverFP transport.Fingerprint, nonce, binding, sig []byte) error {
	if b == nil || b.SigningKey == nil {
		return fmt.Errorf("%w: nil bundle", ErrInvalidArgument)
	}
	id := IDFromSigningKey(b.SigningKey)
	if id != b.ID {
		return ErrInvalidAuth
	}
	msg, err := authMessage(serverFP, nonce, binding, id)
	if err != nil {
		return err
	}
	if err := b.SigningKey.Verify(ContextAuth, msg, sig); err != nil {
		return ErrInvalidAuth
	}
	return nil
}
