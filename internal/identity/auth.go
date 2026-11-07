package identity

import (
	"errors"
	"fmt"

	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/transport"
)

// NonceSize is the length of a relay authentication challenge nonce.
const NonceSize = protocol.NonceSize

// ErrInvalidAuth reports an authentication proof that does not verify for
// the given bundle, server and nonce.
var ErrInvalidAuth = errors.New("identity: invalid authentication proof")

// authInput is the structure an authentication proof signs.
type authInput struct {
	Server []byte `cbor:"1,keyasint"`
	Nonce  []byte `cbor:"2,keyasint"`
	ID     []byte `cbor:"3,keyasint"`
}

// authMessage returns the canonical CBOR encoding of
// {1: server SPKI fingerprint, 2: nonce, 3: ID}, the message signed under
// [ContextAuth].
func authMessage(serverFP transport.Fingerprint, nonce []byte, id ID) ([]byte, error) {
	if serverFP == (transport.Fingerprint{}) {
		return nil, fmt.Errorf("%w: zero server fingerprint", ErrInvalidArgument)
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("%w: nonce must be %d bytes", ErrInvalidArgument, NonceSize)
	}
	return encMode.Marshal(authInput{Server: serverFP[:], Nonce: nonce, ID: id[:]})
}

// SignAuth answers a relay authentication challenge: a hybrid signature
// under [ContextAuth] over CBOR{1: serverFP, 2: nonce, 3: own ID}.
//
// serverFP must be the SPKI fingerprint of the relay certificate this
// client verified on the current TLS connection (the pinned fingerprint),
// never a value received from the relay. Binding it means a malicious relay
// cannot forward a challenge from another relay and replay the proof there:
// the other relay has a different certificate and so a different
// fingerprint. The nonce, chosen fresh by the relay, prevents replay
// against the same relay, and the ID binds the proof to the identity
// authenticating. nonce must be [NonceSize] bytes and serverFP must not be
// zero; otherwise SignAuth returns [ErrInvalidArgument].
func (i *Identity) SignAuth(serverFP transport.Fingerprint, nonce []byte) ([]byte, error) {
	msg, err := authMessage(serverFP, nonce, i.id)
	if err != nil {
		return nil, err
	}
	return i.sign(ContextAuth, msg)
}

// VerifyAuth checks an authentication proof made by [Identity.SignAuth] for
// the identity of bundle b, the relay's own SPKI fingerprint serverFP and
// the nonce the relay issued on this connection. It returns nil only if the
// proof verifies; otherwise [ErrInvalidAuth], or [ErrInvalidArgument] for a
// nonce of the wrong size, a zero fingerprint or a nil bundle.
//
// b must come from [ParseBundle] (the relay stores only verified bundles).
// The ID inside the signed message is recomputed from b's signing key
// rather than taken from b.ID, so a hand-assembled Bundle whose ID field
// disagrees with its key cannot authenticate as somebody else.
func VerifyAuth(b *Bundle, serverFP transport.Fingerprint, nonce, sig []byte) error {
	if b == nil || b.SigningKey == nil {
		return fmt.Errorf("%w: nil bundle", ErrInvalidArgument)
	}
	id := IDFromSigningKey(b.SigningKey)
	if id != b.ID {
		return ErrInvalidAuth
	}
	msg, err := authMessage(serverFP, nonce, id)
	if err != nil {
		return err
	}
	if err := b.SigningKey.Verify(ContextAuth, msg, sig); err != nil {
		return ErrInvalidAuth
	}
	return nil
}
