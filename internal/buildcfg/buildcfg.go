// Package buildcfg holds settings that are fixed when the client binary is
// built, rather than chosen by the person running it.
//
// A distributor can lock a client build to one server:
//
//	go build -ldflags "\
//	  -X github.com/Aepzie/qchat/internal/buildcfg.ServerAddr=chat.example.org:443 \
//	  -X github.com/Aepzie/qchat/internal/buildcfg.ServerPin=sha256:<64 hex digits>" \
//	  ./cmd/client
//
// When both values are embedded, the client must connect to that server,
// authenticated by that pin, and must refuse to connect anywhere else, even
// if the user asks for a different server or pin on the command line. This
// is what lets a pre-configured installer be handed to non-technical users:
// nobody can talk them into pointing it at an impostor server by changing a
// flag. Builds without embedded values require the user to supply both.
package buildcfg

import (
	"errors"
	"fmt"

	"github.com/Aepzie/qchat/internal/transport"
)

// ServerAddr is the embedded server address in "host:port" form, as accepted
// by transport.ValidateHostPort. It is empty unless set at build time with
// -ldflags -X.
var ServerAddr string

// ServerPin is the embedded server public key fingerprint, in any form
// accepted by transport.ParseFingerprint (normally "sha256:<hex>"). It is
// empty unless set at build time with -ldflags -X.
var ServerPin string

// Embedded reports the server this build is locked to.
//
// ok is true only when both ServerAddr and ServerPin are set and valid; addr
// is then in the canonical form returned by transport.ValidateHostPort. If
// neither is set, Embedded returns ok == false and a nil error: the build is
// not locked. If only one is set, or a value is malformed, Embedded returns an
// error; such a build is broken and must not fall back to user-supplied
// values, because that would silently drop the lock.
func Embedded() (addr string, pin transport.Fingerprint, ok bool, err error) {
	return parse(ServerAddr, ServerPin)
}

// parse validates an embedded address and pin pair.
func parse(rawAddr, rawPin string) (string, transport.Fingerprint, bool, error) {
	if rawAddr == "" && rawPin == "" {
		return "", transport.Fingerprint{}, false, nil
	}
	if rawAddr == "" || rawPin == "" {
		return "", transport.Fingerprint{}, false, errors.New("buildcfg: embedded server configuration is incomplete: both ServerAddr and ServerPin must be set")
	}
	addr, err := transport.ValidateHostPort(rawAddr)
	if err != nil {
		return "", transport.Fingerprint{}, false, fmt.Errorf("buildcfg: embedded server address: %w", err)
	}
	pin, err := transport.ParseFingerprint(rawPin)
	if err != nil {
		return "", transport.Fingerprint{}, false, fmt.Errorf("buildcfg: embedded server pin: %w", err)
	}
	return addr, pin, true, nil
}
