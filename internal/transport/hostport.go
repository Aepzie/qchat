package transport

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ErrInvalidAddress is wrapped by every error ValidateHostPort returns, and
// therefore by Dial when it is given a malformed address. Such an error is
// a configuration mistake, not a network failure: retrying cannot fix it.
var ErrInvalidAddress = errors.New("transport: invalid server address")

// ValidateHostPort checks that hostport is a server address Dial accepts and
// returns it in canonical form.
//
// hostport must have the form "host:port" (IPv6 hosts in brackets) with a
// non-empty host and a decimal port between 1 and 65535. The host must
// consist of printable ASCII and must not contain any of / \ ? # @ [ ],
// which would change the meaning of the wss:// URL built from it, for
// example by smuggling in user information or a path. The host is not
// resolved. In the canonical form the port has no leading zeros.
//
// This is the single address check used by the client, by build-time
// configuration and by Dial, so an address accepted at startup is never
// rejected later when connecting.
func ValidateHostPort(hostport string) (string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", invalidAddress(hostport, "want host:port")
	}
	if host == "" {
		return "", invalidAddress(hostport, "empty host")
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`/\?#@[]`, c) >= 0 {
			return "", invalidAddress(hostport, "illegal character in host")
		}
	}
	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNum == 0 {
		return "", invalidAddress(hostport, "port must be 1-65535")
	}
	return net.JoinHostPort(host, strconv.FormatUint(portNum, 10)), nil
}

// invalidAddress builds an ErrInvalidAddress error. The address is quoted
// so that control characters in it cannot garble terminal output or logs.
func invalidAddress(hostport, reason string) error {
	return fmt.Errorf("%w %q: %s", ErrInvalidAddress, hostport, reason)
}
