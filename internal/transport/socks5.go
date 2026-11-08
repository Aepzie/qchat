package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// Timeouts of SOCKS5Dialer used when the caller's context has no earlier
// deadline. Building a Tor circuit to an onion service can take tens of
// seconds, so the handshake limit is generous.
const (
	defaultSOCKS5ConnectTimeout   = 30 * time.Second
	defaultSOCKS5HandshakeTimeout = 120 * time.Second
)

// SOCKS5 protocol constants (RFC 1928 and RFC 1929).
const (
	socks5Version         = 0x05
	socks5AuthNone        = 0x00
	socks5AuthPassword    = 0x02
	socks5AuthNoAccept    = 0xff
	socks5PasswordVersion = 0x01
	socks5CmdConnect      = 0x01
	socks5AddrIPv4        = 0x01
	socks5AddrDomain      = 0x03
	socks5AddrIPv6        = 0x04
	socks5MaxField        = 255
)

// ErrSOCKS5 is wrapped by every error SOCKS5Dialer's dial function returns
// because of the proxy: an unreachable proxy, a refused request or a reply
// that violates the protocol. Errors from the caller's context wrap the
// context error instead.
var ErrSOCKS5 = errors.New("transport: socks5")

// SOCKS5ReplyError is returned when the proxy answers a CONNECT request
// with a failure code. It wraps ErrSOCKS5.
type SOCKS5ReplyError struct {
	// Code is the REP field of the reply, never 0.
	Code byte
}

func (e *SOCKS5ReplyError) Error() string {
	return fmt.Sprintf("transport: socks5: proxy refused the connection: %s (code 0x%02x)", socks5ReplyText(e.Code), e.Code)
}

// Unwrap makes errors.Is(err, ErrSOCKS5) report true.
func (e *SOCKS5ReplyError) Unwrap() error { return ErrSOCKS5 }

// socks5ReplyText describes a SOCKS5 reply code, including the extended
// codes Tor uses for onion services.
func socks5ReplyText(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	case 0xf0:
		return "onion service descriptor not found"
	case 0xf1:
		return "onion service descriptor invalid"
	case 0xf2:
		return "onion service introduction failed"
	case 0xf3:
		return "onion service rendezvous failed"
	case 0xf4:
		return "onion service requires client authorization"
	case 0xf5:
		return "onion service client authorization rejected"
	case 0xf6:
		return "invalid onion address"
	case 0xf7:
		return "onion service introduction timed out"
	default:
		return "unknown error"
	}
}

// SOCKS5Dialer returns a dial function that opens TCP connections through
// the SOCKS5 proxy at proxyAddr ("host:port"), for example Tor's SOCKS port
// 127.0.0.1:9050. It fits DialOptions.NetDialContext and the Dialer field of
// the client's session options.
//
// The destination host name is sent to the proxy as is and never resolved
// locally, so no DNS query reveals whom the client talks to and .onion
// addresses work. Only IP literals are sent as addresses.
//
// If isolation is non-empty, the dial function authenticates with
// username/password authentication (RFC 1929), sending isolation as both
// user name and password, and refuses proxies that do not accept it. Tor
// puts streams with different credentials on different circuits
// (IsolateSOCKSAuth, on by default), so a random isolation token per
// session keeps the session's traffic apart from other applications using
// the same Tor instance. isolation must be at most 255 bytes long; a longer
// token makes every dial fail. If isolation is empty, no authentication is
// offered.
//
// The connection to the proxy is limited to 30 seconds and the SOCKS
// handshake to 120 seconds, or less if ctx expires earlier. Cancelling ctx
// aborts the handshake. There is never a fallback to a direct connection.
func SOCKS5Dialer(proxyAddr string, isolation string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &socks5Dialer{
		proxyAddr:        proxyAddr,
		isolation:        isolation,
		connectTimeout:   defaultSOCKS5ConnectTimeout,
		handshakeTimeout: defaultSOCKS5HandshakeTimeout,
	}
	return d.DialContext
}

// socks5Dialer implements SOCKS5Dialer. Tests shorten its timeouts.
type socks5Dialer struct {
	proxyAddr        string
	isolation        string
	connectTimeout   time.Duration
	handshakeTimeout time.Duration
}

// DialContext connects to addr through the proxy.
func (d *socks5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("%w: unsupported network %q", ErrSOCKS5, network)
	}
	if len(d.isolation) > socks5MaxField {
		return nil, fmt.Errorf("%w: isolation token longer than %d bytes", ErrSOCKS5, socks5MaxField)
	}
	request, err := socks5ConnectRequest(addr)
	if err != nil {
		return nil, err
	}

	dialer := net.Dialer{Timeout: d.connectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("transport: socks5: connect to proxy: %w", ctxErr)
		}
		return nil, fmt.Errorf("%w: connect to proxy: %w", ErrSOCKS5, err)
	}

	if err := conn.SetDeadline(time.Now().Add(d.handshakeTimeout)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %w", ErrSOCKS5, err)
	}
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Unix(1, 0))
	})

	err = d.handshake(conn, request)
	if !stop() || ctx.Err() != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("transport: socks5: handshake: %w", context.Cause(ctx))
	}
	if err != nil {
		_ = conn.Close()
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, fmt.Errorf("%w: handshake timed out: %w", ErrSOCKS5, err)
		}
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %w", ErrSOCKS5, err)
	}
	return conn, nil
}

// handshake negotiates authentication and sends the CONNECT request.
func (d *socks5Dialer) handshake(conn net.Conn, request []byte) error {
	method := byte(socks5AuthNone)
	if d.isolation != "" {
		method = socks5AuthPassword
	}
	if _, err := conn.Write([]byte{socks5Version, 1, method}); err != nil {
		return fmt.Errorf("%w: send greeting: %w", ErrSOCKS5, err)
	}
	var choice [2]byte
	if _, err := io.ReadFull(conn, choice[:]); err != nil {
		return fmt.Errorf("%w: read method selection: %w", ErrSOCKS5, err)
	}
	if choice[0] != socks5Version {
		return fmt.Errorf("%w: proxy speaks version %d, not SOCKS5", ErrSOCKS5, choice[0])
	}
	if choice[1] == socks5AuthNoAccept {
		return fmt.Errorf("%w: proxy accepts none of the offered authentication methods", ErrSOCKS5)
	}
	if choice[1] != method {
		return fmt.Errorf("%w: proxy selected authentication method 0x%02x, which was not offered", ErrSOCKS5, choice[1])
	}
	if method == socks5AuthPassword {
		if err := d.authenticate(conn); err != nil {
			return err
		}
	}

	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("%w: send request: %w", ErrSOCKS5, err)
	}
	return readSOCKS5Reply(conn)
}

// authenticate performs username/password authentication (RFC 1929) with
// the isolation token as user name and password.
func (d *socks5Dialer) authenticate(conn net.Conn) error {
	token := d.isolation
	msg := make([]byte, 0, 3+2*len(token))
	msg = append(msg, socks5PasswordVersion, byte(len(token)))
	msg = append(msg, token...)
	msg = append(msg, byte(len(token)))
	msg = append(msg, token...)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("%w: send credentials: %w", ErrSOCKS5, err)
	}
	var status [2]byte
	if _, err := io.ReadFull(conn, status[:]); err != nil {
		return fmt.Errorf("%w: read authentication status: %w", ErrSOCKS5, err)
	}
	if status[0] != socks5PasswordVersion {
		return fmt.Errorf("%w: malformed authentication reply (version %d)", ErrSOCKS5, status[0])
	}
	if status[1] != 0 {
		return fmt.Errorf("%w: proxy rejected the credentials (status 0x%02x)", ErrSOCKS5, status[1])
	}
	return nil
}

// socks5ConnectRequest builds the CONNECT request for addr ("host:port").
// Host names are sent as domain names; nothing is resolved.
func socks5ConnectRequest(addr string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid destination %q: %w", ErrSOCKS5, addr, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("%w: invalid destination port in %q", ErrSOCKS5, addr)
	}

	request := []byte{socks5Version, socks5CmdConnect, 0x00}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return nil, fmt.Errorf("%w: destination %q has an IPv6 zone, which a proxy cannot use", ErrSOCKS5, addr)
		}
		ip = ip.Unmap()
		if ip.Is4() {
			request = append(request, socks5AddrIPv4)
		} else {
			request = append(request, socks5AddrIPv6)
		}
		request = append(request, ip.AsSlice()...)
	} else {
		if host == "" || len(host) > socks5MaxField {
			return nil, fmt.Errorf("%w: destination host name must be 1 to %d bytes", ErrSOCKS5, socks5MaxField)
		}
		request = append(request, socks5AddrDomain, byte(len(host)))
		request = append(request, host...)
	}
	return append(request, byte(port>>8), byte(port)), nil
}

// readSOCKS5Reply reads and checks the reply to a CONNECT request,
// consuming exactly its bytes so that the connection is positioned at the
// first byte from the destination.
func readSOCKS5Reply(conn net.Conn) error {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return fmt.Errorf("%w: read reply: %w", ErrSOCKS5, err)
	}
	if header[0] != socks5Version {
		return fmt.Errorf("%w: malformed reply (version %d)", ErrSOCKS5, header[0])
	}
	if header[1] != 0 {
		return &SOCKS5ReplyError{Code: header[1]}
	}
	if header[2] != 0 {
		return fmt.Errorf("%w: malformed reply (reserved byte 0x%02x)", ErrSOCKS5, header[2])
	}

	var addrLen int
	switch header[3] {
	case socks5AddrIPv4:
		addrLen = 4
	case socks5AddrIPv6:
		addrLen = 16
	case socks5AddrDomain:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return fmt.Errorf("%w: read reply: %w", ErrSOCKS5, err)
		}
		addrLen = int(n[0])
	default:
		return fmt.Errorf("%w: malformed reply (address type 0x%02x)", ErrSOCKS5, header[3])
	}
	rest := make([]byte, addrLen+2)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return fmt.Errorf("%w: read reply: %w", ErrSOCKS5, err)
	}
	return nil
}
