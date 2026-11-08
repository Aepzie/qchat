package transport

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"testing"
)

// readerConn is a net.Conn whose reads come from a fixed buffer. Only Read
// is implemented; readSOCKS5Reply uses nothing else.
type readerConn struct {
	net.Conn
	r *bytes.Reader
}

func (c readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func FuzzReadSOCKS5Reply(f *testing.F) {
	f.Add([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90})
	f.Add([]byte{0x05, 0x00, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb, 0xaa})
	f.Add([]byte{0x05, 0x00, 0x00, 0x03, 0x03, 'a', 'b', 'c', 0x00, 0x50})
	f.Add([]byte{0x05, 0x05, 0x00, 0x01})
	f.Add([]byte{0x05, 0x00, 0x00, 0x03, 0xff})
	f.Fuzz(func(t *testing.T, reply []byte) {
		r := bytes.NewReader(reply)
		if err := readSOCKS5Reply(readerConn{r: r}); err != nil {
			return
		}
		consumed := len(reply) - r.Len()
		want := 4 + 2
		switch reply[3] {
		case socks5AddrIPv4:
			want += 4
		case socks5AddrIPv6:
			want += 16
		case socks5AddrDomain:
			want += 1 + int(reply[4])
		default:
			t.Fatalf("accepted address type 0x%02x", reply[3])
		}
		if consumed != want {
			t.Fatalf("consumed %d bytes of reply %x, want %d", consumed, reply, want)
		}
		if reply[0] != socks5Version || reply[1] != 0 || reply[2] != 0 {
			t.Fatalf("accepted malformed reply header %x", reply[:4])
		}
	})
}

func FuzzSOCKS5ConnectRequest(f *testing.F) {
	f.Add("example.onion:443")
	f.Add("127.0.0.1:80")
	f.Add("[2001:db8::1]:8443")
	f.Add("[fe80::1%eth0]:1")
	f.Add("[::ffff:192.0.2.1]:65535")
	f.Add("host:0")
	f.Add(":1")
	f.Fuzz(func(t *testing.T, addr string) {
		request, err := socks5ConnectRequest(addr)
		if err != nil {
			return
		}
		host, portText, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatalf("accepted unsplittable %q", addr)
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			t.Fatalf("accepted invalid port in %q", addr)
		}
		if len(request) < 4+2 || request[0] != socks5Version || request[1] != socks5CmdConnect || request[2] != 0 {
			t.Fatalf("malformed request %x for %q", request, addr)
		}
		body := request[4 : len(request)-2]
		switch request[3] {
		case socks5AddrIPv4, socks5AddrIPv6:
			ip, ok := netip.AddrFromSlice(body)
			want, err := netip.ParseAddr(host)
			if !ok || err != nil || ip != want.Unmap() {
				t.Fatalf("request %x does not carry the address of %q", request, addr)
			}
			if (request[3] == socks5AddrIPv4) != ip.Is4() {
				t.Fatalf("request %x has the wrong address type for %q", request, addr)
			}
		case socks5AddrDomain:
			if len(body) < 2 || int(body[0]) != len(body)-1 || string(body[1:]) != host {
				t.Fatalf("request %x does not carry the host name of %q", request, addr)
			}
		default:
			t.Fatalf("request %x has unknown address type", request)
		}
		if got := binary.BigEndian.Uint16(request[len(request)-2:]); uint64(got) != port {
			t.Fatalf("request %x carries port %d, want %d", request, got, port)
		}
	})
}
