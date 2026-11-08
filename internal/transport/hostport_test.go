package transport

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestValidateHostPortAccepts(t *testing.T) {
	cases := map[string]string{
		"localhost:1":             "localhost:1",
		"example.org:65535":       "example.org:65535",
		"chat.example.org:0443":   "chat.example.org:443",
		"10.0.0.1:8443":           "10.0.0.1:8443",
		"[::1]:8443":              "[::1]:8443",
		"[fe80::1%25eth0]:443":    "[fe80::1%25eth0]:443",
		"xn--bcher-kva.example:1": "xn--bcher-kva.example:1",
		"pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:7443": "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:7443",
		"PG6MMJIYJMCRSSLVYKFWNNTLARU7P5SVN6Y2YMMJU6NUBXNDF4PSCRYD.ONION:443":  "PG6MMJIYJMCRSSLVYKFWNNTLARU7P5SVN6Y2YMMJU6NUBXNDF4PSCRYD.ONION:443",
	}
	for in, want := range cases {
		got, err := ValidateHostPort(in)
		if err != nil {
			t.Errorf("ValidateHostPort(%q) = %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ValidateHostPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateHostPortRejects(t *testing.T) {
	bad := []string{
		"", "host", "host:", "host:abc", "host:0", "host:70000", "host:-1", ":80",
		"a:b:443", "user@host:443", "host/path:443", `host\x:443`, "host?q:443",
		"host#f:443", "ho st:443", "host\t:443", "host\x00:443", "host\x7f:443",
		"bücher.example:443", "[host]]:443",
	}
	for _, in := range bad {
		got, err := ValidateHostPort(in)
		if err == nil {
			t.Errorf("ValidateHostPort(%q) = %q, want error", in, got)
			continue
		}
		if !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("ValidateHostPort(%q) error %v does not wrap ErrInvalidAddress", in, err)
		}
	}
}

func TestDialRejectsInvalidAddressWithoutNetwork(t *testing.T) {
	var pin Fingerprint
	pin[0] = 1
	dial := func(context.Context, string, string) (net.Conn, error) {
		t.Error("Dial opened a connection for an invalid address")
		return nil, errors.New("must not dial")
	}
	_, err := Dial(context.Background(), "user@host:443", pin, DialOptions{NetDialContext: dial})
	if !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("Dial error = %v, want ErrInvalidAddress", err)
	}
}
