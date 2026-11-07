package buildcfg

import (
	"errors"
	"strings"
	"testing"

	"github.com/craguS/qchat/internal/transport"
)

const validPin = "sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

func TestParseNotEmbedded(t *testing.T) {
	addr, pin, ok, err := parse("", "")
	if err != nil || ok || addr != "" || !pin.IsZero() {
		t.Fatalf("parse(empty) = %q, %v, %v, %v", addr, pin, ok, err)
	}
}

func TestParseEmbedded(t *testing.T) {
	addr, pin, ok, err := parse("chat.example.org:443", validPin)
	if err != nil || !ok {
		t.Fatalf("parse: ok=%v err=%v", ok, err)
	}
	if addr != "chat.example.org:443" {
		t.Errorf("addr = %q", addr)
	}
	if pin.String() != validPin {
		t.Errorf("pin = %s", pin)
	}
}

func TestParseRejectsBrokenEmbedding(t *testing.T) {
	cases := []struct{ addr, pin string }{
		{"chat.example.org:443", ""},
		{"", validPin},
		{"chat.example.org", validPin},
		{"chat.example.org:0", validPin},
		{":443", validPin},
		{"chat.example.org:443", "sha256:1234"},
		{"chat.example.org:443", "sha256:" + strings.Repeat("0", 64)},
	}
	for _, c := range cases {
		if _, _, ok, err := parse(c.addr, c.pin); ok || err == nil {
			t.Errorf("parse(%q, %q): ok=%v err=%v, want error", c.addr, c.pin, ok, err)
		}
	}
}

func TestEmbeddedUsesPackageVariables(t *testing.T) {
	oldAddr, oldPin := ServerAddr, ServerPin
	t.Cleanup(func() { ServerAddr, ServerPin = oldAddr, oldPin })

	ServerAddr, ServerPin = "", ""
	if _, _, ok, err := Embedded(); ok || err != nil {
		t.Fatalf("unset: ok=%v err=%v", ok, err)
	}
	ServerAddr, ServerPin = "10.0.0.1:8443", validPin
	addr, _, ok, err := Embedded()
	if !ok || err != nil || addr != "10.0.0.1:8443" {
		t.Fatalf("set: addr=%q ok=%v err=%v", addr, ok, err)
	}
}

func TestParseUsesTransportAddressRules(t *testing.T) {
	for _, bad := range []string{"user@chat.example.org:443", "chat example.org:443", "chat.example.org/x:443", "bücher.example:443"} {
		_, _, ok, err := parse(bad, validPin)
		if ok || !errors.Is(err, transport.ErrInvalidAddress) {
			t.Errorf("parse(%q): ok=%v err=%v, want ErrInvalidAddress", bad, ok, err)
		}
	}
	addr, _, ok, err := parse("chat.example.org:0443", validPin)
	if !ok || err != nil || addr != "chat.example.org:443" {
		t.Errorf("parse(non-canonical port) = %q, %v, %v; want canonical address", addr, ok, err)
	}
}
