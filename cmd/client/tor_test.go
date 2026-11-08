package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/craguS/qchat/internal/transport"
)

const testOnion = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:7443"

func TestProxyFlags(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{nil, ""},
		{[]string{"--tor"}, "127.0.0.1:9050"},
		{[]string{"-tor"}, "127.0.0.1:9050"},
		{[]string{"--socks5", "127.0.0.1:9150"}, "127.0.0.1:9150"},
		{[]string{"--socks5", "[::1]:09150"}, "[::1]:9150"},
		{[]string{"--tor", "--socks5", "127.0.0.1:9150"}, "127.0.0.1:9150"},
		{[]string{"--socks5=proxy.lan:1080", "--tor"}, "proxy.lan:1080"},
	}
	for _, tc := range cases {
		if got := flags(t, tc.args...).proxy; got != tc.want {
			t.Errorf("args %v: proxy %q, want %q", tc.args, got, tc.want)
		}
	}
}

func TestProxyFlagsRejectInvalidAddress(t *testing.T) {
	for _, bad := range []string{"", "127.0.0.1", "127.0.0.1:0", "host:99999", "user@host:9050", "host:port"} {
		_, err := parseFlags([]string{"--tor", "--socks5", bad}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "--socks5") || !errors.Is(err, transport.ErrInvalidAddress) {
			t.Errorf("--socks5 %q: error %v", bad, err)
		}
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"--server", "chat.example.org:443", "--pin", pinA, "--socks5", "nope"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "--socks5") {
		t.Fatalf("bad --socks5: code %d, stderr %q", code, errOut.String())
	}
}

func TestResolveTargetWithProxy(t *testing.T) {
	direct, err := resolveTarget(embedded{}, flags(t, "--server", "chat.example.org:443", "--pin", pinA))
	if err != nil {
		t.Fatal(err)
	}
	if direct.proxy != "" || direct.isolation != "" || direct.dialer() != nil {
		t.Fatalf("direct target %+v has a proxy", direct)
	}

	a, err := resolveTarget(embedded{}, flags(t, "--tor", "--server", testOnion, "--pin", pinA))
	if err != nil {
		t.Fatalf("onion server with --tor: %v", err)
	}
	if a.addr != testOnion || a.proxy != "127.0.0.1:9050" || a.dialer() == nil {
		t.Fatalf("target %+v", a)
	}
	b, err := resolveTarget(embedded{}, flags(t, "--tor", "--server", testOnion, "--pin", pinA))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.isolation) != 32 || a.isolation == b.isolation {
		t.Fatalf("isolation tokens %q and %q: want 32 hex digits, fresh per run", a.isolation, b.isolation)
	}

	emb := embedded{addr: "locked.example.org:443", pin: mustPin(t, pinA), ok: true}
	locked, err := resolveTarget(emb, flags(t, "--socks5", "127.0.0.1:9150"))
	if err != nil || !locked.locked || locked.proxy != "127.0.0.1:9150" || locked.isolation == "" {
		t.Fatalf("locked target %+v, %v", locked, err)
	}
}

// fakeProxy listens on 127.0.0.1 and reports the first greeting it
// receives, answering "no acceptable methods".
func fakeProxy(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	greetings := make(chan []byte, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			greeting := make([]byte, 3)
			if _, err := io.ReadFull(conn, greeting); err == nil {
				greetings <- greeting
			}
			conn.Write([]byte{0x05, 0xff})
			conn.Close()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
	})
	return ln.Addr().String(), greetings
}

func TestSessionsDialThroughProxy(t *testing.T) {
	proxy, greetings := fakeProxy(t)
	tgt, err := resolveTarget(embedded{}, flags(t, "--socks5", proxy, "--server", testOnion, "--pin", pinA))
	if err != nil {
		t.Fatal(err)
	}
	opts, _ := lookupOptions(tgt, nil)
	if opts.Dialer == nil {
		t.Fatal("recovery lookup would connect directly")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = opts.Dialer(ctx, "tcp", testOnion)
	if !errors.Is(err, transport.ErrSOCKS5) {
		t.Fatalf("dial error %v, want the proxy's refusal", err)
	}
	select {
	case greeting := <-greetings:
		if !bytes.Equal(greeting, []byte{0x05, 0x01, 0x02}) {
			t.Fatalf("greeting %x, want SOCKS5 with username/password only", greeting)
		}
	default:
		t.Fatal("proxy saw no connection")
	}
}

func TestNoDirectFallbackWhenProxyDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := ln.Addr().String()
	ln.Close()

	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if conn, err := server.Accept(); err == nil {
			accepted <- struct{}{}
			conn.Close()
		}
	}()

	tgt, err := resolveTarget(embedded{}, flags(t, "--socks5", proxy, "--server", server.Addr().String(), "--pin", pinA))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := tgt.dialer()(ctx, "tcp", tgt.addr); !errors.Is(err, transport.ErrSOCKS5) {
		t.Fatalf("dial error %v, want ErrSOCKS5", err)
	}
	select {
	case <-accepted:
		t.Fatal("the server was contacted directly")
	case <-time.After(100 * time.Millisecond):
	}
}
