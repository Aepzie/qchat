package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// startProxy runs script for every connection accepted on a fresh
// 127.0.0.1 listener and returns the listener's address. The connection is
// closed when script returns; all handlers have finished when the test ends.
func startProxy(t *testing.T, script func(conn net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				script(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		wg.Wait()
	})
	return ln.Addr().String()
}

// readGreeting reads a SOCKS5 greeting and returns the offered methods.
func readGreeting(conn net.Conn) ([]byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return nil, err
	}
	if head[0] != socks5Version {
		return nil, errors.New("greeting: wrong version")
	}
	methods := make([]byte, head[1])
	_, err := io.ReadFull(conn, methods)
	return methods, err
}

// readCredentials reads an RFC 1929 username/password request.
func readCredentials(conn net.Conn) (user, pass string, err error) {
	var ver [1]byte
	if _, err := io.ReadFull(conn, ver[:]); err != nil {
		return "", "", err
	}
	if ver[0] != socks5PasswordVersion {
		return "", "", errors.New("credentials: wrong version")
	}
	field := func() (string, error) {
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return "", err
		}
		b := make([]byte, n[0])
		_, err := io.ReadFull(conn, b)
		return string(b), err
	}
	if user, err = field(); err != nil {
		return "", "", err
	}
	pass, err = field()
	return user, pass, err
}

// connectRequest is a parsed SOCKS5 CONNECT request.
type connectRequest struct {
	atyp byte
	host string
	port int
}

// readRequest reads a SOCKS5 CONNECT request.
func readRequest(conn net.Conn) (connectRequest, error) {
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return connectRequest{}, err
	}
	if head[0] != socks5Version || head[1] != socks5CmdConnect || head[2] != 0 {
		return connectRequest{}, errors.New("request: malformed header")
	}
	req := connectRequest{atyp: head[3]}
	var addr []byte
	switch head[3] {
	case socks5AddrIPv4:
		addr = make([]byte, 4)
	case socks5AddrIPv6:
		addr = make([]byte, 16)
	case socks5AddrDomain:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return connectRequest{}, err
		}
		addr = make([]byte, n[0])
	default:
		return connectRequest{}, errors.New("request: unknown address type")
	}
	if _, err := io.ReadFull(conn, addr); err != nil {
		return connectRequest{}, err
	}
	if head[3] == socks5AddrDomain {
		req.host = string(addr)
	} else {
		req.host = net.IP(addr).String()
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return connectRequest{}, err
	}
	req.port = int(port[0])<<8 | int(port[1])
	return req, nil
}

// proxyLog records what a well-behaved fake proxy saw.
type proxyLog struct {
	methods  chan []byte
	creds    chan [2]string
	requests chan connectRequest
}

// startGoodProxy runs a correct SOCKS5 proxy. With isolation set it
// requires username/password authentication. After a successful CONNECT it
// relays to upstream(host) if upstream is non-nil, and otherwise sends
// "hello" in the same write as the reply and then echoes.
func startGoodProxy(t *testing.T, requireAuth bool, upstream func(host string) string) (string, *proxyLog) {
	t.Helper()
	log := &proxyLog{
		methods:  make(chan []byte, 16),
		creds:    make(chan [2]string, 16),
		requests: make(chan connectRequest, 16),
	}
	addr := startProxy(t, func(conn net.Conn) {
		methods, err := readGreeting(conn)
		if err != nil {
			t.Errorf("proxy: %v", err)
			return
		}
		log.methods <- methods
		want := byte(socks5AuthNone)
		if requireAuth {
			want = socks5AuthPassword
		}
		if !bytes.Contains(methods, []byte{want}) {
			conn.Write([]byte{socks5Version, socks5AuthNoAccept})
			return
		}
		conn.Write([]byte{socks5Version, want})
		if requireAuth {
			user, pass, err := readCredentials(conn)
			if err != nil {
				t.Errorf("proxy: %v", err)
				return
			}
			log.creds <- [2]string{user, pass}
			conn.Write([]byte{socks5PasswordVersion, 0})
		}
		req, err := readRequest(conn)
		if err != nil {
			t.Errorf("proxy: %v", err)
			return
		}
		log.requests <- req
		reply := []byte{socks5Version, 0, 0, socks5AddrDomain, 4, 'b', 'n', 'd', 'x', 0x1f, 0x90}
		if upstream == nil {
			conn.Write(append(reply, "hello"...))
			io.Copy(conn, conn)
			return
		}
		up, err := net.Dial("tcp", upstream(req.host))
		if err != nil {
			conn.Write([]byte{socks5Version, 0x04, 0, socks5AddrIPv4, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		conn.Write(reply)
		conn.SetDeadline(time.Time{})
		done := make(chan struct{})
		go func() {
			io.Copy(up, conn)
			up.Close()
			close(done)
		}()
		io.Copy(conn, up)
		conn.Close()
		<-done
	})
	return addr, log
}

func socksTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestSOCKS5ConnectByHostName(t *testing.T) {
	proxy, log := startGoodProxy(t, false, nil)
	dial := SOCKS5Dialer(proxy, "")

	conn, err := dial(socksTestContext(t), "tcp", "example.onion:7443")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if got := <-log.methods; !bytes.Equal(got, []byte{socks5AuthNone}) {
		t.Errorf("offered methods %x, want only no authentication", got)
	}
	req := <-log.requests
	if req.atyp != socks5AddrDomain || req.host != "example.onion" || req.port != 7443 {
		t.Errorf("request %+v, want domain example.onion port 7443", req)
	}

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	greeting := make([]byte, 5)
	if _, err := io.ReadFull(conn, greeting); err != nil || string(greeting) != "hello" {
		t.Fatalf("first bytes after reply %q, %v; want %q", greeting, err, "hello")
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(conn, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("echo %q, %v", echo, err)
	}
}

func TestSOCKS5IPLiterals(t *testing.T) {
	cases := []struct {
		addr string
		atyp byte
		host string
	}{
		{"192.0.2.1:443", socks5AddrIPv4, "192.0.2.1"},
		{"[2001:db8::1]:8443", socks5AddrIPv6, "2001:db8::1"},
		{"[::ffff:192.0.2.9]:443", socks5AddrIPv4, "192.0.2.9"},
	}
	proxy, log := startGoodProxy(t, false, nil)
	dial := SOCKS5Dialer(proxy, "")
	for _, tc := range cases {
		conn, err := dial(socksTestContext(t), "tcp", tc.addr)
		if err != nil {
			t.Fatalf("dial %s: %v", tc.addr, err)
		}
		conn.Close()
		<-log.methods
		req := <-log.requests
		_, port, _ := net.SplitHostPort(tc.addr)
		if req.atyp != tc.atyp || req.host != tc.host || strconv.Itoa(req.port) != port {
			t.Errorf("%s: request %+v", tc.addr, req)
		}
	}
}

func TestSOCKS5IsolationCredentials(t *testing.T) {
	proxy, log := startGoodProxy(t, true, nil)

	for _, token := range []string{"session-a", "session-b", strings.Repeat("z", 255)} {
		conn, err := SOCKS5Dialer(proxy, token)(socksTestContext(t), "tcp", "example.org:443")
		if err != nil {
			t.Fatalf("dial with token %q: %v", token, err)
		}
		conn.Close()
		if got := <-log.methods; !bytes.Equal(got, []byte{socks5AuthPassword}) {
			t.Errorf("offered methods %x, want only username/password", got)
		}
		if got := <-log.creds; got != [2]string{token, token} {
			t.Errorf("credentials %q, want user and password %q", got, token)
		}
		<-log.requests
	}
}

func TestSOCKS5NoFallbackWithoutAuth(t *testing.T) {
	proxy, _ := startGoodProxy(t, true, nil)
	_, err := SOCKS5Dialer(proxy, "")(socksTestContext(t), "tcp", "example.org:443")
	if !errors.Is(err, ErrSOCKS5) || !strings.Contains(err.Error(), "none of the offered") {
		t.Fatalf("error %v, want refused authentication", err)
	}
}

// replyAfterGreeting returns a proxy script that reads the greeting, writes
// selection, and, if afterRequest is non-nil, reads the CONNECT request and
// writes afterRequest.
func replyAfterGreeting(selection, afterRequest []byte) func(conn net.Conn) {
	return func(conn net.Conn) {
		if _, err := readGreeting(conn); err != nil {
			return
		}
		conn.Write(selection)
		if afterRequest == nil {
			return
		}
		if _, err := readRequest(conn); err != nil {
			return
		}
		conn.Write(afterRequest)
	}
}

func TestSOCKS5ReplyCodes(t *testing.T) {
	for _, code := range []byte{0x01, 0x02, 0x04, 0x05, 0x08, 0xf0, 0xf2, 0xf6, 0x42} {
		proxy := startProxy(t, replyAfterGreeting(
			[]byte{socks5Version, socks5AuthNone},
			[]byte{socks5Version, code, 0, socks5AddrIPv4, 0, 0, 0, 0, 0, 0},
		))
		_, err := SOCKS5Dialer(proxy, "")(socksTestContext(t), "tcp", "example.onion:7443")
		var replyErr *SOCKS5ReplyError
		if !errors.As(err, &replyErr) || replyErr.Code != code {
			t.Errorf("code 0x%02x: error %v, want SOCKS5ReplyError", code, err)
			continue
		}
		if !errors.Is(err, ErrSOCKS5) {
			t.Errorf("code 0x%02x: error does not wrap ErrSOCKS5", code)
		}
	}
	if text := (&SOCKS5ReplyError{Code: 0xf0}).Error(); !strings.Contains(text, "onion service descriptor not found") {
		t.Errorf("Tor error text %q", text)
	}
}

func TestSOCKS5MalformedReplies(t *testing.T) {
	ok := []byte{socks5Version, socks5AuthNone}
	cases := map[string]func(conn net.Conn){
		"empty selection":        replyAfterGreeting(nil, nil),
		"short selection":        replyAfterGreeting([]byte{socks5Version}, nil),
		"SOCKS4 selection":       replyAfterGreeting([]byte{0x04, socks5AuthNone}, nil),
		"unoffered method":       replyAfterGreeting([]byte{socks5Version, socks5AuthPassword}, nil),
		"unknown method":         replyAfterGreeting([]byte{socks5Version, 0x80}, nil),
		"reply wrong version":    replyAfterGreeting(ok, []byte{0x04, 0, 0, socks5AddrIPv4, 0, 0, 0, 0, 0, 0}),
		"reply reserved byte":    replyAfterGreeting(ok, []byte{socks5Version, 0, 1, socks5AddrIPv4, 0, 0, 0, 0, 0, 0}),
		"reply address type":     replyAfterGreeting(ok, []byte{socks5Version, 0, 0, 0x09, 0, 0, 0, 0, 0, 0}),
		"reply truncated header": replyAfterGreeting(ok, []byte{socks5Version, 0}),
		"reply truncated IPv4":   replyAfterGreeting(ok, []byte{socks5Version, 0, 0, socks5AddrIPv4, 127, 0}),
		"reply truncated IPv6":   replyAfterGreeting(ok, []byte{socks5Version, 0, 0, socks5AddrIPv6, 0, 0, 0, 0}),
		"reply truncated domain": replyAfterGreeting(ok, []byte{socks5Version, 0, 0, socks5AddrDomain, 200, 'a'}),
		"reply missing length":   replyAfterGreeting(ok, []byte{socks5Version, 0, 0, socks5AddrDomain}),
		"reply missing port":     replyAfterGreeting(ok, []byte{socks5Version, 0, 0, socks5AddrIPv4, 1, 2, 3, 4, 0}),
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			proxy := startProxy(t, script)
			conn, err := SOCKS5Dialer(proxy, "")(socksTestContext(t), "tcp", "example.onion:7443")
			if err == nil {
				conn.Close()
				t.Fatal("dial succeeded")
			}
			if !errors.Is(err, ErrSOCKS5) {
				t.Fatalf("error %v does not wrap ErrSOCKS5", err)
			}
		})
	}
}

func TestSOCKS5MalformedAuthReplies(t *testing.T) {
	cases := map[string][]byte{
		"rejected":      {socks5PasswordVersion, 0x01},
		"wrong version": {socks5Version, 0x00},
		"truncated":     {socks5PasswordVersion},
	}
	for name, status := range cases {
		t.Run(name, func(t *testing.T) {
			proxy := startProxy(t, func(conn net.Conn) {
				if _, err := readGreeting(conn); err != nil {
					return
				}
				conn.Write([]byte{socks5Version, socks5AuthPassword})
				if _, _, err := readCredentials(conn); err != nil {
					return
				}
				conn.Write(status)
			})
			_, err := SOCKS5Dialer(proxy, "token")(socksTestContext(t), "tcp", "example.onion:7443")
			if !errors.Is(err, ErrSOCKS5) {
				t.Fatalf("error %v, want ErrSOCKS5", err)
			}
		})
	}
}

func TestSOCKS5RejectsBadInputBeforeConnecting(t *testing.T) {
	var accepted int
	var mu sync.Mutex
	proxy := startProxy(t, func(net.Conn) {
		mu.Lock()
		accepted++
		mu.Unlock()
	})
	cases := []struct {
		network, addr, isolation string
	}{
		{"udp", "example.org:443", ""},
		{"unix", "example.org:443", ""},
		{"tcp", "example.org", ""},
		{"tcp", "example.org:0", ""},
		{"tcp", "example.org:65536", ""},
		{"tcp", "example.org:https", ""},
		{"tcp", ":443", ""},
		{"tcp", strings.Repeat("a", 256) + ":443", ""},
		{"tcp", "[fe80::1%eth0]:443", ""},
		{"tcp", "example.org:443", strings.Repeat("t", 256)},
	}
	for _, tc := range cases {
		conn, err := SOCKS5Dialer(proxy, tc.isolation)(socksTestContext(t), tc.network, tc.addr)
		if err == nil {
			conn.Close()
			t.Errorf("%s %q: dial succeeded", tc.network, tc.addr)
			continue
		}
		if !errors.Is(err, ErrSOCKS5) {
			t.Errorf("%s %q: error %v does not wrap ErrSOCKS5", tc.network, tc.addr, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if accepted != 0 {
		t.Errorf("proxy saw %d connections for invalid input, want 0", accepted)
	}
}

func TestSOCKS5ProxyUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	_, err = SOCKS5Dialer(addr, "")(socksTestContext(t), "tcp", "example.org:443")
	if !errors.Is(err, ErrSOCKS5) {
		t.Fatalf("error %v, want ErrSOCKS5", err)
	}
}

// stallingProxy reads the greeting and then never answers until the
// client goes away.
func stallingProxy(t *testing.T) string {
	return startProxy(t, func(conn net.Conn) {
		if _, err := readGreeting(conn); err != nil {
			return
		}
		io.Copy(io.Discard, conn)
	})
}

func TestSOCKS5HandshakeTimeout(t *testing.T) {
	d := &socks5Dialer{
		proxyAddr:        stallingProxy(t),
		connectTimeout:   time.Second,
		handshakeTimeout: 200 * time.Millisecond,
	}
	start := time.Now()
	_, err := d.DialContext(socksTestContext(t), "tcp", "example.onion:7443")
	if !errors.Is(err, ErrSOCKS5) || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("error %v, want handshake timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}
}

func TestSOCKS5ContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := SOCKS5Dialer(stallingProxy(t), "")(ctx, "tcp", "example.onion:7443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("deadline took %v", elapsed)
	}
}

func TestSOCKS5ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	_, err := SOCKS5Dialer(stallingProxy(t), "token")(ctx, "tcp", "example.onion:7443")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v, want context.Canceled", err)
	}
}

func TestSOCKS5ConnectionUsableAfterHandshake(t *testing.T) {
	proxy, _ := startGoodProxy(t, false, nil)
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := SOCKS5Dialer(proxy, "")(ctx, "tcp", "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read after the dial context ended: %v", err)
	}
}

func TestServerIdentityForOnionHost(t *testing.T) {
	onion := "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
	if _, _, err := GenerateServerIdentity([]string{onion}); err != nil {
		t.Fatalf("GenerateServerIdentity(%q): %v", onion, err)
	}
}

// TestDialThroughSOCKS5Onion runs the full transport through the proxy to
// a v3 onion host name, which only the proxy can reach: a local DNS lookup
// would fail. Pinning still authenticates the server end to end.
func TestDialThroughSOCKS5Onion(t *testing.T) {
	ts := startTestServer(t, 0)
	onion := strings.Repeat("a", 52) + "qcad.onion"
	proxy, log := startGoodProxy(t, true, func(host string) string {
		if host != onion {
			return "127.0.0.1:1"
		}
		return ts.addr
	})
	ctx := testContext(t)
	opts := DialOptions{NetDialContext: SOCKS5Dialer(proxy, "isolation-token")}

	conn, err := Dial(ctx, onion+":7443", ts.pin, opts)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.CloseNow()
	if req := <-log.requests; req.atyp != socks5AddrDomain || req.host != onion || req.port != 7443 {
		t.Errorf("request %+v", req)
	}
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("over tor")); err != nil {
		t.Fatal(err)
	}
	if _, got, err := conn.Read(ctx); err != nil || string(got) != "over tor" {
		t.Fatalf("echo %q, %v", got, err)
	}
	conn.Close(websocket.StatusNormalClosure, "")

	wrong := ts.pin
	wrong[0] ^= 0xff
	_, err = Dial(ctx, onion+":7443", wrong, opts)
	var mismatch *PinMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("Dial with a wrong pin through the proxy: %v, want PinMismatchError", err)
	}
}
