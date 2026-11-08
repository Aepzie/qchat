package main

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Aepzie/qchat/internal/client"
	"github.com/Aepzie/qchat/internal/protocol"
)

// recordingProxy accepts SOCKS5 username/password authentication, reports
// every user name it sees and then refuses the credentials.
func recordingProxy(t *testing.T) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	names := make(chan string, 8)
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
				conn.Write([]byte{0x05, 0x02})
				head := make([]byte, 2)
				if _, err := io.ReadFull(conn, head); err == nil {
					name := make([]byte, head[1])
					if _, err := io.ReadFull(conn, name); err == nil {
						names <- string(name)
					}
				}
				conn.Write([]byte{0x01, 0x01})
			}
			conn.Close()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
	})
	return ln.Addr().String(), names
}

func TestAnonymousSessionGetsItsOwnCircuit(t *testing.T) {
	proxy, names := recordingProxy(t)
	tgt, err := resolveTarget(embedded{}, flags(t, "--socks5", proxy, "--server", testOnion, "--pin", pinA))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dial := func(d func(context.Context, string, string) (net.Conn, error)) string {
		t.Helper()
		if _, err := d(ctx, "tcp", testOnion); err == nil {
			t.Fatal("the proxy accepted")
		}
		select {
		case name := <-names:
			return name
		case <-ctx.Done():
			t.Fatal("the proxy saw no authentication")
			return ""
		}
	}
	run := dial(tgt.dialer())
	first, err := tgt.anonymousDialer()
	if err != nil || first == nil {
		t.Fatalf("anonymous dialer %v", err)
	}
	second, err := tgt.anonymousDialer()
	if err != nil {
		t.Fatal(err)
	}
	a, b := dial(first), dial(second)
	if run != tgt.isolation || len(a) != 32 || a == run || b == run || a == b {
		t.Fatalf("isolation tokens: run %q, anonymous %q and %q; want three distinct tokens", run, a, b)
	}

	direct, err := resolveTarget(embedded{}, flags(t, "--server", "chat.example.org:443", "--pin", pinA))
	if err != nil {
		t.Fatal(err)
	}
	if d, err := direct.anonymousDialer(); err != nil || d != nil {
		t.Fatalf("direct anonymous dialer %v, %v", d != nil, err)
	}
}

func TestAnonymousLinkConnectsLazily(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	tgt, err := resolveTarget(embedded{}, flags(t, "--server", addr, "--pin", pinA))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var created, pauses atomic.Int32
	link := newAnonymousLink(ctx, func() (*client.Session, error) {
		created.Add(1)
		return newAnonymousSession(tgt)
	}, nil)
	link.delay = func() time.Duration {
		pauses.Add(1)
		return 10 * time.Millisecond
	}
	link.wait = 10 * time.Second
	time.Sleep(50 * time.Millisecond)
	if created.Load() != 0 {
		t.Fatal("the anonymous session was created before any sealed request")
	}
	body := protocol.SealedSend{To: make([]byte, 32), AccessProof: make([]byte, 32), Payload: []byte{1}}
	for range 2 {
		if _, err := link.Request(context.Background(), protocol.TypeSealedSend, body); !errors.Is(err, client.ErrNotConnected) {
			t.Fatalf("Request without a relay = %v, want ErrNotConnected", err)
		}
	}
	if created.Load() != 2 || pauses.Load() != 2 {
		t.Fatalf("%d sessions after %d pauses, want a fresh session after each ended one", created.Load(), pauses.Load())
	}
	if err := link.Ack(1); !errors.Is(err, client.ErrWrongSession) {
		t.Fatalf("Ack = %v", err)
	}
	cancel()
	select {
	case <-link.stopped():
	case <-time.After(5 * time.Second):
		t.Fatal("the anonymous session did not stop")
	}

	idle := newAnonymousLink(context.Background(), func() (*client.Session, error) {
		t.Fatal("an unused link created a session")
		return nil, nil
	}, nil)
	<-idle.stopped()
	if _, err := idle.Request(context.Background(), protocol.TypeSealedSend, body); !errors.Is(err, client.ErrNotConnected) {
		t.Fatalf("Request after stop = %v", err)
	}
}
