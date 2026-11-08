package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/craguS/qchat/internal/client"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/transport"
)

const (
	// maxAnonymousDelay bounds the random pause before the anonymous
	// session connects, so that it does not connect in lockstep with the
	// first sealed send or with the authenticated session.
	maxAnonymousDelay = 10 * time.Second
	// anonymousConnectWait bounds how long a sealed request waits for the
	// anonymous session to connect; onion circuits are slow to build.
	anonymousConnectWait = 90 * time.Second
)

// anonymousDialer returns the dial function for an anonymous session: nil
// for direct connections, otherwise one through the proxy with an
// isolation token of its own, drawn for every call, so that Tor puts the
// session on a circuit separate from the authenticated session's and from
// every earlier anonymous session's.
//
// Without a proxy the anonymous session connects directly from the same
// address as the authenticated one, so the relay can link both by address
// and timing; sealed sender then still hides the sender from the stored
// queue rows and from the protocol, not from the live relay.
func (t target) anonymousDialer() (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	if t.proxy == "" {
		return nil, nil
	}
	token, err := client.NewIsolationToken()
	if err != nil {
		return nil, err
	}
	return transport.SOCKS5Dialer(t.proxy, token), nil
}

// newAnonymousSession returns a new anonymous session for t with a fresh
// dialer.
func newAnonymousSession(t target) (*client.Session, error) {
	dialer, err := t.anonymousDialer()
	if err != nil {
		return nil, err
	}
	return client.New(client.Options{Addr: t.addr, Pin: t.pin, Dialer: dialer, Anonymous: true})
}

// randomPause returns a uniformly random duration below limit.
func randomPause(limit time.Duration) time.Duration {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil || limit <= 0 {
		return limit
	}
	return time.Duration(binary.BigEndian.Uint64(b[:]) % uint64(limit))
}

// anonymousLink is the anonymous relay session used for sealed sends, as
// app.Requester. It is created and connected lazily: the first sealed
// request starts it after a random pause (delay), and every request waits
// until it is connected. Each link builds its session once; a deliberate
// new anonymous connection needs a new link, and thus a new session and
// isolation token.
type anonymousLink struct {
	ctx        context.Context
	newSession func() (*client.Session, error)
	delay      func() time.Duration
	wait       time.Duration
	onState    func(connected bool)

	once sync.Once
	sess *client.Session
	err  error
	done chan struct{}

	mu sync.Mutex
	up chan struct{}
}

// newAnonymousLink returns a link that runs its session until ctx ends and
// reports connection changes to onState.
func newAnonymousLink(ctx context.Context, newSession func() (*client.Session, error), onState func(bool)) *anonymousLink {
	return &anonymousLink{
		ctx:        ctx,
		newSession: newSession,
		delay:      func() time.Duration { return randomPause(maxAnonymousDelay) },
		wait:       anonymousConnectWait,
		onState:    onState,
		done:       make(chan struct{}),
		up:         make(chan struct{}),
	}
}

// start creates and runs the session once, after the random pause.
func (l *anonymousLink) start() {
	l.once.Do(func() {
		pause := time.NewTimer(l.delay())
		defer pause.Stop()
		select {
		case <-l.ctx.Done():
			l.err = client.ErrNotConnected
			close(l.done)
			return
		case <-pause.C:
		}
		if l.sess, l.err = l.newSession(); l.err != nil {
			close(l.done)
			return
		}
		go func() {
			defer close(l.done)
			_ = l.sess.Run(l.ctx)
		}()
		go l.watch(l.sess.Events())
	})
}

// watch tracks the connection state of the session.
func (l *anonymousLink) watch(events <-chan client.Event) {
	for ev := range events {
		sc, ok := ev.(client.StateChanged)
		if !ok {
			continue
		}
		connected := sc.State == client.Connected
		l.mu.Lock()
		changed := l.isUpLocked() != connected
		switch {
		case !changed:
		case connected:
			close(l.up)
		default:
			l.up = make(chan struct{})
		}
		l.mu.Unlock()
		if changed && l.onState != nil {
			l.onState(connected)
		}
	}
}

func (l *anonymousLink) isUpLocked() bool {
	select {
	case <-l.up:
		return true
	default:
		return false
	}
}

func (l *anonymousLink) connected() <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.up
}

// Request starts the session if needed, waits until it is connected, at
// most l.wait, and sends the request on it.
func (l *anonymousLink) Request(ctx context.Context, t protocol.FrameType, body any) (protocol.Frame, error) {
	l.start()
	if l.err != nil {
		return protocol.Frame{}, l.err
	}
	wait := time.NewTimer(l.wait)
	defer wait.Stop()
	select {
	case <-l.connected():
	case <-wait.C:
		return protocol.Frame{}, client.ErrNotConnected
	case <-ctx.Done():
		return protocol.Frame{}, ctx.Err()
	}
	return l.sess.Request(ctx, t, body)
}

// Ack fails: nothing is ever delivered on an anonymous session.
func (l *anonymousLink) Ack(uint64) error { return client.ErrWrongSession }

// stopped returns a channel closed once the session has stopped, or at once
// if it never started.
func (l *anonymousLink) stopped() <-chan struct{} {
	l.once.Do(func() {
		l.err = client.ErrNotConnected
		close(l.done)
	})
	return l.done
}
