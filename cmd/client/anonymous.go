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

// anonymousLink is the anonymous relay session used for sealed sends and
// anonymous lookups, as app.Requester. Sessions are created lazily: a
// request that finds no live session starts one after a random pause
// (delay) and waits until it is connected. An anonymous client.Session
// ends when its connection fails or closes instead of reconnecting, so the
// next request then starts a new Session, whose dialer carries a fresh
// isolation token and thus a new Tor circuit.
type anonymousLink struct {
	ctx        context.Context
	newSession func() (*client.Session, error)
	delay      func() time.Duration
	wait       time.Duration
	onState    func(connected bool)

	mu       sync.Mutex
	cur      *anonymousRun
	starting chan struct{}
	closed   bool
	runs     sync.WaitGroup
}

// anonymousRun is one anonymous Session of a link.
type anonymousRun struct {
	sess  *client.Session
	up    chan struct{}
	ended chan struct{}
}

func closedChan(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// newAnonymousLink returns a link whose sessions run until ctx ends and
// report connection changes to onState.
func newAnonymousLink(ctx context.Context, newSession func() (*client.Session, error), onState func(bool)) *anonymousLink {
	return &anonymousLink{
		ctx:        ctx,
		newSession: newSession,
		delay:      func() time.Duration { return randomPause(maxAnonymousDelay) },
		wait:       anonymousConnectWait,
		onState:    onState,
	}
}

// current returns the live session, starting a new one after the random
// pause if there is none. Concurrent callers share one start.
func (l *anonymousLink) current(ctx context.Context) (*anonymousRun, error) {
	for {
		l.mu.Lock()
		switch {
		case l.closed:
			l.mu.Unlock()
			return nil, client.ErrNotConnected
		case l.cur != nil && !closedChan(l.cur.ended):
			run := l.cur
			l.mu.Unlock()
			return run, nil
		case l.starting != nil:
			starting := l.starting
			l.mu.Unlock()
			select {
			case <-starting:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		starting := make(chan struct{})
		l.starting = starting
		l.mu.Unlock()
		run, err := l.start()
		l.mu.Lock()
		l.starting = nil
		if run != nil {
			l.cur = run
		}
		l.mu.Unlock()
		close(starting)
		return run, err
	}
}

// start waits the random pause and then creates and runs a new session.
func (l *anonymousLink) start() (*anonymousRun, error) {
	pause := time.NewTimer(l.delay())
	defer pause.Stop()
	select {
	case <-l.ctx.Done():
		return nil, client.ErrNotConnected
	case <-pause.C:
	}
	sess, err := l.newSession()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, client.ErrNotConnected
	}
	l.runs.Add(1)
	l.mu.Unlock()
	run := &anonymousRun{sess: sess, up: make(chan struct{}), ended: make(chan struct{})}
	go func() {
		defer l.runs.Done()
		defer close(run.ended)
		_ = sess.Run(l.ctx)
	}()
	go l.watch(run)
	return run, nil
}

// watch tracks the connection state of one session and reports changes.
func (l *anonymousLink) watch(run *anonymousRun) {
	connected := false
	report := func(now bool) {
		if now == connected {
			return
		}
		connected = now
		if now {
			close(run.up)
		}
		if l.onState != nil {
			l.onState(now)
		}
	}
	for ev := range run.sess.Events() {
		if sc, ok := ev.(client.StateChanged); ok {
			report(sc.State == client.Connected)
		}
	}
	report(false)
}

// Request sends the request on the live session, starting a new one if
// needed and waiting until it is connected, at most l.wait.
func (l *anonymousLink) Request(ctx context.Context, t protocol.FrameType, body any) (protocol.Frame, error) {
	wait := time.NewTimer(l.wait)
	defer wait.Stop()
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-wait.C:
			cancel()
		case <-wctx.Done():
		}
	}()
	run, err := l.current(wctx)
	if err != nil {
		if ctx.Err() != nil {
			return protocol.Frame{}, ctx.Err()
		}
		return protocol.Frame{}, client.ErrNotConnected
	}
	select {
	case <-run.up:
	case <-run.ended:
		return protocol.Frame{}, client.ErrNotConnected
	case <-wctx.Done():
		if ctx.Err() != nil {
			return protocol.Frame{}, ctx.Err()
		}
		return protocol.Frame{}, client.ErrNotConnected
	}
	return run.sess.Request(ctx, t, body)
}

// Ack fails: nothing is ever delivered on an anonymous session.
func (l *anonymousLink) Ack(uint64) error { return client.ErrWrongSession }

// stopped stops the link from starting sessions and returns a channel
// closed once every session it started has stopped. The caller cancels the
// link's context first.
func (l *anonymousLink) stopped() <-chan struct{} {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	done := make(chan struct{})
	go func() {
		l.runs.Wait()
		close(done)
	}()
	return done
}
