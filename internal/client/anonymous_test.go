package client

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Aepzie/qchat/internal/protocol"
	"github.com/Aepzie/qchat/internal/sealed"
	"github.com/Aepzie/qchat/internal/transport"
)

func TestAnonymousSessionDoesNotReconnect(t *testing.T) {
	var conns atomic.Int32
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		conns.Add(1)
		if welcome(ctx, t, conn) {
			conn.Close(websocket.StatusGoingAway, "")
		}
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Anonymous: true})
	_, res := runSession(t, s)
	seen := waitFor(t, s, "Failed", isState(Failed))
	ended := seen[len(seen)-1].(StateChanged)
	if !errors.Is(ended.Err, ErrAnonymousSessionEnded) {
		t.Fatalf("Failed with %v, want ErrAnonymousSessionEnded", ended.Err)
	}
	select {
	case <-res.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the anonymous connection ended")
	}
	if !errors.Is(res.err, ErrAnonymousSessionEnded) {
		t.Fatalf("Run = %v, want ErrAnonymousSessionEnded", res.err)
	}
	time.Sleep(4 * s.backoffMax)
	if n := conns.Load(); n != 1 {
		t.Fatalf("anonymous session connected %d times, want 1", n)
	}
	if _, err := s.AnonKeyRequest(requestCtx(t), [32]byte(idOf(2)), proofOf(7)); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("AnonKeyRequest after the end = %v, want ErrNotConnected", err)
	}
}

func TestAnonymousSessionEndsOnFailedDial(t *testing.T) {
	var pin transport.Fingerprint
	pin[0] = 1
	s := newTestSession(t, Options{Addr: "127.0.0.1:1", Pin: pin, Anonymous: true})
	_, res := runSession(t, s)
	waitFor(t, s, "Failed", isState(Failed))
	<-res.done
	if !errors.Is(res.err, ErrAnonymousSessionEnded) {
		t.Fatalf("Run = %v, want ErrAnonymousSessionEnded", res.err)
	}
}

func TestAnonymousReconnectOptIn(t *testing.T) {
	var conns atomic.Int32
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		conns.Add(1)
		if welcome(ctx, t, conn) {
			conn.Close(websocket.StatusGoingAway, "")
		}
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Anonymous: true, AnonymousReconnect: true})
	runSession(t, s)
	seen := waitFor(t, s, "second attempt", func(ev Event) bool {
		sc, ok := ev.(StateChanged)
		return ok && sc.State == Connected && conns.Load() >= 2
	})
	for _, ev := range seen {
		if sc, ok := ev.(StateChanged); ok && sc.State == Failed {
			t.Fatalf("session with AnonymousReconnect failed: %v", sc.Err)
		}
	}
}

func TestNewRejectsReconnectWithoutAnonymous(t *testing.T) {
	var pin transport.Fingerprint
	pin[0] = 1
	if _, err := New(Options{Addr: "127.0.0.1:1", Pin: pin, AnonymousReconnect: true}); err == nil {
		t.Fatal("New accepted AnonymousReconnect without Anonymous")
	}
}

// lookupResponder answers anonymous lookups as a relay would: proof 0 is
// refused, any other proof granted.
func lookupResponder(ctx context.Context, t *testing.T, conn *websocket.Conn) func(protocol.Frame) bool {
	notFound := func(id uint64) bool {
		return writeFrame(ctx, conn, protocol.TypeError, id, protocol.ErrorBody{Code: protocol.ErrCodeNotFound, Message: "not found"}) == nil
	}
	return func(f protocol.Frame) bool {
		switch f.Type {
		case protocol.TypeKeyRequest:
			req, err := protocol.DecodeBody[protocol.KeyRequest](f, protocol.TypeKeyRequest)
			if err != nil || req.AccessProof == nil {
				t.Errorf("KeyRequest without proof: %+v, %v", req, err)
				return false
			}
			if req.AccessProof[0] == 0 {
				return notFound(f.ID)
			}
			return writeFrame(ctx, conn, protocol.TypeKeyResponse, f.ID, protocol.KeyResponse{Bundle: req.ID}) == nil
		case protocol.TypePrekeyRequest:
			req, err := protocol.DecodeBody[protocol.PrekeyRequest](f, protocol.TypePrekeyRequest)
			if err != nil || req.AccessProof == nil {
				t.Errorf("PrekeyRequest without proof: %+v, %v", req, err)
				return false
			}
			if req.AccessProof[0] == 0 {
				return notFound(f.ID)
			}
			resp := protocol.PrekeyResponse{Bundle: req.ID, SignedPrekey: []byte("spk"), OneTimePrekey: req.AccessProof}
			return writeFrame(ctx, conn, protocol.TypePrekeyResponse, f.ID, resp) == nil
		default:
			t.Errorf("anonymous connection sent %v", f.Type)
			return false
		}
	}
}

func TestAnonymousLookups(t *testing.T) {
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if welcome(ctx, t, conn) {
			serveFrames(ctx, conn, lookupResponder(ctx, t, conn))
		}
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Anonymous: true})
	runSession(t, s)
	waitFor(t, s, "Connected", isState(Connected))
	ctx := requestCtx(t)

	bundle, err := s.AnonKeyRequest(ctx, [32]byte(idOf(4)), proofOf(7))
	if err != nil || !bytes.Equal(bundle, idOf(4)) {
		t.Fatalf("AnonKeyRequest = %x, %v", bundle, err)
	}
	prekeys, err := s.AnonPrekeyRequest(ctx, [32]byte(idOf(4)), proofOf(7))
	if err != nil || !bytes.Equal(prekeys.Bundle, idOf(4)) || !bytes.Equal(prekeys.OneTimePrekey, bytes.Repeat([]byte{7}, protocol.AccessVerifierSize)) {
		t.Fatalf("AnonPrekeyRequest = %+v, %v", prekeys, err)
	}
	var remote *RemoteError
	if _, err := s.AnonKeyRequest(ctx, [32]byte(idOf(4)), proofOf(0)); !errors.As(err, &remote) || remote.Code != protocol.ErrCodeNotFound {
		t.Fatalf("AnonKeyRequest with a refused proof = %v, want NotFound", err)
	}
	if _, err := s.AnonPrekeyRequest(ctx, [32]byte(idOf(4)), proofOf(0)); !errors.As(err, &remote) || remote.Code != protocol.ErrCodeNotFound {
		t.Fatalf("AnonPrekeyRequest with a refused proof = %v, want NotFound", err)
	}
	if _, err := s.Request(ctx, protocol.TypeKeyRequest, &protocol.KeyRequest{ID: idOf(4), AccessProof: idOf(7)}); err != nil {
		t.Fatalf("Request with a pointer body: %v", err)
	}
}

func TestAuthenticatedSessionRefusesAnonymousLookups(t *testing.T) {
	a := newFakeAuth()
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if !serveAuth(ctx, t, conn, a, authPlan{}) {
			return
		}
		serveFrames(ctx, conn, func(f protocol.Frame) bool {
			t.Errorf("authenticated connection sent %v", f.Type)
			return false
		})
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Auth: a})
	runSession(t, s)
	waitFor(t, s, "Connected", isState(Connected))
	ctx := requestCtx(t)
	if _, err := s.AnonKeyRequest(ctx, [32]byte(idOf(4)), proofOf(7)); !errors.Is(err, ErrWrongSession) {
		t.Fatalf("AnonKeyRequest on an authenticated session = %v, want ErrWrongSession", err)
	}
	if _, err := s.AnonPrekeyRequest(ctx, [32]byte(idOf(4)), proofOf(7)); !errors.Is(err, ErrWrongSession) {
		t.Fatalf("AnonPrekeyRequest on an authenticated session = %v, want ErrWrongSession", err)
	}
	if _, err := s.Request(ctx, protocol.TypePrekeyRequest, &protocol.PrekeyRequest{ID: idOf(4), AccessProof: idOf(7)}); !errors.Is(err, ErrWrongSession) {
		t.Fatalf("PrekeyRequest with a proof on an authenticated session = %v, want ErrWrongSession", err)
	}
}

// TestAnonymousLookupsThroughRelay fetches a bundle anonymously from a
// real relay.
func TestAnonymousLookupsThroughRelay(t *testing.T) {
	addr, pin := startRelay(t)
	bob, bobBundle := newIdentity(t)
	receiver := newTestSession(t, Options{Addr: addr, Pin: pin, Auth: identityAuth{ident: bob, bundle: bobBundle.Raw}})
	runSession(t, receiver)
	waitFor(t, receiver, "receiver Connected", isState(Connected))
	ctx := requestCtx(t)
	key, err := sealed.NewAccessKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.SetAccessKey(ctx, key.Verifier(), false); err != nil {
		t.Fatal(err)
	}

	anon := newTestSession(t, Options{Addr: addr, Pin: pin, Anonymous: true})
	runSession(t, anon)
	waitFor(t, anon, "anonymous Connected", isState(Connected))
	raw, err := anon.AnonKeyRequest(ctx, [32]byte(bob.ID()), key.Verifier())
	if err != nil || !bytes.Equal(raw, bobBundle.Raw) {
		t.Fatalf("AnonKeyRequest = %d bytes, %v", len(raw), err)
	}
	wrong := key.Verifier()
	wrong[3] ^= 1
	var remote *RemoteError
	if _, err := anon.AnonKeyRequest(ctx, [32]byte(bob.ID()), wrong); !errors.As(err, &remote) || remote.Code != protocol.ErrCodeNotFound {
		t.Fatalf("AnonKeyRequest with a wrong proof = %v, want NotFound", err)
	}
	if _, err := anon.AnonPrekeyRequest(ctx, [32]byte(bob.ID()), key.Verifier()); !errors.As(err, &remote) || remote.Code != protocol.ErrCodeNotFound {
		t.Fatalf("AnonPrekeyRequest without uploaded prekeys = %v, want NotFound", err)
	}
	if err := anon.SealedSend(ctx, [32]byte(bob.ID()), key.Verifier(), []byte("after lookups")); err != nil {
		t.Fatalf("SealedSend after lookups: %v", err)
	}
}
