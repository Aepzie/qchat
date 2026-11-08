package client

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/coder/websocket"

	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/transport"
)

func proofOf(b byte) [protocol.AccessVerifierSize]byte {
	return [protocol.AccessVerifierSize]byte(bytes.Repeat([]byte{b}, protocol.AccessVerifierSize))
}

// sealedResponder answers sealed sends as a relay would, and fails the test
// on any frame an anonymous connection must not send.
func sealedResponder(ctx context.Context, t *testing.T, conn *websocket.Conn) func(protocol.Frame) bool {
	return func(f protocol.Frame) bool {
		switch f.Type {
		case protocol.TypeSealedSend:
			req, err := protocol.DecodeBody[protocol.SealedSend](f, protocol.TypeSealedSend)
			if err != nil {
				t.Errorf("SealedSend: %v", err)
				return false
			}
			if req.AccessProof[0] == 0 {
				return writeFrame(ctx, conn, protocol.TypeError, f.ID, protocol.ErrorBody{Code: protocol.ErrCodeNotFound, Message: "not found"}) == nil
			}
			return writeFrame(ctx, conn, protocol.TypeSendResult, f.ID, protocol.SendResult{Status: protocol.SendAccepted}) == nil
		case protocol.TypeSealedSendMulti:
			req, err := protocol.DecodeBody[protocol.SealedSendMulti](f, protocol.TypeSealedSendMulti)
			if err != nil {
				t.Errorf("SealedSendMulti: %v", err)
				return false
			}
			result := protocol.SendMultiResult{Status: protocol.SendAccepted}
			for _, entry := range req.Entries {
				if entry.AccessProof[0] == 0 {
					result.Failed = append(result.Failed, entry.To)
					result.Reasons = append(result.Reasons, protocol.ErrCodeNotFound)
				}
			}
			return writeFrame(ctx, conn, protocol.TypeSendMultiResult, f.ID, result) == nil
		default:
			t.Errorf("anonymous connection sent %v", f.Type)
			return false
		}
	}
}

func TestNewRejectsAnonymousAuthentication(t *testing.T) {
	var pin transport.Fingerprint
	pin[0] = 1
	for name, opts := range map[string]Options{
		"Auth":         {Addr: "127.0.0.1:1", Pin: pin, Anonymous: true, Auth: newFakeAuth()},
		"SkipRegister": {Addr: "127.0.0.1:1", Pin: pin, Anonymous: true, SkipRegister: true},
	} {
		if _, err := New(opts); err == nil {
			t.Errorf("%s: New accepted an anonymous session that authenticates", name)
		}
	}
}

func TestAnonymousSessionSealedSends(t *testing.T) {
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if welcome(ctx, t, conn) {
			serveFrames(ctx, conn, sealedResponder(ctx, t, conn))
		}
	})
	var dials atomic.Int32
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Anonymous: true, Dialer: dialer})
	runSession(t, s)
	seen := waitFor(t, s, "Connected", isState(Connected))
	for _, ev := range seen {
		if sc, ok := ev.(StateChanged); ok && sc.State == Authenticating {
			t.Fatal("anonymous session authenticated")
		}
	}
	if dials.Load() != 1 {
		t.Fatalf("custom dialer used %d times, want 1", dials.Load())
	}
	ctx := requestCtx(t)

	if err := s.SealedSend(ctx, [32]byte(idOf(2)), proofOf(7), []byte("sealed")); err != nil {
		t.Fatalf("SealedSend: %v", err)
	}
	err := s.SealedSend(ctx, [32]byte(idOf(2)), proofOf(0), []byte("sealed"))
	var remote *RemoteError
	if !errors.As(err, &remote) || remote.Code != protocol.ErrCodeNotFound {
		t.Fatalf("SealedSend with a wrong proof = %v, want NotFound", err)
	}
	entries := []protocol.SealedRecipient{
		{To: idOf(2), AccessProof: bytes.Repeat([]byte{7}, protocol.AccessVerifierSize)},
		{To: idOf(3), AccessProof: make([]byte, protocol.AccessVerifierSize)},
	}
	result, err := s.SealedSendMulti(ctx, entries, []byte("group"))
	if err != nil || len(result.Failed) != 1 || !bytes.Equal(result.Failed[0], idOf(3)) {
		t.Fatalf("SealedSendMulti = %+v, %v", result, err)
	}

	for _, req := range []struct {
		typ  protocol.FrameType
		body any
	}{
		{protocol.TypeKeyRequest, protocol.KeyRequest{ID: idOf(2)}},
		{protocol.TypeSend, protocol.Send{To: idOf(2), Payload: []byte("x")}},
		{protocol.TypeRegister, protocol.Register{Bundle: []byte("b")}},
		{protocol.TypeSetAccessKey, protocol.SetAccessKey{Verifier: idOf(1)}},
	} {
		if _, err := s.Request(ctx, req.typ, req.body); !errors.Is(err, ErrWrongSession) {
			t.Errorf("%v on an anonymous session = %v, want ErrWrongSession", req.typ, err)
		}
	}
	if err := s.Ack(1); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("Ack on an anonymous session = %v, want ErrNotConnected", err)
	}
	if err := s.SealedSend(ctx, [32]byte(idOf(2)), proofOf(7), []byte("still alive")); err != nil {
		t.Fatalf("SealedSend after refused requests: %v", err)
	}
}

func TestAuthenticatedSessionRefusesSealedSends(t *testing.T) {
	a := newFakeAuth()
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if !serveAuth(ctx, t, conn, a, authPlan{}) {
			return
		}
		serveFrames(ctx, conn, func(f protocol.Frame) bool {
			if f.Type != protocol.TypeSetAccessKey {
				t.Errorf("authenticated connection sent %v", f.Type)
				return false
			}
			req, err := protocol.DecodeBody[protocol.SetAccessKey](f, protocol.TypeSetAccessKey)
			if err != nil || !bytes.Equal(req.Verifier, idOf(5)) || !req.AllowUnidentified {
				t.Errorf("SetAccessKey = %+v, %v", req, err)
				return false
			}
			return writeFrame(ctx, conn, protocol.TypeAccessKeySet, f.ID, protocol.AccessKeySet{}) == nil
		})
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Auth: a})
	runSession(t, s)
	waitFor(t, s, "Connected", isState(Connected))
	ctx := requestCtx(t)

	if err := s.SealedSend(ctx, [32]byte(idOf(2)), proofOf(7), []byte("linkable")); !errors.Is(err, ErrWrongSession) {
		t.Fatalf("SealedSend on an authenticated session = %v, want ErrWrongSession", err)
	}
	if _, err := s.SealedSendMulti(ctx, []protocol.SealedRecipient{{To: idOf(2), AccessProof: idOf(7)}}, []byte("linkable")); !errors.Is(err, ErrWrongSession) {
		t.Fatalf("SealedSendMulti on an authenticated session = %v, want ErrWrongSession", err)
	}
	if err := s.SetAccessKey(ctx, [32]byte(idOf(5)), true); err != nil {
		t.Fatalf("SetAccessKey: %v", err)
	}
}

func TestAnonymousSessionRejectsDeliver(t *testing.T) {
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if !welcome(ctx, t, conn) {
			return
		}
		_ = writeFrame(ctx, conn, protocol.TypeDeliver, 0, protocol.Deliver{From: make([]byte, protocol.IDSize), Payload: []byte("x"), QueueID: 1})
		servePongs(ctx, conn, 0)
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Anonymous: true})
	runSession(t, s)
	seen := waitFor(t, s, "disconnect after Deliver", func(ev Event) bool {
		sc, ok := ev.(StateChanged)
		return ok && sc.State == Disconnected && errors.Is(sc.Err, ErrProtocolViolation)
	})
	for _, ev := range seen {
		if _, ok := ev.(Delivery); ok {
			t.Fatal("anonymous session reported a Delivery")
		}
	}
}

func TestSealedSendMultiRejectsForeignFailures(t *testing.T) {
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if !welcome(ctx, t, conn) {
			return
		}
		serveFrames(ctx, conn, func(f protocol.Frame) bool {
			result := protocol.SendMultiResult{Status: protocol.SendAccepted, Failed: [][]byte{idOf(9)}, Reasons: []protocol.ErrorCode{protocol.ErrCodeNotFound}}
			return writeFrame(ctx, conn, protocol.TypeSendMultiResult, f.ID, result) == nil
		})
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Anonymous: true})
	runSession(t, s)
	waitFor(t, s, "Connected", isState(Connected))
	_, err := s.SealedSendMulti(requestCtx(t), []protocol.SealedRecipient{{To: idOf(2), AccessProof: idOf(7)}}, []byte("x"))
	if !errors.Is(err, ErrProtocolViolation) {
		t.Fatalf("SealedSendMulti with a foreign failure = %v, want ErrProtocolViolation", err)
	}
}

func TestNewIsolationToken(t *testing.T) {
	a, err := NewIsolationToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewIsolationToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 2*isolationTokenSize || a == b {
		t.Fatalf("tokens %q and %q: want %d hex digits, fresh each time", a, b, 2*isolationTokenSize)
	}
	if _, err := hex.DecodeString(a); err != nil {
		t.Fatalf("token %q is not hex: %v", a, err)
	}
}

func TestDeliveryIsSealed(t *testing.T) {
	if !(Delivery{}).IsSealed() {
		t.Fatal("zero From is not sealed")
	}
	if (Delivery{From: [32]byte(idOf(1))}).IsSealed() {
		t.Fatal("identified delivery is sealed")
	}
}
