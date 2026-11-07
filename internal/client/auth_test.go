package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/transport"
)

// fakeAuth is an Authenticator whose signature is "sig:" followed by the
// nonce, so the fake server can check it.
type fakeAuth struct {
	id     [32]byte
	bundle []byte
	invite string

	mu          sync.Mutex
	signFP      transport.Fingerprint
	signBinding []byte
}

func newFakeAuth() *fakeAuth {
	a := &fakeAuth{bundle: []byte("bundle-bytes"), invite: "INVITE-1"}
	for i := range a.id {
		a.id[i] = byte(i + 1)
	}
	return a
}

func (a *fakeAuth) ID() [32]byte   { return a.id }
func (a *fakeAuth) Bundle() []byte { return a.bundle }
func (a *fakeAuth) Invite() string { return a.invite }

func (a *fakeAuth) SignAuth(serverFP transport.Fingerprint, nonce, binding []byte) ([]byte, error) {
	a.mu.Lock()
	a.signFP = serverFP
	a.signBinding = binding
	a.mu.Unlock()
	return expectedSig(nonce), nil
}

func expectedSig(nonce []byte) []byte { return append([]byte("sig:"), nonce...) }

// testNonce is the challenge nonce the fake server sends.
var testNonce = bytes.Repeat([]byte{0xab}, protocol.NonceSize)

// authStep is how the fake server answers one authentication step.
type authStep struct {
	// code, if non-zero, is sent as an Error frame instead of the success
	// response.
	code protocol.ErrorCode
}

// authPlan lists the answers to Register, AuthBegin and AuthProof.
type authPlan struct {
	register, begin, proof authStep
}

// serveAuth runs the Welcome and authentication exchange, checking every
// client frame against a. It reports whether the connection is now
// authenticated.
func serveAuth(ctx context.Context, t *testing.T, conn *websocket.Conn, a *fakeAuth, plan authPlan) bool {
	if !welcome(ctx, t, conn) {
		return false
	}
	f, err := readFrame(ctx, conn)
	if err != nil {
		return false
	}
	reg, err := protocol.DecodeBody[protocol.Register](f, protocol.TypeRegister)
	if err != nil {
		t.Errorf("expected Register: %v", err)
		return false
	}
	if !bytes.Equal(reg.Bundle, a.bundle) || reg.Invite != a.invite {
		t.Errorf("Register = %+v", reg)
	}
	if !answer(ctx, conn, f.ID, plan.register, protocol.TypeRegistered, protocol.Registered{}) {
		return false
	}
	if f, err = readFrame(ctx, conn); err != nil {
		return false
	}
	begin, err := protocol.DecodeBody[protocol.AuthBegin](f, protocol.TypeAuthBegin)
	if err != nil {
		t.Errorf("expected AuthBegin: %v", err)
		return false
	}
	if !bytes.Equal(begin.ID, a.id[:]) {
		t.Errorf("AuthBegin ID = %x", begin.ID)
	}
	if !answer(ctx, conn, f.ID, plan.begin, protocol.TypeAuthChallenge, protocol.AuthChallenge{Nonce: testNonce}) {
		return false
	}
	if f, err = readFrame(ctx, conn); err != nil {
		return false
	}
	proof, err := protocol.DecodeBody[protocol.AuthProof](f, protocol.TypeAuthProof)
	if err != nil {
		t.Errorf("expected AuthProof: %v", err)
		return false
	}
	if !bytes.Equal(proof.Sig, expectedSig(testNonce)) {
		t.Errorf("AuthProof sig = %q", proof.Sig)
	}
	return answer(ctx, conn, f.ID, plan.proof, protocol.TypeAuthOK, protocol.AuthOK{})
}

// answer sends the success response, or an Error frame if step says so. It
// reports whether the success response was sent.
func answer[T any](ctx context.Context, conn *websocket.Conn, id uint64, step authStep, typ protocol.FrameType, body T) bool {
	if step.code != 0 {
		_ = writeFrame(ctx, conn, protocol.TypeError, id, protocol.ErrorBody{Code: step.code, Message: "denied"})
		return false
	}
	return writeFrame(ctx, conn, typ, id, body) == nil
}

// serveFrames answers pings and passes every other frame to handle until the
// connection ends or handle returns false.
func serveFrames(ctx context.Context, conn *websocket.Conn, handle func(protocol.Frame) bool) {
	for {
		f, err := readFrame(ctx, conn)
		if err != nil {
			return
		}
		if f.Type == protocol.TypePing {
			ping, err := protocol.DecodeBody[protocol.Ping](f, protocol.TypePing)
			if err != nil || writeFrame(ctx, conn, protocol.TypePong, f.ID, protocol.Pong(ping)) != nil {
				return
			}
			continue
		}
		if !handle(f) {
			return
		}
	}
}

// keyResponder answers KeyRequest with the requested ID as the bundle,
// NotFound for an all-zero ID, and Send with Delivered.
func keyResponder(ctx context.Context, t *testing.T, conn *websocket.Conn) func(protocol.Frame) bool {
	return func(f protocol.Frame) bool {
		switch f.Type {
		case protocol.TypeKeyRequest:
			req, err := protocol.DecodeBody[protocol.KeyRequest](f, protocol.TypeKeyRequest)
			if err != nil {
				t.Errorf("KeyRequest: %v", err)
				return false
			}
			if bytes.Equal(req.ID, make([]byte, protocol.IDSize)) {
				return writeFrame(ctx, conn, protocol.TypeError, f.ID, protocol.ErrorBody{Code: protocol.ErrCodeNotFound, Message: "unknown"}) == nil
			}
			return writeFrame(ctx, conn, protocol.TypeKeyResponse, f.ID, protocol.KeyResponse{Bundle: req.ID}) == nil
		case protocol.TypeSend:
			return writeFrame(ctx, conn, protocol.TypeSendResult, f.ID, protocol.SendResult{Status: protocol.SendDelivered}) == nil
		default:
			t.Errorf("unexpected %v frame", f.Type)
			return false
		}
	}
}

func idOf(b byte) []byte { return bytes.Repeat([]byte{b}, protocol.IDSize) }

func keyRequest(ctx context.Context, s *Session, id []byte) ([]byte, error) {
	f, err := s.Request(ctx, protocol.TypeKeyRequest, protocol.KeyRequest{ID: id})
	if err != nil {
		return nil, err
	}
	resp, err := protocol.DecodeBody[protocol.KeyResponse](f, protocol.TypeKeyResponse)
	if err != nil {
		return nil, err
	}
	return resp.Bundle, nil
}

func requestCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestAuthenticateFlow(t *testing.T) {
	a := newFakeAuth()
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if serveAuth(ctx, t, conn, a, authPlan{}) {
			servePongs(ctx, conn, 0)
		}
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Auth: a})
	runSession(t, s)

	seen := waitFor(t, s, "Connected", isState(Connected))
	var order []string
	for _, ev := range seen {
		switch e := ev.(type) {
		case StateChanged:
			order = append(order, e.State.String())
		case Authenticated:
			if e.ID != a.id {
				t.Errorf("Authenticated.ID = %x", e.ID)
			}
			order = append(order, "auth")
		}
	}
	if got, want := fmt.Sprint(order), "[connecting authenticating auth connected]"; got != want {
		t.Fatalf("events = %s, want %s", got, want)
	}
	a.mu.Lock()
	fp, binding := a.signFP, a.signBinding
	a.mu.Unlock()
	if fp != fs.pin {
		t.Errorf("SignAuth fingerprint = %v, want the pin", fp)
	}
	if len(binding) != transport.AuthBindingSize || !bytes.Equal(binding, fs.lastBinding()) {
		t.Error("SignAuth channel binding differs from the server's binding of the connection")
	}
	if _, ok := s.Info(); !ok {
		t.Error("Info reports no connection")
	}
}

func TestRegistrationDeniedIsPermanent(t *testing.T) {
	for _, code := range []protocol.ErrorCode{protocol.ErrCodeRegistrationDenied, protocol.ErrCodeConflict} {
		t.Run(code.String(), func(t *testing.T) {
			a := newFakeAuth()
			fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
				serveAuth(ctx, t, conn, a, authPlan{register: authStep{code: code}})
				_, _, _ = conn.Read(ctx)
			})
			s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Auth: a})
			_, res := runSession(t, s)

			seen := waitFor(t, s, "Failed", isState(Failed))
			var denied *RegistrationDenied
			for _, ev := range seen {
				if d, ok := ev.(RegistrationDenied); ok {
					denied = &d
				}
			}
			if denied == nil || denied.Code != code || denied.Message != "denied" {
				t.Fatalf("RegistrationDenied = %+v; saw %v", denied, seen)
			}
			if err := res.wait(t); !errors.Is(err, ErrAuthFailed) {
				t.Fatalf("Run = %v, want ErrAuthFailed", err)
			}
			if n := fs.conns.Load(); n != 1 {
				t.Errorf("%d connections, want 1", n)
			}
		})
	}
}

func TestUnauthorizedIsPermanent(t *testing.T) {
	a := newFakeAuth()
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		serveAuth(ctx, t, conn, a, authPlan{proof: authStep{code: protocol.ErrCodeUnauthorized}})
		_, _, _ = conn.Read(ctx)
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Auth: a})
	_, res := runSession(t, s)

	seen := waitFor(t, s, "Failed", isState(Failed))
	err := seen[len(seen)-1].(StateChanged).Err
	var remote *RemoteError
	if !errors.Is(err, ErrAuthFailed) || !errors.As(err, &remote) || remote.Code != protocol.ErrCodeUnauthorized {
		t.Fatalf("Failed.Err = %v", err)
	}
	for _, ev := range seen {
		if _, ok := ev.(RegistrationDenied); ok {
			t.Errorf("unexpected RegistrationDenied")
		}
	}
	if err := res.wait(t); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Run = %v", err)
	}
	if n := fs.conns.Load(); n != 1 {
		t.Errorf("%d connections, want 1", n)
	}
}

func TestRateLimitedDuringAuthRetries(t *testing.T) {
	a := newFakeAuth()
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		plan := authPlan{}
		if n == 1 {
			plan.begin = authStep{code: protocol.ErrCodeRateLimited}
		}
		if serveAuth(ctx, t, conn, a, plan) {
			servePongs(ctx, conn, 0)
		}
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Auth: a})
	runSession(t, s)

	seen := waitFor(t, s, "Disconnected", isState(Disconnected))
	var remote *RemoteError
	if err := seen[len(seen)-1].(StateChanged).Err; !errors.As(err, &remote) || remote.Code != protocol.ErrCodeRateLimited || errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Disconnected.Err = %v", err)
	}
	waitFor(t, s, "Connected", isState(Connected))
}

func TestRequestRoundTrip(t *testing.T) {
	a := newFakeAuth()
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if serveAuth(ctx, t, conn, a, authPlan{}) {
			serveFrames(ctx, conn, keyResponder(ctx, t, conn))
		}
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Auth: a})
	runSession(t, s)
	waitFor(t, s, "Connected", isState(Connected))
	ctx := requestCtx(t)

	bundle, err := keyRequest(ctx, s, idOf(7))
	if err != nil || !bytes.Equal(bundle, idOf(7)) {
		t.Fatalf("KeyRequest = %x, %v", bundle, err)
	}
	f, err := s.Request(ctx, protocol.TypeSend, protocol.Send{To: idOf(7), Payload: []byte("ciphertext")})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	result, err := protocol.DecodeBody[protocol.SendResult](f, protocol.TypeSendResult)
	if err != nil || result.Status != protocol.SendDelivered {
		t.Fatalf("SendResult = %+v, %v", result, err)
	}

	_, err = keyRequest(ctx, s, make([]byte, protocol.IDSize))
	var remote *RemoteError
	if !errors.As(err, &remote) || remote.Code != protocol.ErrCodeNotFound || remote.Message != "unknown" {
		t.Fatalf("KeyRequest for unknown ID = %v, want NotFound", err)
	}
	if bundle, err := keyRequest(ctx, s, idOf(8)); err != nil || !bytes.Equal(bundle, idOf(8)) {
		t.Fatalf("KeyRequest after error = %x, %v", bundle, err)
	}

	if _, err := s.Request(ctx, protocol.TypePing, protocol.Ping{}); err == nil {
		t.Error("Request accepted a Ping")
	}
}

func TestRequestBeforeAuthentication(t *testing.T) {
	var pin transport.Fingerprint
	pin[0] = 1
	s := newTestSession(t, Options{Addr: "127.0.0.1:1", Pin: pin, Auth: newFakeAuth()})
	_, err := s.Request(context.Background(), protocol.TypeKeyRequest, protocol.KeyRequest{ID: idOf(1)})
	if !errors.Is(err, ErrNotConnected) {
		t.Fatalf("Request = %v, want ErrNotConnected", err)
	}

	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if welcome(ctx, t, conn) {
			servePongs(ctx, conn, 0)
		}
	})
	plain := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin})
	runSession(t, plain)
	waitFor(t, plain, "Connected", isState(Connected))
	_, err = plain.Request(context.Background(), protocol.TypeKeyRequest, protocol.KeyRequest{ID: idOf(1)})
	if !errors.Is(err, ErrNotConnected) {
		t.Fatalf("Request without Auth = %v, want ErrNotConnected", err)
	}
}

func TestPendingRequestFailsOnDisconnect(t *testing.T) {
	a := newFakeAuth()
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if !serveAuth(ctx, t, conn, a, authPlan{}) {
			return
		}
		serveFrames(ctx, conn, func(f protocol.Frame) bool {
			_ = conn.Close(websocket.StatusGoingAway, "")
			return false
		})
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Auth: a})
	runSession(t, s)
	waitFor(t, s, "Connected", isState(Connected))

	_, err := s.Request(requestCtx(t), protocol.TypeSend, protocol.Send{To: idOf(2), Payload: []byte("x")})
	if !errors.Is(err, ErrConnectionLost) {
		t.Fatalf("Request = %v, want ErrConnectionLost", err)
	}
}

func TestConcurrentRequestsCorrelate(t *testing.T) {
	const count = 8
	a := newFakeAuth()
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if !serveAuth(ctx, t, conn, a, authPlan{}) {
			return
		}
		var held []protocol.Frame
		serveFrames(ctx, conn, func(f protocol.Frame) bool {
			held = append(held, f)
			if len(held) < count {
				return true
			}
			respond := keyResponder(ctx, t, conn)
			for i := len(held) - 1; i >= 0; i-- {
				if !respond(held[i]) {
					return false
				}
			}
			held = nil
			return true
		})
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Auth: a})
	runSession(t, s)
	waitFor(t, s, "Connected", isState(Connected))
	ctx := requestCtx(t)

	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := range count {
		wg.Add(1)
		go func(b byte) {
			defer wg.Done()
			bundle, err := keyRequest(ctx, s, idOf(b))
			if err == nil && !bytes.Equal(bundle, idOf(b)) {
				err = fmt.Errorf("request %d got bundle %x", b, bundle[:1])
			}
			errs <- err
		}(byte(i + 1))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

func TestDeliverAndUnknownResponses(t *testing.T) {
	a := newFakeAuth()
	fs := startFakeServer(t, func(ctx context.Context, conn *websocket.Conn, n int) {
		if !serveAuth(ctx, t, conn, a, authPlan{}) {
			return
		}
		if writeFrame(ctx, conn, protocol.TypeKeyResponse, 9999, protocol.KeyResponse{Bundle: []byte("stray")}) != nil {
			return
		}
		if writeFrame(ctx, conn, protocol.TypeSendResult, 0, protocol.SendResult{Status: protocol.SendDelivered}) != nil {
			return
		}
		if writeFrame(ctx, conn, protocol.TypeDeliver, 0, protocol.Deliver{From: idOf(9), Payload: []byte("hello")}) != nil {
			return
		}
		serveFrames(ctx, conn, keyResponder(ctx, t, conn))
	})
	s := newTestSession(t, Options{Addr: fs.addr, Pin: fs.pin, Auth: a})
	runSession(t, s)

	seen := waitFor(t, s, "Delivery", func(ev Event) bool { _, ok := ev.(Delivery); return ok })
	for _, ev := range seen {
		if sc, ok := ev.(StateChanged); ok && sc.State == Disconnected {
			t.Fatalf("disconnected before Delivery: %v", sc.Err)
		}
	}
	d := seen[len(seen)-1].(Delivery)
	if d.From != [32]byte(idOf(9)) || string(d.Payload) != "hello" {
		t.Fatalf("Delivery = %+v", d)
	}
	if bundle, err := keyRequest(requestCtx(t), s, idOf(3)); err != nil || !bytes.Equal(bundle, idOf(3)) {
		t.Fatalf("KeyRequest after stray responses = %x, %v", bundle, err)
	}
}

func TestEventQueueKeepsDeliveries(t *testing.T) {
	q := &eventQueue{out: make(chan Event), notify: make(chan struct{}, 1)}
	for range maxPendingEvents {
		q.push(ServerError{})
	}
	q.push(Delivery{Payload: []byte("a")})
	q.push(Authenticated{})
	q.push(RegistrationDenied{})
	var kept int
	for _, ev := range q.pending {
		switch ev.(type) {
		case Delivery, Authenticated, RegistrationDenied:
			kept++
		}
	}
	if kept != 3 {
		t.Fatalf("kept %d critical events, want 3", kept)
	}
}
