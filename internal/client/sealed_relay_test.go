package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/sealed"
	"github.com/craguS/qchat/internal/server"
	"github.com/craguS/qchat/internal/transport"
)

// identityAuth presents a real identity to the relay.
type identityAuth struct {
	ident  *identity.Identity
	bundle []byte
}

func (a identityAuth) ID() [32]byte   { return [32]byte(a.ident.ID()) }
func (a identityAuth) Bundle() []byte { return a.bundle }
func (a identityAuth) Invite() string { return "" }

func (a identityAuth) SignAuth(serverFP transport.Fingerprint, nonce, binding []byte) ([]byte, error) {
	return a.ident.SignAuth(serverFP, nonce, binding)
}

// startRelay runs a real relay with open registration on 127.0.0.1.
func startRelay(t *testing.T) (addr string, pin transport.Fingerprint) {
	t.Helper()
	certPEM, keyPEM, err := transport.GenerateServerIdentity([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pin, err = transport.FingerprintOfTLS(cert)
	if err != nil {
		t.Fatal(err)
	}
	cfg := server.DefaultConfig()
	cfg.Listen = "127.0.0.1:0"
	cfg.Registration = server.RegistrationOpen
	cfg.Database = filepath.Join(t.TempDir(), "qchat.db")
	srv, err := server.New(cfg, cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("relay did not stop")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for srv.Addr() == nil {
		if time.Now().After(deadline) {
			t.Fatal("relay did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return ln.Addr().String(), pin
}

func newIdentity(t *testing.T) (*identity.Identity, *identity.Bundle) {
	t.Helper()
	ident, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ident.Destroy)
	raw, err := ident.Bundle(1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := identity.ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ident, bundle
}

// TestSealedSendThroughRelay sends a sealed envelope from an anonymous
// session through a real relay to an authenticated session.
func TestSealedSendThroughRelay(t *testing.T) {
	addr, pin := startRelay(t)
	alice, _ := newIdentity(t)
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
		t.Fatalf("SetAccessKey: %v", err)
	}

	token, err := NewIsolationToken()
	if err != nil {
		t.Fatal(err)
	}
	var dialed atomic.Int32
	dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	sender := newTestSession(t, Options{Addr: addr, Pin: pin, Anonymous: true, Dialer: dialer})
	runSession(t, sender)
	waitFor(t, sender, "sender Connected", isState(Connected))
	if dialed.Load() != 1 || token == "" {
		t.Fatalf("anonymous session dialed %d times through its dialer", dialed.Load())
	}

	inner := []byte("pairwise envelope placeholder")
	envelope, err := sealed.Seal(alice.ID(), bobBundle, inner)
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.SealedSend(ctx, [32]byte(bob.ID()), key.Verifier(), envelope); err != nil {
		t.Fatalf("SealedSend: %v", err)
	}
	seen := waitFor(t, receiver, "Delivery", func(ev Event) bool { _, ok := ev.(Delivery); return ok })
	delivery := seen[len(seen)-1].(Delivery)
	if !delivery.IsSealed() || !bytes.Equal(delivery.Payload, envelope) {
		t.Fatalf("Delivery from %x, sealed %v", delivery.From, delivery.IsSealed())
	}
	opened, err := sealed.Open(bob, delivery.Payload)
	if err != nil || opened.ClaimedSender != alice.ID() || !bytes.Equal(opened.Inner, inner) {
		t.Fatalf("Open = %+v, %v", opened, err)
	}
	if err := receiver.Ack(delivery.QueueID); err != nil {
		t.Fatal(err)
	}

	wrong := key.Verifier()
	wrong[0] ^= 1
	err = sender.SealedSend(ctx, [32]byte(bob.ID()), wrong, envelope)
	var remote *RemoteError
	if !errors.As(err, &remote) || remote.Code != protocol.ErrCodeNotFound {
		t.Fatalf("SealedSend with a wrong proof = %v, want NotFound", err)
	}
	result, err := sender.SealedSendMulti(ctx, []protocol.SealedRecipient{
		{To: idBytes(bob.ID()), AccessProof: verifierBytes(key)},
	}, []byte("group envelope placeholder"))
	if err != nil || len(result.Failed) != 0 {
		t.Fatalf("SealedSendMulti = %+v, %v", result, err)
	}
	seen = waitFor(t, receiver, "group Delivery", func(ev Event) bool { _, ok := ev.(Delivery); return ok })
	if group := seen[len(seen)-1].(Delivery); !group.IsSealed() || string(group.Payload) != "group envelope placeholder" {
		t.Fatalf("group Delivery = %+v", group)
	}
}

func verifierBytes(key sealed.AccessKey) []byte {
	verifier := key.Verifier()
	return verifier[:]
}

func idBytes(id identity.ID) []byte { return id[:] }
