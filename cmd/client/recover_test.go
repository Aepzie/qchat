package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Aepzie/qchat/internal/client"
	"github.com/Aepzie/qchat/internal/identity"
	"github.com/Aepzie/qchat/internal/profile"
	"github.com/Aepzie/qchat/internal/protocol"
)

// fakeRelay is a relaySession that replays scripted events.
type fakeRelay struct {
	events    chan client.Event
	runErr    error
	frame     protocol.Frame
	reqErr    error
	requested []protocol.KeyRequest
}

func newFakeRelay(events ...client.Event) *fakeRelay {
	ch := make(chan client.Event, len(events))
	for _, ev := range events {
		ch <- ev
	}
	return &fakeRelay{events: ch}
}

func (f *fakeRelay) Run(ctx context.Context) error {
	defer close(f.events)
	if f.runErr != nil {
		return f.runErr
	}
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeRelay) Events() <-chan client.Event { return f.events }

func (f *fakeRelay) Request(_ context.Context, t protocol.FrameType, body any) (protocol.Frame, error) {
	if t != protocol.TypeKeyRequest {
		return protocol.Frame{}, errors.New("unexpected request type")
	}
	f.requested = append(f.requested, body.(protocol.KeyRequest))
	return f.frame, f.reqErr
}

func keyResponse(t *testing.T, raw []byte) protocol.Frame {
	t.Helper()
	f, err := protocol.NewFrame(protocol.TypeKeyResponse, 7, protocol.KeyResponse{Bundle: raw})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func lookupContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestLookupOwnBundleAfterAuthentication(t *testing.T) {
	id := identity.ID{1, 2, 3}
	relay := newFakeRelay(client.StateChanged{State: client.Connecting}, client.Authenticated{ID: id})
	relay.frame = keyResponse(t, []byte("bundle bytes"))
	got, err := lookupOwnBundle(lookupContext(t), relay, id)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "bundle bytes" {
		t.Fatalf("bundle = %q", got)
	}
	if len(relay.requested) != 1 || !bytes.Equal(relay.requested[0].ID, id[:]) {
		t.Fatalf("requests = %v", relay.requested)
	}
}

func TestLookupOwnBundleNotRegistered(t *testing.T) {
	relay := newFakeRelay(client.ServerError{Code: protocol.ErrCodeNotFound})
	got, err := lookupOwnBundle(lookupContext(t), relay, identity.ID{1})
	if err != nil || got != nil {
		t.Fatalf("got %q, %v; want nil, nil", got, err)
	}
	if len(relay.requested) != 0 {
		t.Fatal("KeyRequest sent without authentication")
	}
}

func TestLookupOwnBundleFailures(t *testing.T) {
	t.Run("session stops", func(t *testing.T) {
		relay := newFakeRelay(client.ServerError{Code: protocol.ErrCodeUnauthorized})
		relay.runErr = client.ErrAuthFailed
		_, err := lookupOwnBundle(lookupContext(t), relay, identity.ID{1})
		if !errors.Is(err, client.ErrAuthFailed) {
			t.Fatalf("err = %v, want ErrAuthFailed", err)
		}
	})
	t.Run("wrong answer", func(t *testing.T) {
		relay := newFakeRelay(client.Authenticated{})
		f, err := protocol.NewFrame(protocol.TypeSendResult, 7, protocol.SendResult{Status: protocol.SendDelivered})
		if err != nil {
			t.Fatal(err)
		}
		relay.frame = f
		if _, err := lookupOwnBundle(lookupContext(t), relay, identity.ID{1}); err == nil {
			t.Fatal("wrong answer accepted")
		}
	})
	t.Run("request fails", func(t *testing.T) {
		relay := newFakeRelay(client.Authenticated{})
		relay.reqErr = client.ErrNotConnected
		if _, err := lookupOwnBundle(lookupContext(t), relay, identity.ID{1}); !errors.Is(err, client.ErrNotConnected) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("timeout keeps last error", func(t *testing.T) {
		relay := newFakeRelay(client.StateChanged{State: client.Connecting, Err: client.ErrHandshakeTimeout})
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if _, err := lookupOwnBundle(ctx, relay, identity.ID{1}); !errors.Is(err, client.ErrHandshakeTimeout) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestDatabaseMissingHint(t *testing.T) {
	dir := filepath.Join("some", "profile")
	hint := databaseMissingHint(dir)
	for _, want := range []string{filepath.Join(dir, profile.DBFileName), "backup", "contacts", "--recover"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint lacks %q:\n%s", want, hint)
		}
	}
}

func TestRecoverFlag(t *testing.T) {
	if flags(t).recoverDB {
		t.Fatal("recovery on by default")
	}
	if !flags(t, "--recover").recoverDB {
		t.Fatal("--recover not parsed")
	}
}

func TestLookupSkipsRegistration(t *testing.T) {
	opts, ok := lookupOptions(target{}, nil)
	if !ok || !opts.SkipRegister {
		t.Fatalf("lookupOptions = %+v, %v; want SkipRegister and supported", opts, ok)
	}
}
