package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/craguS/qchat/internal/app"
	"github.com/craguS/qchat/internal/client"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/profile"
	"github.com/craguS/qchat/internal/protocol"
)

// lookupTimeout bounds the connection that looks up the relay's copy of the
// own bundle during recovery, including reconnects.
const lookupTimeout = 90 * time.Second

// databaseMissingHint explains a lost local database and how to continue.
func databaseMissingHint(dir string) string {
	return "qchat: the local database " + filepath.Join(dir, profile.DBFileName) + " is missing, but the key file is still there.\n" +
		"  If you have a backup of " + profile.DBFileName + ", copy it back into " + dir + " and start qchat again.\n" +
		"  Otherwise qchat can create a new, empty database for your identity. Your ID stays the same,\n" +
		"  but your contacts, their verifications, your display name and your message history are lost for good.\n" +
		"  To do that, start qchat again with --recover."
}

// recoveredNotice tells the user what recovery did not restore.
const recoveredNotice = "qchat: created a new, empty database for your identity. Contacts and message history were not restored:\n" +
	"  add your contacts again and verify their safety numbers once more."

// lookupOptions returns the options of the session that looks up the
// relay's copy of the own bundle, and whether the client package supports
// such a session. It must authenticate without registering: registering
// first would send a newly signed bundle, which the relay rejects as a
// conflict when it already holds one with that serial.
func lookupOptions(t target, auth client.Authenticator) (client.Options, bool) {
	return client.Options{Addr: t.addr, Pin: t.pin, Auth: auth, SkipRegister: true}, true
}

// recoverProfile creates a new, empty database for the profile in dir after
// its database was lost. It first looks up the bundle the relay holds for
// the identity, so that the recovered profile keeps registering exactly
// those bytes (see profile.Recover). Nothing in dir changes unless the
// lookup succeeds.
func recoverProfile(t target, dir string, passphrase []byte) (*profile.Profile, error) {
	relayBundle, err := fetchRelayBundle(t, dir, passphrase)
	if err != nil {
		return nil, err
	}
	return profile.Recover(dir, passphrase, relayBundle)
}

// fetchRelayBundle returns the bundle the relay holds for the identity of
// the profile in dir, or nil if it holds none.
//
// The profile package opens an identity only together with a database, and
// dir must stay untouched until the bundle is known, so the identity is
// opened from a copy of the key file in a temporary directory that is
// removed afterwards.
func fetchRelayBundle(t target, dir string, passphrase []byte) ([]byte, error) {
	scratch, err := os.MkdirTemp("", "qchat-recover-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)
	if err := copyKeyFile(dir, scratch); err != nil {
		return nil, err
	}
	probe, err := profile.Recover(scratch, passphrase, nil)
	if err != nil {
		return nil, err
	}
	defer probe.Close()

	opts, _ := lookupOptions(t, app.AuthOnly(probe.Identity))
	sess, err := client.New(opts)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	return lookupOwnBundle(ctx, sess, probe.Identity.ID())
}

// copyKeyFile copies the key file of the profile in srcDir into dstDir.
func copyKeyFile(srcDir, dstDir string) error {
	blob, err := os.ReadFile(filepath.Join(srcDir, profile.KeyFileName))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dstDir, profile.KeyFileName), blob, 0o600)
}

// relaySession is the part of *client.Session the bundle lookup uses.
type relaySession interface {
	Run(ctx context.Context) error
	Events() <-chan client.Event
	Request(ctx context.Context, t protocol.FrameType, body any) (protocol.Frame, error)
}

// lookupOwnBundle runs sess, which authenticates as id without registering,
// and returns the bundle the relay holds for id. It returns nil and no
// error if the relay holds none: it then answers the authentication attempt
// with NotFound. It gives up when ctx ends or the session stops for good.
func lookupOwnBundle(ctx context.Context, sess relaySession, id identity.ID) ([]byte, error) {
	runCtx, cancel := context.WithCancel(ctx)
	events := sess.Events()
	runDone := make(chan error, 1)
	go func() { runDone <- sess.Run(runCtx) }()
	defer func() {
		cancel()
		for range events {
		}
	}()

	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return nil, unreachable(ctx, lastErr)
		case ev, ok := <-events:
			if !ok {
				runErr := <-runDone
				if ctx.Err() != nil {
					return nil, unreachable(ctx, lastErr)
				}
				return nil, fmt.Errorf("cannot look up your identity on the server: %w", runErr)
			}
			switch e := ev.(type) {
			case client.Authenticated:
				return requestOwnBundle(ctx, sess, id)
			case client.ServerError:
				if e.Code == protocol.ErrCodeNotFound {
					return nil, nil
				}
			case client.StateChanged:
				if e.Err != nil {
					lastErr = e.Err
				}
			}
		}
	}
}

// unreachable reports that the lookup ran out of time, with the last
// connection error if there was one.
func unreachable(ctx context.Context, lastErr error) error {
	if lastErr != nil {
		return fmt.Errorf("cannot reach the server: %w", lastErr)
	}
	return fmt.Errorf("cannot reach the server: %w", ctx.Err())
}

// requestOwnBundle asks the relay for the bundle of id over an
// authenticated session. An empty answer is an error, because an empty
// bundle means "none held" to profile.Recover.
func requestOwnBundle(ctx context.Context, sess relaySession, id identity.ID) ([]byte, error) {
	frame, err := sess.Request(ctx, protocol.TypeKeyRequest, protocol.KeyRequest{ID: id[:]})
	if err != nil {
		return nil, fmt.Errorf("cannot look up your identity on the server: %w", err)
	}
	resp, err := protocol.DecodeBody[protocol.KeyResponse](frame, protocol.TypeKeyResponse)
	if err != nil {
		return nil, fmt.Errorf("unexpected answer from the server: %w", err)
	}
	if len(resp.Bundle) == 0 {
		return nil, errors.New("the server returned an empty identity bundle")
	}
	return resp.Bundle, nil
}
