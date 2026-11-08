package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/craguS/qchat/internal/crypto/sealbox"
	"github.com/craguS/qchat/internal/handshake"
	"github.com/craguS/qchat/internal/prekey"
	"github.com/craguS/qchat/internal/protocol"
	"github.com/craguS/qchat/internal/store/clientdb"
)

// Prekey policy of docs/design/phase-3-forward-secrecy.md, section
// "Prekeys". The signed prekey times are those of package handshake: a new
// signed prekey replaces the active one after SignedPrekeyRotation (7 days),
// is valid for SignedPrekeyLifetime (9 days), and its private key is kept
// for SignedPrekeyRetention (16 days) after creation, so that a first
// message queued on the relay just before expiry can still be read; then
// PruneRetiredPrekeys deletes it.
const (
	signedPrekeyRotation  = handshake.SignedPrekeyRotation
	signedPrekeyLifetime  = handshake.SignedPrekeyLifetime
	signedPrekeyRetention = handshake.SignedPrekeyRetention
	// oneTimePrekeyPool is the number of one-time prekeys the relay is
	// topped up to.
	oneTimePrekeyPool = 50
	// oneTimePrekeyLow is the relay count below which the pool is topped up.
	oneTimePrekeyLow = 20
	// prekeyMaintenanceInterval is how often maintenance runs while the
	// client stays connected.
	prekeyMaintenanceInterval = time.Hour
	// keyIDAttempts bounds the regeneration of prekeys whose random key ID
	// collides with a stored one.
	keyIDAttempts = 8
)

// startMaintenance uploads the verifier of the own access key, then runs
// maintainPrekeys, prefetchPrekeys and pruneGroupKeys, in the background. Prekey
// maintenance runs never overlap; a run requested while one is in progress
// is skipped.
func (a *App) startMaintenance(ctx context.Context) {
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		defer a.maintRuns.Add(1)
		_ = a.publishAccessKey(ctx)
		_ = a.maintainPrekeys(ctx)
		a.prefetchPrekeys(ctx)
		_ = a.pruneGroupKeys(ctx)
	}()
}

// maintainPrekeys keeps the own prekeys on the relay as the policy
// requires:
//
//  1. delete private keys whose retention has ended (PruneRetiredPrekeys)
//     and replay set entries that can no longer match (PruneSeenInits);
//  2. ask the relay for its status with an empty PrekeyUpload;
//  3. make sure an active signed prekey exists locally, generating one
//     when there is none or the newest is older than signedPrekeyRotation,
//     and upload it unless the relay already holds it;
//  4. when the relay holds fewer than oneTimePrekeyLow one-time prekeys,
//     top it up to oneTimePrekeyPool.
//
// Private keys are always stored before their public halves are uploaded,
// and marked as uploaded only afterwards, so a crash at any point loses no
// private key of a published prekey. Re-uploading a prekey after such a
// crash is harmless: the relay ignores known key IDs.
func (a *App) maintainPrekeys(ctx context.Context) error {
	if !a.maintMu.TryLock() {
		return nil
	}
	defer a.maintMu.Unlock()
	sess := a.session()
	if sess == nil {
		return ErrOffline
	}
	now := a.now()
	if _, err := a.prof.DB.PruneRetiredPrekeys(ctx, now); err != nil {
		return err
	}
	if _, err := a.prof.DB.PruneSeenInits(ctx, now); err != nil {
		return err
	}
	status, err := uploadPrekeys(ctx, sess, protocol.PrekeyUpload{})
	if err != nil {
		return err
	}
	signed, expires, err := a.activeSignedPrekey(ctx, now)
	if err != nil {
		return err
	}
	var upload protocol.PrekeyUpload
	if !signed.Uploaded || status.SignedPrekeyExpires != expires.Unix() {
		upload.SignedPrekey = signed.Public
	}
	var oneTime []clientdb.PrekeySecret
	if status.OneTimeRemaining < oneTimePrekeyLow {
		if oneTime, err = a.oneTimePrekeysToUpload(ctx, now, oneTimePrekeyPool-int(status.OneTimeRemaining)); err != nil {
			return err
		}
		for _, p := range oneTime {
			upload.OneTimePrekeys = append(upload.OneTimePrekeys, p.Public)
		}
	}
	if upload.SignedPrekey == nil && len(upload.OneTimePrekeys) == 0 {
		return nil
	}
	if _, err := uploadPrekeys(ctx, sess, upload); err != nil {
		return err
	}
	if upload.SignedPrekey != nil {
		oneTime = append(oneTime, signed)
	}
	for _, p := range oneTime {
		p.Uploaded = true
		if err := a.prof.DB.PutPrekeySecret(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

// uploadPrekeys sends one PrekeyUpload and returns the relay's status.
func uploadPrekeys(ctx context.Context, sess Requester, upload protocol.PrekeyUpload) (protocol.PrekeyStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	frame, err := sess.Request(ctx, protocol.TypePrekeyUpload, upload)
	if err != nil {
		return protocol.PrekeyStatus{}, err
	}
	return protocol.DecodeBody[protocol.PrekeyStatus](frame, protocol.TypePrekeyStatus)
}

// activeSignedPrekey returns the newest stored signed prekey and its expiry,
// after generating and storing a new one if there is none, the newest is
// due for rotation, or it does not verify (any more) at now.
func (a *App) activeSignedPrekey(ctx context.Context, now time.Time) (clientdb.PrekeySecret, time.Time, error) {
	stored, err := a.prof.DB.ListPrekeySecrets(ctx, clientdb.PrekeySigned)
	if err != nil {
		return clientdb.PrekeySecret{}, time.Time{}, err
	}
	if n := len(stored); n > 0 {
		newest := stored[n-1]
		parsed, err := prekey.ParseSignedPrekey(newest.Public, a.self, now)
		if err == nil && parsed.KeyID == newest.KeyID && now.Sub(parsed.Created) < signedPrekeyRotation {
			return newest, parsed.Expires, nil
		}
	}
	taken := make(map[uint32]bool, len(stored))
	for _, p := range stored {
		taken[p.KeyID] = true
	}
	for range keyIDAttempts {
		pair, err := prekey.GenerateSignedPrekey(a.prof.Identity, now, signedPrekeyLifetime)
		if err != nil {
			return clientdb.PrekeySecret{}, time.Time{}, err
		}
		if taken[pair.Public.KeyID] {
			pair.Private.Destroy()
			continue
		}
		secret, err := prekeySecret(clientdb.PrekeySigned, pair.Public.KeyID, pair.Private, pair.Public.Raw, pair.Public.Created)
		pair.Private.Destroy()
		if err != nil {
			return clientdb.PrekeySecret{}, time.Time{}, err
		}
		secret.RetireAt = pair.Public.Created.Add(signedPrekeyRetention)
		if err := a.prof.DB.PutPrekeySecret(ctx, secret); err != nil {
			return clientdb.PrekeySecret{}, time.Time{}, err
		}
		return secret, pair.Public.Expires, nil
	}
	return clientdb.PrekeySecret{}, time.Time{}, errors.New("app: no free signed prekey ID")
}

// oneTimePrekeysToUpload returns up to want one-time prekeys to upload:
// stored ones not yet marked as uploaded first (left over from an
// interrupted run), then newly generated ones, which it stores first.
func (a *App) oneTimePrekeysToUpload(ctx context.Context, now time.Time, want int) ([]clientdb.PrekeySecret, error) {
	want = min(want, protocol.MaxOneTimePrekeysPerUpload)
	stored, err := a.prof.DB.ListPrekeySecrets(ctx, clientdb.PrekeyOneTime)
	if err != nil {
		return nil, err
	}
	taken := make(map[uint32]bool, len(stored))
	var out []clientdb.PrekeySecret
	for _, p := range stored {
		taken[p.KeyID] = true
		if !p.Uploaded && len(p.Public) > 0 && len(out) < want {
			out = append(out, p)
		}
	}
	for attempt := 0; len(out) < want && attempt < keyIDAttempts; attempt++ {
		pairs, err := prekey.GenerateOneTimePrekeys(a.prof.Identity, want-len(out))
		if err != nil {
			return nil, err
		}
		for i, pair := range pairs {
			if taken[pair.Public.KeyID] {
				pair.Private.Destroy()
				continue
			}
			secret, err := prekeySecret(clientdb.PrekeyOneTime, pair.Public.KeyID, pair.Private, pair.Public.Raw, now)
			pair.Private.Destroy()
			if err == nil {
				err = a.prof.DB.PutPrekeySecret(ctx, secret)
			}
			if err != nil {
				for _, rest := range pairs[i+1:] {
					rest.Private.Destroy()
				}
				return nil, err
			}
			taken[pair.Public.KeyID] = true
			out = append(out, secret)
		}
	}
	return out, nil
}

// prekeySecret builds the database record of a prekey private key.
func prekeySecret(kind clientdb.PrekeyKind, keyID uint32, priv *sealbox.PrivateKey, public []byte, created time.Time) (clientdb.PrekeySecret, error) {
	record, err := prekey.MarshalPrivate(keyID, priv)
	if err != nil {
		return clientdb.PrekeySecret{}, err
	}
	return clientdb.PrekeySecret{Kind: kind, KeyID: keyID, Private: record, Public: public, Created: created}, nil
}

// loadPrekey returns the private key of an own prekey, its public encoding
// as uploaded and its RetireAt (zero for none). The caller destroys the key.
// It returns clientdb.ErrNotFound for an unknown or deleted key.
func (a *App) loadPrekey(ctx context.Context, kind clientdb.PrekeyKind, keyID uint32) (*sealbox.PrivateKey, []byte, time.Time, error) {
	secret, err := a.prof.DB.GetPrekeySecret(ctx, kind, keyID)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	defer clear(secret.Private)
	if len(secret.Public) == 0 {
		return nil, nil, time.Time{}, fmt.Errorf("%w: prekey record has no public encoding", clientdb.ErrCorrupt)
	}
	id, priv, err := prekey.UnmarshalPrivate(secret.Private)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	if id != keyID {
		priv.Destroy()
		return nil, nil, time.Time{}, fmt.Errorf("%w: prekey record has key ID %d, want %d", clientdb.ErrCorrupt, id, keyID)
	}
	return priv, secret.Public, secret.RetireAt, nil
}
