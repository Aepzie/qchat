package profile

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/craguS/qchat/internal/crypto/vault"
	"github.com/craguS/qchat/internal/identity"
	"github.com/craguS/qchat/internal/store/clientdb"
)

// File names inside a profile directory.
const (
	// KeyFileName is the passphrase-encrypted vault holding the identity
	// secret and the database key. Its presence defines an existing profile.
	KeyFileName = "identity.qkey"

	// DBFileName is the encrypted client database.
	DBFileName = "qchat.db"
)

// MinPassphraseRunes is the minimum passphrase length, in Unicode code
// points, accepted by [Create] and [Profile.ChangePassphrase].
//
// The passphrase is the only protection of a stolen key file, and Argon2id
// only slows down guessing; it cannot make a short passphrase strong. Twelve
// characters is a floor, not a recommendation: user interfaces should
// suggest several random words. Passphrases are used byte for byte as
// entered, without Unicode normalisation, so the same passphrase must be
// typed the same way on every unlock.
const MinPassphraseRunes = 12

// Settings names used by this package in the client database.
const (
	settingBundle       = "self.bundle"
	settingBundleSerial = "self.bundle_serial"
)

// keyRecordVersion is the version of the record sealed in the key file.
const keyRecordVersion = 1

// maxKeyFileSize bounds the key file read by Unlock. A real one is about
// 200 bytes.
const maxKeyFileSize = 64 << 10

// Errors returned by this package. Callers compare with [errors.Is].
var (
	// ErrWrongPassphrase reports a passphrase that does not open the key
	// file (or a key file that was modified; the two cannot be told apart).
	// It is the same value as vault.ErrWrongPassphrase.
	ErrWrongPassphrase = vault.ErrWrongPassphrase

	// ErrWeakPassphrase reports a new passphrase shorter than
	// [MinPassphraseRunes].
	ErrWeakPassphrase = fmt.Errorf("profile: passphrase must be at least %d characters", MinPassphraseRunes)

	// ErrExists reports that [Create] found an existing profile.
	ErrExists = errors.New("profile: a profile already exists in this directory")

	// ErrNoProfile reports that [Unlock] found no key file.
	ErrNoProfile = errors.New("profile: no profile in this directory")

	// ErrMalformedKeyFile reports a key file whose decrypted content is not
	// a valid key record.
	ErrMalformedKeyFile = errors.New("profile: malformed key file")

	// ErrClosed reports use of a profile after [Profile.Close].
	ErrClosed = errors.New("profile: profile is closed")

	// ErrDatabaseMissing reports that [Unlock] found the key file but no
	// database. The contacts, verifications, pinned bundles, message history
	// and the stored own bundle are gone; [Recover] creates a new, empty
	// database without locking the user out of the relay. Errors carrying
	// it also match clientdb.ErrMissing.
	ErrDatabaseMissing = errors.New("profile: the key file exists but the database is missing")

	// ErrBundleMismatch reports that the bundle given to [Recover] does not
	// carry the keys of the profile's identity.
	ErrBundleMismatch = errors.New("profile: bundle does not match the profile's identity")
)

// keyRecord is the plaintext sealed in the key file.
type keyRecord struct {
	Version  uint8  `cbor:"1,keyasint"`
	Identity []byte `cbor:"2,keyasint"`
	DBKey    []byte `cbor:"3,keyasint"`
}

// Profile is an unlocked local account: the private identity and the open
// client database. Close it when done; that also destroys the keys held in
// memory. A Profile is safe for concurrent use.
type Profile struct {
	// Dir is the profile directory.
	Dir string

	// Identity is the unlocked private identity.
	Identity *identity.Identity

	// DB is the open client database.
	DB *clientdb.DB

	// BundleSerial is the serial of the identity's current bundle, 0 if no
	// bundle has been created yet. It is maintained by [Profile.Bundle].
	BundleSerial uint64

	// KDFParams are the Argon2id parameters [Profile.ChangePassphrase] seals
	// the key file with. [Create] sets the parameters it was given and
	// [Unlock] sets vault.DefaultParams, so changing the passphrase also
	// upgrades a key file written with older, weaker parameters.
	KDFParams vault.Params

	mu          sync.Mutex
	displayName string
	closed      bool
}

// CheckPassphrase reports [ErrWeakPassphrase] unless passphrase has at least
// [MinPassphraseRunes] characters. It is applied to new passphrases only,
// and user interfaces can call it to validate input before the slow key
// derivation runs.
func CheckPassphrase(passphrase []byte) error {
	if utf8.RuneCount(passphrase) < MinPassphraseRunes {
		return ErrWeakPassphrase
	}
	return nil
}

// Exists reports whether dir contains a profile, that is, a key file.
func Exists(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, KeyFileName))
	return err == nil
}

// Create creates a new profile in dir: it creates the directory with
// permissions restricted to the current user, generates a new identity and
// a random database key, writes the key file (the vault-sealed record
// {1: version, 2: identity secret, 3: database key}) atomically, creates the
// encrypted database, stores displayName in it and creates the first
// identity bundle (serial 1).
//
// The passphrase must satisfy [CheckPassphrase] and displayName
// clientdb.ValidateDisplayName. params are the Argon2id parameters, normally
// vault.DefaultParams. Create refuses with [ErrExists] if dir already holds
// a key file or a database; it never overwrites either. If any step fails,
// the files Create wrote are removed again.
func Create(dir string, passphrase []byte, displayName string, params vault.Params) (*Profile, error) {
	if err := CheckPassphrase(passphrase); err != nil {
		return nil, err
	}
	if err := clientdb.ValidateDisplayName(displayName); err != nil {
		return nil, err
	}
	if err := makePrivateDir(dir); err != nil {
		return nil, err
	}
	keyPath, dbPath := filepath.Join(dir, KeyFileName), filepath.Join(dir, DBFileName)
	if Exists(dir) {
		return nil, ErrExists
	}
	// A database without a key file is unreadable, but it may belong to a
	// key file the user is about to restore from a backup. Never replace it.
	if _, err := os.Lstat(dbPath); err == nil {
		return nil, fmt.Errorf("%w: %s exists without %s; restore the key file or remove the database", ErrExists, DBFileName, KeyFileName)
	}

	id, err := identity.Generate()
	if err != nil {
		return nil, err
	}
	dbKey, err := vault.RandomKey()
	if err != nil {
		id.Destroy()
		return nil, err
	}
	defer clear(dbKey[:])

	blob, err := sealKeyRecord(id, dbKey, passphrase, params)
	if err == nil {
		err = writeFileAtomic(dir, KeyFileName, blob)
	}
	if err != nil {
		id.Destroy()
		return nil, err
	}

	p := &Profile{Dir: dir, Identity: id, KDFParams: params}
	if err := p.initialize(dbPath, dbKey, displayName); err != nil {
		_ = p.Close()
		removeFiles(dbPath, dbPath+"-wal", dbPath+"-shm", keyPath)
		return nil, err
	}
	return p, nil
}

// initialize creates the database of a new profile and its first settings.
func (p *Profile) initialize(dbPath string, dbKey [vault.KeySize]byte, displayName string) error {
	db, err := clientdb.Open(dbPath, dbKey)
	if err != nil {
		return err
	}
	p.DB = db
	if err := p.SetDisplayName(displayName); err != nil {
		return err
	}
	_, err = p.Bundle(time.Now())
	return err
}

// Unlock opens the profile in dir with passphrase. It returns
// [ErrNoProfile] if dir has no key file, [ErrWrongPassphrase] if the
// passphrase is wrong (or the key file was modified), [ErrDatabaseMissing]
// if the key file opens but the database does not exist (it is never
// re-created silently: an empty database would lose every contact and
// verification and make [Profile.Bundle] sign a new bundle the relay rejects
// as a conflict), and another error if the key file or database is damaged
// or the database does not belong to the key file.
//
// After [ErrDatabaseMissing] the caller should restore qchat.db from a
// backup if one exists, and otherwise call [Recover].
func Unlock(dir string, passphrase []byte) (*Profile, error) {
	id, dbKey, err := openKeyFile(dir, passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(dbKey[:])
	db, err := clientdb.OpenExisting(filepath.Join(dir, DBFileName), dbKey)
	if errors.Is(err, clientdb.ErrMissing) {
		id.Destroy()
		return nil, fmt.Errorf("%w: %w", ErrDatabaseMissing, err)
	}
	if errors.Is(err, clientdb.ErrWrongKey) {
		id.Destroy()
		return nil, fmt.Errorf("profile: %s does not belong to %s: %w", DBFileName, KeyFileName, err)
	}
	if err != nil {
		id.Destroy()
		return nil, err
	}

	p := &Profile{Dir: dir, Identity: id, DB: db, KDFParams: vault.DefaultParams()}
	if err := p.load(); err != nil {
		_ = p.Close()
		return nil, err
	}
	return p, nil
}

// Recover opens the profile in dir with passphrase after its database was
// lost ([Unlock] returned [ErrDatabaseMissing]). It creates a new, empty
// database and adopts relayBundle, the bundle the relay currently holds for
// the profile's identity, as the stored own bundle, so that
// [Profile.Bundle] keeps returning exactly the bytes the relay already
// knows instead of signing a new serial 1 bundle the relay would reject.
//
// relayBundle must pass identity.ParseBundleForID for the profile's ID, and
// its signing and KEM keys must equal those of the local identity;
// otherwise Recover returns [ErrBundleMismatch], wrapping the parse error
// if there is one, and creates nothing. An
// empty relayBundle means the relay holds no bundle for this identity; the
// first call of [Profile.Bundle] then creates a serial 1 bundle as after
// [Create].
//
// Contacts, verifications, message history, replay protection and the
// display name are not recovered; the caller should set the display name
// again and re-verify contacts. Recover refuses with [ErrExists] if a
// database exists, and returns [ErrNoProfile] and [ErrWrongPassphrase] like
// Unlock. If a step fails, the database files it created are removed.
func Recover(dir string, passphrase, relayBundle []byte) (*Profile, error) {
	id, dbKey, err := openKeyFile(dir, passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(dbKey[:])
	var adopted *identity.Bundle
	if len(relayBundle) > 0 {
		if adopted, err = matchingBundle(id, relayBundle); err != nil {
			id.Destroy()
			return nil, err
		}
	}
	dbPath := filepath.Join(dir, DBFileName)
	if _, err := os.Lstat(dbPath); !errors.Is(err, fs.ErrNotExist) {
		id.Destroy()
		if err != nil {
			return nil, fmt.Errorf("profile: %w", err)
		}
		return nil, fmt.Errorf("%w: %s exists; use Unlock", ErrExists, DBFileName)
	}

	db, err := clientdb.Open(dbPath, dbKey)
	if err != nil {
		id.Destroy()
		removeFiles(dbPath, dbPath+"-wal", dbPath+"-shm")
		return nil, err
	}
	p := &Profile{Dir: dir, Identity: id, DB: db, KDFParams: vault.DefaultParams()}
	if adopted != nil {
		if err := p.storeBundle(adopted.Raw, adopted.Serial); err != nil {
			_ = p.Close()
			removeFiles(dbPath, dbPath+"-wal", dbPath+"-shm")
			return nil, err
		}
	}
	return p, nil
}

// matchingBundle parses raw as a bundle of id and checks that it carries
// exactly the keys of id.
func matchingBundle(id *identity.Identity, raw []byte) (*identity.Bundle, error) {
	bundle, err := identity.ParseBundleForID(raw, id.ID())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBundleMismatch, err)
	}
	if !bundle.SigningKey.Equal(id.SigningKey()) || !bundle.KEMKey.Equal(id.KEMKey()) {
		return nil, fmt.Errorf("%w: keys differ from the local identity", ErrBundleMismatch)
	}
	return bundle, nil
}

// openKeyFile reads and decrypts the key file of dir. The caller destroys
// the identity and clears the database key.
func openKeyFile(dir string, passphrase []byte) (*identity.Identity, [vault.KeySize]byte, error) {
	var dbKey [vault.KeySize]byte
	blob, err := readKeyFile(dir)
	if err != nil {
		return nil, dbKey, err
	}
	record, err := openKeyRecord(blob, passphrase)
	if err != nil {
		return nil, dbKey, err
	}
	defer clear(record.Identity)
	defer clear(record.DBKey)

	id, err := identity.UnmarshalSecret(record.Identity)
	if err != nil {
		return nil, dbKey, fmt.Errorf("%w: %w", ErrMalformedKeyFile, err)
	}
	copy(dbKey[:], record.DBKey)
	return id, dbKey, nil
}

// load reads the cached settings of an unlocked profile. Missing settings
// (possible after a crash during Create) are treated as unset.
func (p *Profile) load() error {
	ctx := context.Background()
	name, err := p.DB.GetSetting(ctx, clientdb.SettingDisplayName)
	switch {
	case err == nil:
		p.displayName = string(name)
	case !errors.Is(err, clientdb.ErrNotFound):
		return err
	}
	serial, err := p.DB.GetSetting(ctx, settingBundleSerial)
	switch {
	case err == nil && len(serial) == 8:
		p.BundleSerial = binary.BigEndian.Uint64(serial)
	case err == nil:
		return fmt.Errorf("%w: stored bundle serial has %d bytes", clientdb.ErrCorrupt, len(serial))
	case !errors.Is(err, clientdb.ErrNotFound):
		return err
	}
	return nil
}

// Bundle returns the identity's current encoded bundle, the one to register
// with the relay.
//
// The first call creates a bundle with serial [Profile.BundleSerial] (1 if
// still 0) and creation time now, and stores it in the database; every later
// call returns exactly the stored bytes and ignores now. Re-sending the same
// bytes matters: bundle signatures are randomised, and the relay rejects a
// different bundle with an already registered serial as a conflict, so a
// freshly signed bundle with the same serial would lock the user out.
func (p *Profile) Bundle(now time.Time) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrClosed
	}
	ctx := context.Background()
	stored, err := p.DB.GetSetting(ctx, settingBundle)
	if err == nil {
		if _, err := identity.ParseBundleForID(stored, p.Identity.ID()); err != nil {
			return nil, fmt.Errorf("profile: stored bundle is invalid: %w", err)
		}
		return stored, nil
	}
	if !errors.Is(err, clientdb.ErrNotFound) {
		return nil, err
	}

	serial := max(p.BundleSerial, 1)
	raw, err := p.Identity.Bundle(serial, now)
	if err != nil {
		return nil, err
	}
	if err := p.storeBundle(raw, serial); err != nil {
		return nil, err
	}
	return raw, nil
}

// storeBundle stores raw as the own bundle with the given serial and updates
// [Profile.BundleSerial]. The serial is written first, so a crash in between
// never leaves a bundle whose serial is unknown.
func (p *Profile) storeBundle(raw []byte, serial uint64) error {
	ctx := context.Background()
	var encodedSerial [8]byte
	binary.BigEndian.PutUint64(encodedSerial[:], serial)
	if err := p.DB.PutSetting(ctx, settingBundleSerial, encodedSerial[:]); err != nil {
		return err
	}
	if err := p.DB.PutSetting(ctx, settingBundle, raw); err != nil {
		return err
	}
	p.BundleSerial = serial
	return nil
}

// DisplayName returns the user's own display name, or "" if none is set.
// The display name is stored only in the local database; it never reaches
// the relay.
func (p *Profile) DisplayName() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.displayName
}

// SetDisplayName validates and stores the user's own display name (see
// clientdb.ValidateDisplayName).
func (p *Profile) SetDisplayName(name string) error {
	if err := clientdb.ValidateDisplayName(name); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	if err := p.DB.PutSetting(context.Background(), clientdb.SettingDisplayName, []byte(name)); err != nil {
		return err
	}
	p.displayName = name
	return nil
}

// ChangePassphrase re-seals the key file under newPassphrase with
// [Profile.KDFParams], replacing it atomically: after a crash the key file
// is either the old one or the new one, never a mix.
//
// The current passphrase is required even though the profile is already
// unlocked, so that somebody at an unlocked, unattended client cannot lock
// the owner out or set a passphrase they know. newPassphrase must satisfy
// [CheckPassphrase]. The identity and the database key do not change, so
// copies of the old key file (backups) still open with the old passphrase.
func (p *Profile) ChangePassphrase(oldPassphrase, newPassphrase []byte) error {
	if err := CheckPassphrase(newPassphrase); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	blob, err := readKeyFile(p.Dir)
	if err != nil {
		return err
	}
	secret, err := vault.Open(oldPassphrase, blob)
	if err != nil {
		return err
	}
	defer clear(secret)
	record, err := decodeKeyRecord(secret)
	if err != nil {
		return err
	}
	// Re-check that the file still holds this profile's identity, so a key
	// file swapped on disk is never re-sealed under the new passphrase.
	current, err := identity.UnmarshalSecret(record.Identity)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedKeyFile, err)
	}
	sameIdentity := current.ID() == p.Identity.ID()
	current.Destroy()
	if !sameIdentity {
		return fmt.Errorf("%w: key file holds a different identity", ErrMalformedKeyFile)
	}

	params := p.KDFParams
	if params == (vault.Params{}) {
		params = vault.DefaultParams()
	}
	resealed, err := vault.Seal(newPassphrase, secret, params)
	if err != nil {
		return err
	}
	return writeFileAtomic(p.Dir, KeyFileName, resealed)
}

// Close closes the database and destroys the private keys held in memory.
// It is idempotent; after Close every method returns [ErrClosed].
func (p *Profile) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	var err error
	if p.DB != nil {
		err = p.DB.Close()
	}
	if p.Identity != nil {
		p.Identity.Destroy()
	}
	return err
}

// sealKeyRecord encodes the key record of id and dbKey and seals it under
// passphrase.
func sealKeyRecord(id *identity.Identity, dbKey [vault.KeySize]byte, passphrase []byte, params vault.Params) ([]byte, error) {
	secret, err := id.MarshalSecret()
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	plain, err := encMode.Marshal(keyRecord{Version: keyRecordVersion, Identity: secret, DBKey: dbKey[:]})
	if err != nil {
		return nil, fmt.Errorf("profile: encoding key record: %w", err)
	}
	defer clear(plain)
	return vault.Seal(passphrase, plain, params)
}

// openKeyRecord decrypts and decodes a key file. The caller clears the
// returned slices.
func openKeyRecord(blob, passphrase []byte) (keyRecord, error) {
	plain, err := vault.Open(passphrase, blob)
	if err != nil {
		return keyRecord{}, err
	}
	defer clear(plain)
	return decodeKeyRecord(plain)
}

func decodeKeyRecord(plain []byte) (keyRecord, error) {
	var record keyRecord
	if err := decodeCanonical(plain, &record); err != nil {
		clear(record.Identity)
		clear(record.DBKey)
		return keyRecord{}, fmt.Errorf("%w: %w", ErrMalformedKeyFile, err)
	}
	if record.Version != keyRecordVersion || len(record.DBKey) != vault.KeySize {
		clear(record.Identity)
		clear(record.DBKey)
		return keyRecord{}, ErrMalformedKeyFile
	}
	return record, nil
}

// readKeyFile reads the key file of dir, bounded in size.
func readKeyFile(dir string) ([]byte, error) {
	f, err := os.Open(filepath.Join(dir, KeyFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoProfile
	}
	if err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	defer f.Close()
	blob, err := io.ReadAll(io.LimitReader(f, maxKeyFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("profile: reading key file: %w", err)
	}
	if len(blob) > maxKeyFileSize {
		return nil, fmt.Errorf("%w: key file too large", ErrMalformedKeyFile)
	}
	return blob, nil
}

// writeFileAtomic replaces dir/name with contents: it writes a temporary
// file in the same directory, flushes it to disk and renames it over the
// target, so readers and crashes see either the old or the new file. The
// temporary file is created with mode 0600 (on Windows it inherits the
// protected DACL of the profile directory).
func writeFileAtomic(dir, name string, contents []byte) (err error) {
	f, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return fmt.Errorf("profile: writing %s: %w", name, err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(contents); err != nil {
		return fmt.Errorf("profile: writing %s: %w", name, err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("profile: writing %s: %w", name, err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("profile: writing %s: %w", name, err)
	}
	if err = os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("profile: writing %s: %w", name, err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("profile: writing %s: %w", name, err)
	}
	return nil
}

// removeFiles deletes paths, ignoring errors; it is used for rollback.
func removeFiles(paths ...string) {
	for _, path := range paths {
		_ = os.Remove(path)
	}
}
