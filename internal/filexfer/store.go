package filexfer

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	// filesDir and incomingDir are the store's directories under the
	// profile directory.
	filesDir    = "files"
	incomingDir = "incoming"
	partSuffix  = ".part"
	fileSuffix  = ".qcf"
	// slotSize is the space one sealed chunk takes in a stored file: a
	// presence marker and the sealed chunk.
	slotSize = 1 + MaxSealedChunkSize
	// slotPresent marks a written slot; an unwritten slot reads as zero.
	slotPresent = 1
	// maxUniqueTries bounds the names Export tries.
	maxUniqueTries = 1000
	// LocalIDSize is the length of a local file ID.
	LocalIDSize = 16
)

// ErrUnsafePath reports a store directory or file that is not a plain
// directory or regular file, such as a symbolic link.
var ErrUnsafePath = errors.New("filexfer: refusing a path that is not a plain file or directory")

// LocalID names a file in the store. It is chosen locally at random and
// never derived from anything a sender controls.
type LocalID [LocalIDSize]byte

func (id LocalID) String() string { return hex.EncodeToString(id[:]) }

// Store holds the files of one profile. It is safe for concurrent use.
type Store struct {
	mu       sync.Mutex
	dir      string
	incoming string
}

// OpenStore opens, creating if needed, the store under profileDir.
func OpenStore(profileDir string) (*Store, error) {
	dir := filepath.Join(profileDir, filesDir)
	incoming := filepath.Join(dir, incomingDir)
	for _, d := range []string{dir, incoming} {
		if err := ensureDir(d); err != nil {
			return nil, err
		}
	}
	return &Store{dir: dir, incoming: incoming}, nil
}

// ensureDir creates d with mode 0700 or checks that it is a plain
// directory, not a link.
func ensureDir(d string) error {
	fi, err := os.Lstat(d)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(d, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("filexfer: %w", err)
		}
		fi, err = os.Lstat(d)
	}
	if err != nil {
		return fmt.Errorf("filexfer: %w", err)
	}
	if !fi.IsDir() || fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return fmt.Errorf("%w: %s", ErrUnsafePath, d)
	}
	return nil
}

func (s *Store) partPath(id LocalID) string { return filepath.Join(s.incoming, id.String()+partSuffix) }
func (s *Store) filePath(id LocalID) string { return filepath.Join(s.dir, id.String()+fileSuffix) }

// openRegular opens an existing store file without following a link.
func openRegular(path string, flag int) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrUnsafePath, path)
	}
	f, err := os.OpenFile(path, flag, 0)
	if err != nil {
		return nil, err
	}
	if after, err := f.Stat(); err != nil || !os.SameFile(fi, after) {
		f.Close()
		return nil, fmt.Errorf("%w: %s changed while it was opened", ErrUnsafePath, path)
	}
	return f, nil
}

// Begin creates the empty transfer file of a file being received.
func (s *Store) Begin(id LocalID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.partPath(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("filexfer: %w", err)
	}
	return f.Close()
}

// Put authenticates a received chunk of the file o and writes it to its
// slot, and reports whether the slot was empty before. Writing a chunk
// again is harmless. It returns [ErrAuth] for a chunk that does not belong
// to o, and an error wrapping fs.ErrNotExist when the transfer was never
// begun or has been removed.
func (s *Store) Put(id LocalID, o *Offer, c Chunk) (bool, error) {
	if c.FileID != o.FileID || c.Total != o.Chunks {
		return false, ErrAuth
	}
	plain, err := OpenChunk(o, c.Index, c.Sealed)
	if err != nil {
		return false, err
	}
	clear(plain)
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := openRegular(s.partPath(id), os.O_RDWR)
	if err != nil {
		return false, fmt.Errorf("filexfer: %w", err)
	}
	offset := int64(c.Index) * slotSize
	marker := make([]byte, 1)
	if _, err := f.ReadAt(marker, offset); err != nil && !errors.Is(err, io.EOF) {
		f.Close()
		return false, fmt.Errorf("filexfer: %w", err)
	}
	slot := make([]byte, 1+len(c.Sealed))
	slot[0] = slotPresent
	copy(slot[1:], c.Sealed)
	if _, err := f.WriteAt(slot, offset); err != nil {
		f.Close()
		return false, fmt.Errorf("filexfer: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return false, fmt.Errorf("filexfer: %w", err)
	}
	return marker[0] != slotPresent, f.Close()
}

// Received returns how many chunks of the file o the transfer file holds.
func (s *Store) Received(id LocalID, o *Offer) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := openRegular(s.partPath(id), os.O_RDONLY)
	if err != nil {
		return 0, fmt.Errorf("filexfer: %w", err)
	}
	defer f.Close()
	n := 0
	marker := make([]byte, 1)
	for i := range o.Chunks {
		_, err := f.ReadAt(marker, int64(i)*slotSize)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("filexfer: %w", err)
		}
		if marker[0] == slotPresent {
			n++
		}
	}
	return n, nil
}

// Finish checks a complete transfer of the file o, every chunk and the
// SHA-256 of the whole content, and moves it into the store. It returns
// [ErrIncomplete], [ErrAuth] or [ErrHash] when the check fails; the transfer
// file is kept then, for the caller to remove.
func (s *Store) Finish(id LocalID, o *Offer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := openRegular(s.partPath(id), os.O_RDONLY)
	if err != nil {
		return fmt.Errorf("filexfer: %w", err)
	}
	err = verify(f, o, io.Discard)
	f.Close()
	if err != nil {
		return err
	}
	if err := os.Rename(s.partPath(id), s.filePath(id)); err != nil {
		return fmt.Errorf("filexfer: %w", err)
	}
	return nil
}

// verify reads every slot of the file o from f, authenticates and decrypts
// it, writes the plaintext to w and checks the SHA-256 at the end.
func verify(f *os.File, o *Offer, w io.Writer) error {
	h := sha256.New()
	for i := range o.Chunks {
		slot := make([]byte, 1+SealedLen(o, i))
		if _, err := f.ReadAt(slot, int64(i)*slotSize); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return ErrIncomplete
			}
			return fmt.Errorf("filexfer: %w", err)
		}
		if slot[0] != slotPresent {
			return ErrIncomplete
		}
		plain, err := OpenChunk(o, i, slot[1:])
		if err != nil {
			return err
		}
		h.Write(plain)
		_, err = w.Write(plain)
		clear(plain)
		if err != nil {
			return fmt.Errorf("filexfer: %w", err)
		}
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), o.SHA256[:]) != 1 {
		return ErrHash
	}
	return nil
}

// Import reads exactly o.Size bytes of a file being sent from r, seals them
// into the store as the file o and sets o.SHA256. It fails if r holds fewer
// or more bytes, for example because the file changed meanwhile.
func (s *Store) Import(id LocalID, o *Offer, r io.Reader) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	part := s.partPath(id)
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("filexfer: %w", err)
	}
	fail := func(err error) error {
		f.Close()
		os.Remove(part)
		return err
	}
	h := sha256.New()
	buf := make([]byte, ChunkSize)
	defer clear(buf)
	for i := range o.Chunks {
		plain := buf[:chunkLen(o.Size, i)]
		if _, err := io.ReadFull(r, plain); err != nil {
			return fail(fmt.Errorf("filexfer: the file changed while it was read: %w", err))
		}
		h.Write(plain)
		sealed, err := SealChunk(o, i, plain)
		if err != nil {
			return fail(err)
		}
		slot := append([]byte{slotPresent}, sealed...)
		if _, err := f.WriteAt(slot, int64(i)*slotSize); err != nil {
			return fail(fmt.Errorf("filexfer: %w", err))
		}
	}
	if n, _ := r.Read(buf[:1]); n != 0 {
		return fail(errors.New("filexfer: the file grew while it was read"))
	}
	copy(o.SHA256[:], h.Sum(nil))
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("filexfer: %w", err))
	}
	if err := f.Close(); err != nil {
		os.Remove(part)
		return fmt.Errorf("filexfer: %w", err)
	}
	if err := os.Rename(part, s.filePath(id)); err != nil {
		os.Remove(part)
		return fmt.Errorf("filexfer: %w", err)
	}
	return nil
}

// Sealed returns sealed chunk index of the stored file o, as it is sent.
func (s *Store) Sealed(id LocalID, o *Offer, index uint32) ([]byte, error) {
	if index >= o.Chunks {
		return nil, ErrIncomplete
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := openRegular(s.filePath(id), os.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("filexfer: %w", err)
	}
	defer f.Close()
	slot := make([]byte, 1+SealedLen(o, index))
	if _, err := f.ReadAt(slot, int64(index)*slotSize); err != nil {
		return nil, fmt.Errorf("filexfer: %w", err)
	}
	if slot[0] != slotPresent {
		return nil, ErrIncomplete
	}
	return slot[1:], nil
}

// Export decrypts the stored file o into a new file in dir, named after
// the sanitised offered name, and returns its path. It never replaces an
// existing file: when the name is taken it tries "name (1).ext", "name
// (2).ext" and so on. The new file is removed again if any chunk fails to
// authenticate or the content does not match its SHA-256.
func (s *Store) Export(id LocalID, o *Offer, dir string) (string, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("filexfer: %w", err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("filexfer: %s is not a directory", dir)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	src, err := openRegular(s.filePath(id), os.O_RDONLY)
	if err != nil {
		return "", fmt.Errorf("filexfer: %w", err)
	}
	defer src.Close()
	dst, path, err := createUnique(dir, SanitizeName(o.Name))
	if err != nil {
		return "", err
	}
	if err := verify(src, o, dst); err != nil {
		dst.Close()
		os.Remove(path)
		return "", err
	}
	if err := dst.Sync(); err != nil {
		dst.Close()
		os.Remove(path)
		return "", fmt.Errorf("filexfer: %w", err)
	}
	if err := dst.Close(); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("filexfer: %w", err)
	}
	return path, nil
}

// createUnique creates a new file in dir named name or a numbered variant
// of it. O_EXCL makes the creation fail, rather than follow a link or
// truncate, when anything already exists under the name.
func createUnique(dir, name string) (*os.File, string, error) {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	if stem == "" {
		stem, ext = name, ""
	}
	for i := range maxUniqueTries {
		candidate := name
		if i > 0 {
			candidate = stem + " (" + strconv.Itoa(i) + ")" + ext
		}
		path := filepath.Join(dir, candidate)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("filexfer: %w", err)
		}
		return f, path, nil
	}
	return nil, "", fmt.Errorf("filexfer: no free name for %s in %s", name, dir)
}

// Remove deletes the transfer file and the stored file of id, whichever
// exist.
func (s *Store) Remove(id LocalID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for _, p := range []string{s.partPath(id), s.filePath(id)} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Has reports whether the store holds the finished file id.
func (s *Store) Has(id LocalID) bool {
	fi, err := os.Lstat(s.filePath(id))
	return err == nil && fi.Mode().IsRegular()
}

// Orphans returns the local IDs of the transfer and stored files for which
// keep reports false.
func (s *Store) Orphans(keep func(LocalID) bool) []LocalID {
	var out []LocalID
	for _, d := range []struct{ dir, suffix string }{{s.incoming, partSuffix}, {s.dir, fileSuffix}} {
		entries, err := os.ReadDir(d.dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			raw, ok := strings.CutSuffix(e.Name(), d.suffix)
			b, err := hex.DecodeString(raw)
			if !ok || err != nil || len(b) != LocalIDSize {
				continue
			}
			if id := LocalID(b); !keep(id) {
				out = append(out, id)
			}
		}
	}
	return out
}
