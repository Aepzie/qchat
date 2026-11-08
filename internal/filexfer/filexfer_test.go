package filexfer

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func randomLocal(t *testing.T) LocalID {
	t.Helper()
	return LocalID(randomBytes(t, LocalIDSize))
}

// sendSide imports content as the sender does and returns the offer and
// the sealed chunks in order.
func sendSide(t *testing.T, content []byte) (Offer, [][]byte) {
	t.Helper()
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewOffer("report.pdf", int64(len(content)), "application/pdf")
	if err != nil {
		t.Fatal(err)
	}
	id := randomLocal(t)
	if err := st.Import(id, &o, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	var chunks [][]byte
	for i := range o.Chunks {
		sealed, err := st.Sealed(id, &o, i)
		if err != nil {
			t.Fatal(err)
		}
		chunks = append(chunks, sealed)
	}
	return o, chunks
}

// roundTripOffer encodes and decodes o as it travels.
func roundTripOffer(t *testing.T, o Offer) Offer {
	t.Helper()
	b, err := MarshalOffer(o)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseOffer(b)
	if err != nil {
		t.Fatal(err)
	}
	if got != o {
		t.Fatalf("offer round trip: %+v != %+v", got, o)
	}
	return got
}

func chunkOf(t *testing.T, o Offer, i uint32, sealed []byte) Chunk {
	t.Helper()
	b, err := MarshalChunk(Chunk{FileID: o.FileID, Index: i, Total: o.Chunks, Sealed: sealed})
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseChunk(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestChunkingAndOutOfOrderReassembly(t *testing.T) {
	content := randomBytes(t, 3*ChunkSize+1234)
	o, chunks := sendSide(t, content)
	if o.Chunks != 4 || len(chunks) != 4 {
		t.Fatalf("chunks = %d, want 4", o.Chunks)
	}
	o = roundTripOffer(t, o)

	profile := t.TempDir()
	st, err := OpenStore(profile)
	if err != nil {
		t.Fatal(err)
	}
	id := randomLocal(t)
	if err := st.Begin(id); err != nil {
		t.Fatal(err)
	}
	for _, i := range []uint32{3, 1, 1, 0} {
		if err := st.Put(id, &o, chunkOf(t, o, i, chunks[i])); err != nil {
			t.Fatalf("Put(%d): %v", i, err)
		}
	}
	if n, err := st.Received(id, &o); err != nil || n != 3 {
		t.Fatalf("Received = %d, %v; want 3", n, err)
	}
	if err := st.Finish(id, &o); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("Finish with a chunk missing: %v", err)
	}
	if err := st.Put(id, &o, chunkOf(t, o, 2, chunks[2])); err != nil {
		t.Fatal(err)
	}
	if err := st.Finish(id, &o); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	out := t.TempDir()
	path, err := st.Export(id, &o, out)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "report.pdf" {
		t.Errorf("exported as %s", path)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("exported content differs (%v)", err)
	}
	stored, err := os.ReadFile(st.filePath(id))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, content[:64]) {
		t.Error("the stored file contains plaintext")
	}
}

func TestTamperedChunkRejected(t *testing.T) {
	o, chunks := sendSide(t, randomBytes(t, 2*ChunkSize))
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := randomLocal(t)
	if err := st.Begin(id); err != nil {
		t.Fatal(err)
	}
	flipped := bytes.Clone(chunks[0])
	flipped[len(flipped)/2] ^= 1
	cases := map[string]Chunk{
		"flipped bit":    {FileID: o.FileID, Index: 0, Total: o.Chunks, Sealed: flipped},
		"wrong position": {FileID: o.FileID, Index: 1, Total: o.Chunks, Sealed: chunks[0]},
		"wrong total":    {FileID: o.FileID, Index: 0, Total: o.Chunks + 1, Sealed: chunks[0]},
		"wrong file":     {FileID: [FileIDSize]byte{1}, Index: 0, Total: o.Chunks, Sealed: chunks[0]},
		"truncated":      {FileID: o.FileID, Index: 0, Total: o.Chunks, Sealed: chunks[0][:len(chunks[0])-1]},
	}
	for name, c := range cases {
		if err := st.Put(id, &o, c); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: Put = %v, want ErrAuth", name, err)
		}
	}
	other := o
	other.Key[0] ^= 1
	if _, err := OpenChunk(&other, 0, chunks[0]); !errors.Is(err, ErrAuth) {
		t.Errorf("wrong key: %v", err)
	}
	if n, _ := st.Received(id, &o); n != 0 {
		t.Errorf("%d rejected chunks were stored", n)
	}
}

func TestTamperedAtRestRejected(t *testing.T) {
	content := randomBytes(t, ChunkSize+10)
	o, chunks := sendSide(t, content)
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := randomLocal(t)
	if err := st.Begin(id); err != nil {
		t.Fatal(err)
	}
	for i, sealed := range chunks {
		if err := st.Put(id, &o, chunkOf(t, o, uint32(i), sealed)); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Finish(id, &o); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(st.filePath(id), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{0xAA}, slotSize+40); err != nil {
		t.Fatal(err)
	}
	f.Close()
	out := t.TempDir()
	if _, err := st.Export(id, &o, out); !errors.Is(err, ErrAuth) {
		t.Fatalf("Export of a tampered file: %v", err)
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Errorf("a partial export was left behind: %v", entries)
	}
}

func TestWrongTotalHashRejected(t *testing.T) {
	o, chunks := sendSide(t, randomBytes(t, ChunkSize+1))
	o.SHA256[0] ^= 1
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := randomLocal(t)
	if err := st.Begin(id); err != nil {
		t.Fatal(err)
	}
	for i, sealed := range chunks {
		if err := st.Put(id, &o, chunkOf(t, o, uint32(i), sealed)); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Finish(id, &o); !errors.Is(err, ErrHash) {
		t.Fatalf("Finish with a wrong hash: %v", err)
	}
	if st.Has(id) {
		t.Error("a file with a wrong hash was moved into the store")
	}
}

func TestSizeLimits(t *testing.T) {
	if _, err := NewOffer("a", MaxFileSize+1, ""); !errors.Is(err, ErrTooLarge) {
		t.Errorf("NewOffer above the limit: %v", err)
	}
	if _, err := NewOffer("a", 0, ""); !errors.Is(err, ErrEmpty) {
		t.Errorf("NewOffer of an empty file: %v", err)
	}
	o, err := NewOffer("a", MaxFileSize, "")
	if err != nil || o.Chunks != MaxChunks {
		t.Fatalf("NewOffer at the limit: %d chunks, %v", o.Chunks, err)
	}
	b, err := MarshalOffer(o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseOffer(b); err != nil {
		t.Fatalf("ParseOffer at the limit: %v", err)
	}
	for name, mutate := range map[string]func(*Offer){
		"too large":     func(o *Offer) { o.Size = MaxFileSize + 1; o.Chunks = ChunksFor(o.Size) },
		"chunk count":   func(o *Offer) { o.Chunks++ },
		"empty":         func(o *Offer) { o.Size, o.Chunks = 0, 0 },
		"no name":       func(o *Offer) { o.Name = "" },
		"long name":     func(o *Offer) { o.Name = strings.Repeat("a", MaxNameSize+1) },
		"long mimetype": func(o *Offer) { o.MIME = strings.Repeat("a", MaxMIMESize+1) },
	} {
		bad := o
		mutate(&bad)
		if _, err := MarshalOffer(bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: MarshalOffer = %v", name, err)
		}
		w := offerWire{FileID: bad.FileID[:], Name: bad.Name, Size: bad.Size, SHA256: bad.SHA256[:], Chunks: bad.Chunks, MIME: bad.MIME, Key: bad.Key[:]}
		raw, err := encMode.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseOffer(raw); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: ParseOffer = %v", name, err)
		}
	}
	for name, c := range map[string]Chunk{
		"index beyond total": {Index: 2, Total: 2, Sealed: make([]byte, 100)},
		"too many chunks":    {Index: 0, Total: MaxChunks + 1, Sealed: make([]byte, 100)},
		"oversized":          {Index: 0, Total: 1, Sealed: make([]byte, MaxSealedChunkSize+1)},
		"empty":              {Index: 0, Total: 1, Sealed: make([]byte, 40)},
	} {
		if _, err := MarshalChunk(c); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: MarshalChunk = %v", name, err)
		}
	}
}

func TestImportDetectsChangedFile(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewOffer("a.bin", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Import(randomLocal(t), &o, bytes.NewReader(make([]byte, 99))); err == nil {
		t.Error("Import of a shrunk file succeeded")
	}
	if err := st.Import(randomLocal(t), &o, bytes.NewReader(make([]byte, 101))); err == nil {
		t.Error("Import of a grown file succeeded")
	}
}

func TestSanitizeName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"report.pdf", "report.pdf"},
		{`..\..\x`, "x"},
		{"../../etc/passwd", "passwd"},
		{`C:\Windows\System32\evil.dll`, "evil.dll"},
		{"..", "file"},
		{".", "file"},
		{"", "file"},
		{"...", "file"},
		{".bashrc", "bashrc"},
		{"  .hidden. ", "hidden"},
		{"CON.txt", "_CON.txt"},
		{"con", "_con"},
		{"nul.tar.gz", "_nul.tar.gz"},
		{"COM1", "_COM1"},
		{"lpt9.log", "_lpt9.log"},
		{"CONSOLE.txt", "CONSOLE.txt"},
		{"\x1b[2J.txt", "[2J.txt"},
		{"a\x00b\nc\td.txt", "abcd.txt"},
		{"no break.txt", "no break.txt"},
		{"invoice\u202Etxt.exe", "invoicetxt.exe"},
		{"a\u2066b\u2069c\u200Bd", "abcd"},
		{"what?<>:\"|*.txt", "what_______.txt"},
		{"trailing dots...", "trailing dots"},
		{"ok \xff name", "ok  name"},
		{"日本語.txt", "日本語.txt"},
	}
	for _, c := range cases {
		if got := SanitizeName(c.in); got != c.want {
			t.Errorf("SanitizeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	long := strings.Repeat("é", 300) + ".txt"
	got := SanitizeName(long)
	if len(got) > maxSanitizedName || !strings.HasSuffix(got, ".txt") || !utf8.ValidString(got) {
		t.Errorf("long name sanitised to %d bytes %q", len(got), got)
	}
}

func FuzzSanitizeName(f *testing.F) {
	for _, s := range []string{"a.txt", `..\..\x`, "CON.txt", "\x1b[2J.txt", "\u202Eabc"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got := SanitizeName(in)
		if got == "" || got == "." || got == ".." || strings.ContainsAny(got, `/\<>:"|?*`) || strings.HasPrefix(got, ".") ||
			strings.HasSuffix(got, ".") || strings.HasSuffix(got, " ") || len(got) > maxSanitizedName+1 || !utf8.ValidString(got) {
			t.Fatalf("SanitizeName(%q) = %q", in, got)
		}
		if SanitizeName(got) != got {
			t.Fatalf("SanitizeName is not idempotent on %q: %q", got, SanitizeName(got))
		}
	})
}

func TestExportNeverOverwrites(t *testing.T) {
	content := []byte("new content")
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewOffer("notes.txt", int64(len(content)), "")
	if err != nil {
		t.Fatal(err)
	}
	id := randomLocal(t)
	if err := st.Import(id, &o, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	existing := filepath.Join(out, "notes.txt")
	if err := os.WriteFile(existing, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "notes (1).txt"), []byte("keep me too"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := st.Export(id, &o, out)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "notes (2).txt" {
		t.Errorf("exported as %s", filepath.Base(path))
	}
	for name, want := range map[string]string{"notes.txt": "keep me", "notes (1).txt": "keep me too", "notes (2).txt": string(content)} {
		got, err := os.ReadFile(filepath.Join(out, name))
		if err != nil || string(got) != want {
			t.Errorf("%s = %q, %v", name, got, err)
		}
	}
	again, err := st.Export(id, &o, out)
	if err != nil || filepath.Base(again) != "notes (3).txt" {
		t.Errorf("second export: %s, %v", again, err)
	}
}

func TestExportDoesNotFollowSymlink(t *testing.T) {
	content := []byte("payload")
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewOffer("link.txt", int64(len(content)), "")
	if err != nil {
		t.Fatal(err)
	}
	id := randomLocal(t)
	if err := st.Import(id, &o, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	target := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(out, "link.txt")); err != nil {
		t.Skipf("cannot create symbolic links here: %v", err)
	}
	path, err := st.Export(id, &o, out)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "link (1).txt" {
		t.Errorf("exported as %s", filepath.Base(path))
	}
	if got, _ := os.ReadFile(target); string(got) != "original" {
		t.Errorf("the link target was overwritten: %q", got)
	}
}

func TestStoreRejectsLinkedDirectory(t *testing.T) {
	profile := t.TempDir()
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(profile, filesDir)); err != nil {
		t.Skipf("cannot create symbolic links here: %v", err)
	}
	if _, err := OpenStore(profile); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("OpenStore with a linked files directory: %v", err)
	}
}

func TestRemoveAndOrphans(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keep, drop := randomLocal(t), randomLocal(t)
	for _, id := range []LocalID{keep, drop} {
		if err := st.Begin(id); err != nil {
			t.Fatal(err)
		}
	}
	orphans := st.Orphans(func(id LocalID) bool { return id == keep })
	if len(orphans) != 1 || orphans[0] != drop {
		t.Fatalf("Orphans = %v", orphans)
	}
	if err := st.Remove(drop); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(st.partPath(drop)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("transfer file still there: %v", err)
	}
	if err := st.Remove(drop); err != nil {
		t.Errorf("removing twice: %v", err)
	}
}
