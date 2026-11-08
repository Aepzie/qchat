package clientdb

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func randomKey(t *testing.T) [32]byte {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return k
}

func randomID(t *testing.T) [32]byte {
	t.Helper()
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return id
}

func randomMsgID(t *testing.T) [16]byte {
	t.Helper()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return id
}

func openTemp(t *testing.T) (*DB, string, [32]byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "qchat.db")
	key := randomKey(t)
	d, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d, path, key
}

func sampleContact(t *testing.T, name string) Contact {
	t.Helper()
	now := time.Now()
	return Contact{
		ID:           randomID(t),
		DisplayName:  name,
		Bundle:       []byte("bundle-" + name),
		BundleSerial: 7,
		Verified:     true,
		VerifiedAt:   now.Add(-time.Hour),
		AddedAt:      now.Add(-2 * time.Hour),
	}
}

func sampleMessage(t *testing.T, peer [32]byte, body string) Message {
	t.Helper()
	now := time.Now()
	return Message{
		Peer:     peer,
		MsgID:    randomMsgID(t),
		Dir:      Incoming,
		Sent:     now.Add(-time.Second),
		Received: now,
		Body:     body,
		Status:   StatusReceived,
		Flags:    FlagClockSkew,
	}
}

func equalContact(a, b Contact) bool {
	return a.ID == b.ID && a.DisplayName == b.DisplayName && bytes.Equal(a.Bundle, b.Bundle) &&
		a.BundleSerial == b.BundleSerial && a.Verified == b.Verified &&
		a.VerifiedAt.Equal(b.VerifiedAt) && a.KeyChangedAt.Equal(b.KeyChangedAt) && a.AddedAt.Equal(b.AddedAt)
}

func equalMessage(a, b Message) bool {
	return a.Peer == b.Peer && a.MsgID == b.MsgID && a.Dir == b.Dir && a.Sent.Equal(b.Sent) &&
		a.Received.Equal(b.Received) && a.Body == b.Body && a.Status == b.Status && a.Flags == b.Flags
}

func TestContactRoundTrip(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	c := sampleContact(t, "Alice")
	if err := d.PutContact(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetContact(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !equalContact(got, c) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, c)
	}
	if !got.KeyChangedAt.IsZero() {
		t.Fatalf("KeyChangedAt should stay zero, got %v", got.KeyChangedAt)
	}

	c.DisplayName = "Alice B."
	c.KeyChangedAt = time.Now()
	c.BundleSerial = 8
	if err := d.PutContact(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetContact(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !equalContact(got, c) {
		t.Fatalf("replace mismatch:\n got %+v\nwant %+v", got, c)
	}

	if _, err := d.GetContact(ctx, randomID(t)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown contact: got %v, want ErrNotFound", err)
	}
}

func TestListContactsSorted(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	for _, name := range []string{"carol", "Bob", "alice", "Dave"} {
		if err := d.PutContact(ctx, sampleContact(t, name)); err != nil {
			t.Fatal(err)
		}
	}
	list, err := d.ListContacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range list {
		names = append(names, c.DisplayName)
	}
	if got, want := strings.Join(names, ","), "alice,Bob,carol,Dave"; got != want {
		t.Fatalf("order = %s, want %s", got, want)
	}
}

func TestWrongKey(t *testing.T) {
	ctx := context.Background()
	d, path, key := openTemp(t)
	if err := d.PutContact(ctx, sampleContact(t, "Alice")); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, randomKey(t)); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong key: got %v, want ErrWrongKey", err)
	}
	d2, err := Open(path, key)
	if err != nil {
		t.Fatalf("reopen with right key: %v", err)
	}
	d2.Close()
}

func TestMissingCanaryIsCorrupt(t *testing.T) {
	d, path, key := openTemp(t)
	if _, err := d.conn.Exec(`DELETE FROM meta`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	if _, err := Open(path, key); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing canary: got %v, want ErrCorrupt", err)
	}
}

func TestReopenPersistence(t *testing.T) {
	ctx := context.Background()
	d, path, key := openTemp(t)
	c := sampleContact(t, "Alice")
	m := sampleMessage(t, c.ID, "hello")
	if err := d.PutContact(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := d.AppendMessage(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := d.PutSetting(ctx, SettingDisplayName, []byte("Me")); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	d2, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	got, err := d2.GetContact(ctx, c.ID)
	if err != nil || !equalContact(got, c) {
		t.Fatalf("contact after reopen: %+v, %v", got, err)
	}
	msgs, err := d2.Messages(ctx, c.ID, 10, 0)
	if err != nil || len(msgs) != 1 || !equalMessage(msgs[0], m) {
		t.Fatalf("messages after reopen: %+v, %v", msgs, err)
	}
	v, err := d2.GetSetting(ctx, SettingDisplayName)
	if err != nil || string(v) != "Me" {
		t.Fatalf("setting after reopen: %q, %v", v, err)
	}
	if err := d2.AppendMessage(ctx, m); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate after reopen: got %v, want ErrDuplicate", err)
	}
}

func TestPragmas(t *testing.T) {
	d, _, _ := openTemp(t)
	var mode string
	if err := d.conn.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}
	var secure int
	if err := d.conn.QueryRow(`PRAGMA secure_delete`).Scan(&secure); err != nil {
		t.Fatal(err)
	}
	if secure != 1 {
		t.Fatalf("secure_delete = %d, want 1", secure)
	}
	var busy int
	if err := d.conn.QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil {
		t.Fatal(err)
	}
	if busy != busyTimeoutMillis {
		t.Fatalf("busy_timeout = %d, want %d", busy, busyTimeoutMillis)
	}
	var version int
	if err := d.conn.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(migrations) {
		t.Fatalf("schema version = %d, want %d", version, len(migrations))
	}
}

func TestTamperedCiphertext(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	c := sampleContact(t, "Alice")
	m := sampleMessage(t, c.ID, "secret")
	if err := d.PutContact(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := d.AppendMessage(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := d.PutSetting(ctx, "theme", []byte("dark")); err != nil {
		t.Fatal(err)
	}

	tamperValue := func(table, keyCol string, mutate func([]byte) []byte) {
		t.Helper()
		var key, value []byte
		if err := d.conn.QueryRow(fmt.Sprintf(`SELECT %s, value FROM %s`, keyCol, table)).Scan(&key, &value); err != nil {
			t.Fatal(err)
		}
		if _, err := d.conn.Exec(fmt.Sprintf(`UPDATE %s SET value = ? WHERE %s = ?`, table, keyCol), mutate(value), key); err != nil {
			t.Fatal(err)
		}
	}
	tamperValue("contacts", "lookup", func(v []byte) []byte { v[len(v)/2] ^= 0x80; return v })
	if _, err := d.GetContact(ctx, c.ID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered contact: got %v, want ErrCorrupt", err)
	}
	if _, err := d.ListContacts(ctx); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered contact list: got %v, want ErrCorrupt", err)
	}

	tamperValue("messages", "lookup", func(v []byte) []byte { v[0] ^= 0x01; return v })
	if _, err := d.Messages(ctx, c.ID, 10, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered message: got %v, want ErrCorrupt", err)
	}
	if err := d.UpdateMessageStatus(ctx, c.ID, m.MsgID, StatusDelivered); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("status update on tampered message: got %v, want ErrCorrupt", err)
	}

	tamperValue("settings", "lookup", func(v []byte) []byte { return v[:5] })
	if _, err := d.GetSetting(ctx, "theme"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("truncated setting: got %v, want ErrCorrupt", err)
	}

	tamperValue("contacts", "lookup", func([]byte) []byte { return []byte{} })
	if _, err := d.GetContact(ctx, c.ID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("empty contact value: got %v, want ErrCorrupt", err)
	}
}

func TestRowSwapDetected(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	a := sampleContact(t, "Alice")
	b := sampleContact(t, "Bob")
	for _, c := range []Contact{a, b} {
		if err := d.PutContact(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	la, lb := d.keys.contactLookup(a.ID), d.keys.contactLookup(b.ID)
	var va, vb []byte
	if err := d.conn.QueryRow(`SELECT value FROM contacts WHERE lookup = ?`, la).Scan(&va); err != nil {
		t.Fatal(err)
	}
	if err := d.conn.QueryRow(`SELECT value FROM contacts WHERE lookup = ?`, lb).Scan(&vb); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.Exec(`UPDATE contacts SET value = ? WHERE lookup = ?`, vb, la); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.Exec(`UPDATE contacts SET value = ? WHERE lookup = ?`, va, lb); err != nil {
		t.Fatal(err)
	}
	for _, c := range []Contact{a, b} {
		if _, err := d.GetContact(ctx, c.ID); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("swapped contact %s: got %v, want ErrCorrupt", c.DisplayName, err)
		}
	}

	if err := d.PutSetting(ctx, "theme", []byte("dark")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.Exec(`UPDATE settings SET lookup = ?`, la); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.Exec(`UPDATE contacts SET value = (SELECT value FROM settings) WHERE lookup = ?`, la); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetContact(ctx, a.ID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("cross-table copy: got %v, want ErrCorrupt", err)
	}
}

func TestMessageReorderDetected(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	peer := randomID(t)
	m1 := sampleMessage(t, peer, "first")
	m2 := sampleMessage(t, peer, "second")
	for _, m := range []Message{m1, m2} {
		if err := d.AppendMessage(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.conn.Exec(`UPDATE messages SET seq = CASE seq WHEN 1 THEN 100 WHEN 2 THEN 1 END`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Messages(ctx, peer, 10, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("reordered messages: got %v, want ErrCorrupt", err)
	}
}

func TestMessageMovedToOtherPeerDetected(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	alice, bob := randomID(t), randomID(t)
	if err := d.AppendMessage(ctx, sampleMessage(t, alice, "for alice")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.Exec(`UPDATE messages SET peer = ?`, d.keys.contactLookup(bob)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Messages(ctx, bob, 10, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("moved message: got %v, want ErrCorrupt", err)
	}
}

func TestNoPlaintextInFile(t *testing.T) {
	ctx := context.Background()
	d, path, _ := openTemp(t)
	c := sampleContact(t, "Zebediah Quartermaine")
	c.Bundle = []byte("UNIQUE-BUNDLE-MARKER-0123456789")
	m := sampleMessage(t, c.ID, "the eagle lands at midnight")
	settingValue := []byte("UNIQUE-SETTING-MARKER-42")
	if err := d.PutContact(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := d.AppendMessage(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := d.PutSetting(ctx, SettingDisplayName, settingValue); err != nil {
		t.Fatal(err)
	}

	needles := map[string][]byte{
		"contact ID":   c.ID[:],
		"display name": []byte(c.DisplayName),
		"bundle":       c.Bundle,
		"message ID":   m.MsgID[:],
		"body":         []byte(m.Body),
		"setting name": []byte(SettingDisplayName),
		"setting":      settingValue,
	}
	scan := func(stage string) {
		t.Helper()
		for _, p := range []string{path, path + "-wal", path + "-shm"} {
			raw, err := os.ReadFile(p)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			for what, needle := range needles {
				if bytes.Contains(raw, needle) {
					t.Errorf("%s: %s found in plaintext in %s", stage, what, filepath.Base(p))
				}
			}
		}
	}
	scan("open")
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	scan("closed")
}

func TestDuplicateMessage(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	peer := randomID(t)
	m := sampleMessage(t, peer, "hi")
	if err := d.AppendMessage(ctx, m); err != nil {
		t.Fatal(err)
	}
	dup := m
	dup.Body = "different body"
	if err := d.AppendMessage(ctx, dup); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate: got %v, want ErrDuplicate", err)
	}
	other := m
	other.Peer = randomID(t)
	if err := d.AppendMessage(ctx, other); err != nil {
		t.Fatalf("same MsgID from another peer: %v", err)
	}
	ok, err := d.HasMessage(ctx, peer, m.MsgID)
	if err != nil || !ok {
		t.Fatalf("HasMessage = %v, %v", ok, err)
	}
	ok, err = d.HasMessage(ctx, peer, randomMsgID(t))
	if err != nil || ok {
		t.Fatalf("HasMessage(unknown) = %v, %v", ok, err)
	}
	msgs, err := d.Messages(ctx, peer, 10, 0)
	if err != nil || len(msgs) != 1 || msgs[0].Body != "hi" {
		t.Fatalf("messages after duplicate: %+v, %v", msgs, err)
	}
}

func TestPagination(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	alice, bob := randomID(t), randomID(t)
	for i := 1; i <= 25; i++ {
		if err := d.AppendMessage(ctx, sampleMessage(t, alice, fmt.Sprintf("a%02d", i))); err != nil {
			t.Fatal(err)
		}
		if err := d.AppendMessage(ctx, sampleMessage(t, bob, fmt.Sprintf("b%02d", i))); err != nil {
			t.Fatal(err)
		}
	}

	bodies := func(msgs []Message) string {
		var parts []string
		for _, m := range msgs {
			parts = append(parts, m.Body)
		}
		return strings.Join(parts, ",")
	}
	want := func(from, to int) string {
		var parts []string
		for i := from; i <= to; i++ {
			parts = append(parts, fmt.Sprintf("a%02d", i))
		}
		return strings.Join(parts, ",")
	}

	page1, err := d.Messages(ctx, alice, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := bodies(page1); got != want(16, 25) {
		t.Fatalf("page 1 = %s", got)
	}
	for i := 1; i < len(page1); i++ {
		if page1[i].Seq <= page1[i-1].Seq {
			t.Fatalf("sequence not increasing: %d then %d", page1[i-1].Seq, page1[i].Seq)
		}
	}
	page2, err := d.Messages(ctx, alice, 10, page1[0].Seq)
	if err != nil {
		t.Fatal(err)
	}
	if got := bodies(page2); got != want(6, 15) {
		t.Fatalf("page 2 = %s", got)
	}
	page3, err := d.Messages(ctx, alice, 10, page2[0].Seq)
	if err != nil {
		t.Fatal(err)
	}
	if got := bodies(page3); got != want(1, 5) {
		t.Fatalf("page 3 = %s", got)
	}
	page4, err := d.Messages(ctx, alice, 10, page3[0].Seq)
	if err != nil || len(page4) != 0 {
		t.Fatalf("page 4 = %+v, %v", page4, err)
	}
	if _, err := d.Messages(ctx, alice, 0, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero limit: got %v, want ErrInvalid", err)
	}
	none, err := d.Messages(ctx, randomID(t), 10, 0)
	if err != nil || len(none) != 0 {
		t.Fatalf("unknown peer: %+v, %v", none, err)
	}
}

func TestSequenceNotReusedAfterDelete(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	c := sampleContact(t, "Alice")
	if err := d.PutContact(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := d.AppendMessage(ctx, sampleMessage(t, c.ID, "one")); err != nil {
		t.Fatal(err)
	}
	first, err := d.Messages(ctx, c.ID, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteContact(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.AppendMessage(ctx, sampleMessage(t, c.ID, "two")); err != nil {
		t.Fatal(err)
	}
	second, err := d.Messages(ctx, c.ID, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if second[0].Seq <= first[0].Seq {
		t.Fatalf("sequence reused: %d after %d", second[0].Seq, first[0].Seq)
	}
}

func TestUpdateMessageStatus(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	peer := randomID(t)
	m := sampleMessage(t, peer, "out")
	m.Dir = Outgoing
	m.Status = StatusSent
	if err := d.AppendMessage(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateMessageStatus(ctx, peer, m.MsgID, StatusDelivered); err != nil {
		t.Fatal(err)
	}
	msgs, err := d.Messages(ctx, peer, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	m.Status = StatusDelivered
	if len(msgs) != 1 || !equalMessage(msgs[0], m) {
		t.Fatalf("after status update: %+v", msgs)
	}
	if err := d.UpdateMessageStatus(ctx, peer, randomMsgID(t), StatusFailed); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown message: got %v, want ErrNotFound", err)
	}
	if err := d.UpdateMessageStatus(ctx, peer, m.MsgID, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid status: got %v, want ErrInvalid", err)
	}
}

func TestDeleteContactCascades(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	a := sampleContact(t, "Alice")
	b := sampleContact(t, "Bob")
	ma := sampleMessage(t, a.ID, "to alice")
	mb := sampleMessage(t, b.ID, "to bob")
	for _, c := range []Contact{a, b} {
		if err := d.PutContact(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range []Message{ma, mb} {
		if err := d.AppendMessage(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.DeleteContact(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetContact(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted contact: got %v, want ErrNotFound", err)
	}
	if msgs, err := d.Messages(ctx, a.ID, 10, 0); err != nil || len(msgs) != 0 {
		t.Fatalf("message of deleted contact still present: %v, %v", msgs, err)
	}
	var count int
	if err := d.conn.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("message rows = %d, want 1", count)
	}
	if ok, err := d.HasMessage(ctx, b.ID, mb.MsgID); err != nil || !ok {
		t.Fatalf("other contact's message lost: %v, %v", ok, err)
	}
	if _, err := d.GetContact(ctx, b.ID); err != nil {
		t.Fatalf("other contact lost: %v", err)
	}
	if err := d.DeleteContact(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: got %v, want ErrNotFound", err)
	}
}

func TestSettings(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	if _, err := d.GetSetting(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing setting: got %v, want ErrNotFound", err)
	}
	if err := d.PutSetting(ctx, SettingDisplayName, []byte("Me")); err != nil {
		t.Fatal(err)
	}
	if err := d.PutSetting(ctx, SettingDisplayName, []byte("Me again")); err != nil {
		t.Fatal(err)
	}
	v, err := d.GetSetting(ctx, SettingDisplayName)
	if err != nil || string(v) != "Me again" {
		t.Fatalf("setting = %q, %v", v, err)
	}
	if err := d.PutSetting(ctx, "empty", nil); err != nil {
		t.Fatal(err)
	}
	v, err = d.GetSetting(ctx, "empty")
	if err != nil || v == nil || len(v) != 0 {
		t.Fatalf("empty setting = %v, %v", v, err)
	}
}

func TestValidation(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)

	badNames := []string{"", strings.Repeat("a", MaxDisplayNameRunes+1), "bad\x1b[31m", "tab\there", "nul\x00", "\xff\xfe", "rtl\u202eoverride"}
	for _, name := range badNames {
		c := sampleContact(t, "ok")
		c.DisplayName = name
		if err := d.PutContact(ctx, c); !errors.Is(err, ErrInvalid) {
			t.Errorf("display name %q: got %v, want ErrInvalid", name, err)
		}
	}
	okName := strings.Repeat("é", MaxDisplayNameRunes)
	if err := d.PutContact(ctx, sampleContact(t, okName)); err != nil {
		t.Errorf("64-rune name rejected: %v", err)
	}
	big := sampleContact(t, "big")
	big.Bundle = make([]byte, MaxBundleSize+1)
	if err := d.PutContact(ctx, big); !errors.Is(err, ErrInvalid) {
		t.Errorf("oversized bundle: got %v", err)
	}
	early := sampleContact(t, "early")
	early.AddedAt = time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := d.PutContact(ctx, early); !errors.Is(err, ErrInvalid) {
		t.Errorf("unrepresentable time: got %v", err)
	}

	peer := randomID(t)
	cases := map[string]func(*Message){
		"body too large": func(m *Message) { m.Body = strings.Repeat("x", MaxBodySize+1) },
		"invalid utf8":   func(m *Message) { m.Body = "\xff" },
		"no direction":   func(m *Message) { m.Dir = 0 },
		"bad direction":  func(m *Message) { m.Dir = 3 },
		"no status":      func(m *Message) { m.Status = 0 },
		"bad status":     func(m *Message) { m.Status = 6 },
	}
	for name, mutate := range cases {
		m := sampleMessage(t, peer, "x")
		mutate(&m)
		if err := d.AppendMessage(ctx, m); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
	maxBody := sampleMessage(t, peer, strings.Repeat("x", MaxBodySize))
	if err := d.AppendMessage(ctx, maxBody); err != nil {
		t.Errorf("max-size body rejected: %v", err)
	}

	for _, name := range []string{"", "Upper", "has space", strings.Repeat("a", MaxSettingNameLen+1)} {
		if err := d.PutSetting(ctx, name, []byte("v")); !errors.Is(err, ErrInvalid) {
			t.Errorf("setting name %q: got %v, want ErrInvalid", name, err)
		}
	}
	if err := d.PutSetting(ctx, "big", make([]byte, MaxSettingValueSize+1)); !errors.Is(err, ErrInvalid) {
		t.Errorf("oversized setting: got %v", err)
	}
}

func TestClosed(t *testing.T) {
	ctx := context.Background()
	d, _, _ := openTemp(t)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := d.GetContact(ctx, randomID(t)); !errors.Is(err, ErrClosed) {
		t.Fatalf("GetContact after Close: got %v, want ErrClosed", err)
	}
	if err := d.AppendMessage(ctx, sampleMessage(t, randomID(t), "x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("AppendMessage after Close: got %v, want ErrClosed", err)
	}
}

func TestOpenRejectsSpecialPaths(t *testing.T) {
	for _, p := range []string{"", ":memory:", "file:x.db", "x.db?mode=ro"} {
		if _, err := Open(p, randomKey(t)); !errors.Is(err, ErrInvalid) {
			t.Errorf("path %q: got %v, want ErrInvalid", p, err)
		}
	}
}

func TestSubkeysDiffer(t *testing.T) {
	k, err := deriveKeys(randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	probe := []byte("probe")
	sealed, err := k.seal(probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := deriveKeys(randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.open(sealed, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("open under another key: got %v, want ErrCorrupt", err)
	}
	if bytes.Equal(k.lookup(labelContact, probe), k.lookup(labelMessage, probe)) {
		t.Fatal("labels do not separate lookups")
	}
}

func TestReplayRejectedAfterDeleteContact(t *testing.T) {
	ctx := context.Background()
	d, path, key := openTemp(t)
	c := sampleContact(t, "Alice")
	if err := d.PutContact(ctx, c); err != nil {
		t.Fatal(err)
	}
	old := sampleMessage(t, c.ID, "old")
	if err := d.AppendMessage(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteContact(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.PutContact(ctx, c); err != nil {
		t.Fatal(err)
	}
	if ok, err := d.HasMessage(ctx, c.ID, old.MsgID); err != nil || !ok {
		t.Fatalf("HasMessage after delete = %v, %v; want true", ok, err)
	}
	if err := d.AppendMessage(ctx, old); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replayed message after delete and re-add: got %v, want ErrDuplicate", err)
	}
	if msgs, err := d.Messages(ctx, c.ID, 10, 0); err != nil || len(msgs) != 0 {
		t.Fatalf("replayed message stored: %v, %v", msgs, err)
	}
	fresh := sampleMessage(t, c.ID, "new")
	if err := d.AppendMessage(ctx, fresh); err != nil {
		t.Fatalf("new message after re-add: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenExisting(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.AppendMessage(ctx, old); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replay after reopen: got %v, want ErrDuplicate", err)
	}
}

func TestMigrationBackfillsSeen(t *testing.T) {
	ctx := context.Background()
	d, path, key := openTemp(t)
	peer := randomID(t)
	m := sampleMessage(t, peer, "before migration")
	if err := d.AppendMessage(ctx, m); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{`DROP TABLE seen`, `DROP TABLE sessions`, `DROP TABLE prekeys`, `DELETE FROM schema_migrations WHERE version >= 2`} {
		if _, err := d.conn.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenExisting(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.conn.Exec(`DELETE FROM messages`); err != nil {
		t.Fatal(err)
	}
	if err := reopened.AppendMessage(ctx, m); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("message stored before migration: got %v, want ErrDuplicate", err)
	}
}

func TestOpenExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "qchat.db")
	key := randomKey(t)
	if _, err := OpenExisting(path, key); !errors.Is(err, ErrMissing) {
		t.Fatalf("missing file: got %v, want ErrMissing", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("OpenExisting created the file: %v", err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExisting(path, key); !errors.Is(err, ErrMissing) {
		t.Fatalf("empty file: got %v, want ErrMissing", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	d, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PutSetting(context.Background(), "probe", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	existing, err := OpenExisting(path, key)
	if err != nil {
		t.Fatalf("existing database: %v", err)
	}
	if value, err := existing.GetSetting(context.Background(), "probe"); err != nil || string(value) != "x" {
		t.Errorf("setting after OpenExisting: %q, %v", value, err)
	}
	existing.Close()
	if _, err := OpenExisting(path, randomKey(t)); !errors.Is(err, ErrWrongKey) {
		t.Errorf("wrong key: got %v, want ErrWrongKey", err)
	}
	if _, err := OpenExisting(":memory:", key); !errors.Is(err, ErrInvalid) {
		t.Errorf("special path: got %v, want ErrInvalid", err)
	}
}
