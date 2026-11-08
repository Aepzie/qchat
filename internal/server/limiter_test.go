package server

import (
	"net/netip"
	"testing"
)

func TestConnLimiterPerIP(t *testing.T) {
	l := newConnLimiter(10, 2)
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	if !l.acquire(a) {
		t.Fatal("first slot for a refused")
	}
	if !l.acquire(a) {
		t.Fatal("second slot for a refused")
	}
	if l.acquire(a) {
		t.Fatal("third slot for a granted")
	}
	if !l.acquire(b) {
		t.Fatal("slot for b refused")
	}
	l.release(a)
	if !l.acquire(a) {
		t.Fatal("slot for a refused after release")
	}
	l.release(a)
	l.release(a)
	l.release(b)
	if total, keys := l.counts(); total != 0 || keys != 0 {
		t.Fatalf("after releasing everything: total %d, keys %d; want 0, 0", total, keys)
	}
}

func TestConnLimiterGlobal(t *testing.T) {
	l := newConnLimiter(2, 2)
	if !l.acquire(netip.MustParseAddr("192.0.2.1")) || !l.acquire(netip.MustParseAddr("192.0.2.2")) {
		t.Fatal("slots below the global limit refused")
	}
	if l.acquire(netip.MustParseAddr("192.0.2.3")) {
		t.Fatal("slot above the global limit granted")
	}
}

func TestConnLimiterReleaseUnknownIsNoop(t *testing.T) {
	l := newConnLimiter(2, 1)
	l.release(netip.MustParseAddr("192.0.2.9"))
	if total, keys := l.counts(); total != 0 || keys != 0 {
		t.Fatalf("release of unknown key changed counts: %d, %d", total, keys)
	}
	if !l.acquire(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("acquire failed after spurious release")
	}
}

func TestLimitKey(t *testing.T) {
	same := [][2]string{
		{"192.0.2.1", "::ffff:192.0.2.1"},
		{"2001:db8:1:2::1", "2001:db8:1:2:ffff:ffff:ffff:ffff"},
		{"fe80::1%eth0", "fe80::2"},
	}
	for _, pair := range same {
		a, b := limitKey(netip.MustParseAddr(pair[0])), limitKey(netip.MustParseAddr(pair[1]))
		if a != b {
			t.Errorf("limitKey(%s) = %s and limitKey(%s) = %s, want equal", pair[0], a, pair[1], b)
		}
	}
	different := [][2]string{
		{"192.0.2.1", "192.0.2.2"},
		{"2001:db8:1:2::1", "2001:db8:1:3::1"},
	}
	for _, pair := range different {
		if limitKey(netip.MustParseAddr(pair[0])) == limitKey(netip.MustParseAddr(pair[1])) {
			t.Errorf("limitKey(%s) == limitKey(%s), want different", pair[0], pair[1])
		}
	}
}

func TestClientKey(t *testing.T) {
	for _, remote := range []string{"192.0.2.1:1234", "[2001:db8::1]:443", "[fe80::1%eth0]:1"} {
		if _, ok := clientKey(remote); !ok {
			t.Errorf("clientKey(%q) failed", remote)
		}
	}
	for _, remote := range []string{"", "192.0.2.1", "example.org:80", "@:1"} {
		if _, ok := clientKey(remote); ok {
			t.Errorf("clientKey(%q) succeeded", remote)
		}
	}
}
