package server

import (
	"net/netip"
	"sync"
)

// ipv6LimitPrefix is the prefix length under which IPv6 addresses share one
// per-IP counter. A single subscriber is normally given a whole /64, so
// counting individual IPv6 addresses would let one client bypass the limit
// by rotating through its own prefix.
const ipv6LimitPrefix = 64

// connLimiter enforces the global and per-IP connection limits.
//
// Privacy: the map holds client addresses only while they have open
// connections. An entry is deleted as soon as its counter reaches zero, and
// addresses are never logged or persisted.
type connLimiter struct {
	mu       sync.Mutex
	total    int
	maxTotal int
	maxPerIP int
	perIP    map[netip.Addr]int
}

func newConnLimiter(maxTotal, maxPerIP int) *connLimiter {
	return &connLimiter{
		maxTotal: maxTotal,
		maxPerIP: maxPerIP,
		perIP:    make(map[netip.Addr]int),
	}
}

// limitKey maps a client address to its counter key: IPv4 (including
// IPv4-mapped IPv6) addresses count individually, IPv6 addresses by /64.
func limitKey(addr netip.Addr) netip.Addr {
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return addr
	}
	prefix, err := addr.Prefix(ipv6LimitPrefix)
	if err != nil {
		return addr
	}
	return prefix.Addr()
}

// acquire reserves a connection slot for key and reports whether one was
// available.
func (l *connLimiter) acquire(key netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.maxTotal || l.perIP[key] >= l.maxPerIP {
		return false
	}
	l.total++
	l.perIP[key]++
	return true
}

// release frees a slot previously reserved by acquire.
func (l *connLimiter) release(key netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, ok := l.perIP[key]
	if !ok {
		return
	}
	l.total--
	if n <= 1 {
		delete(l.perIP, key)
		return
	}
	l.perIP[key] = n - 1
}

// counts returns the number of reserved slots and of distinct keys.
func (l *connLimiter) counts() (total, keys int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total, len(l.perIP)
}
