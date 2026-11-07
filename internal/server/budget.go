package server

import "sync"

// byteBudget counts bytes of encoded frames held for writers against a
// limit. It bounds both the queue of one session and the total held across
// all sessions.
//
// A reservation is granted while used+n stays within the limit, and always
// when nothing is held, so a single frame larger than the limit can never
// wait forever.
type byteBudget struct {
	mu    sync.Mutex
	limit int64
	used  int64
	freed chan struct{}
}

func newByteBudget(limit int64) *byteBudget {
	return &byteBudget{limit: limit, freed: make(chan struct{})}
}

// tryAcquire reserves n bytes if they fit and reports whether it did.
func (b *byteBudget) tryAcquire(n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used > 0 && b.used+n > b.limit {
		return false
	}
	b.used += n
	return true
}

// release returns n reserved bytes and wakes every waiter.
func (b *byteBudget) release(n int64) {
	if n == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used -= n
	close(b.freed)
	b.freed = make(chan struct{})
}

// changed returns a channel that is closed at the next release. Callers
// take it before trying to acquire, so a release between a failed attempt
// and the wait is never missed.
func (b *byteBudget) changed() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.freed
}

// inUse returns the number of reserved bytes.
func (b *byteBudget) inUse() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// acquirePair reserves n bytes from both budgets or from neither and
// reports whether it did.
func acquirePair(local, global *byteBudget, n int64) bool {
	if !local.tryAcquire(n) {
		return false
	}
	if !global.tryAcquire(n) {
		local.release(n)
		return false
	}
	return true
}
