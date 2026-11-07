package client

import "sync"

// eventBuffer is the size of the channel returned by Session.Events.
const eventBuffer = 32

// maxPendingEvents bounds the events held back while the consumer is slow.
// Critical events are queued even beyond the bound, so it only limits
// expendable ones; it is reached only if the consumer has fallen far behind.
const maxPendingEvents = 1024

// eventQueue decouples the network loop from the consumer. push never
// blocks; a separate goroutine delivers queued events to out in order.
//
// Delivery policy: an RTT event replaces a still-undelivered RTT event at the
// tail of the queue (only the latest measurement matters), and when the
// queue is full the oldest RTT or Connecting event is discarded first.
// SecurityAlert, Authenticated, Delivery, RegistrationDenied and Failed
// events are never discarded.
type eventQueue struct {
	out    chan Event
	notify chan struct{}

	mu      sync.Mutex
	pending []Event
	closed  bool
}

func newEventQueue() *eventQueue {
	q := &eventQueue{
		out:    make(chan Event, eventBuffer),
		notify: make(chan struct{}, 1),
	}
	go q.deliver()
	return q
}

// push enqueues ev without blocking. Events pushed after close are ignored.
func (q *eventQueue) push(ev Event) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	if _, isRTT := ev.(RTT); isRTT && len(q.pending) > 0 {
		if _, lastIsRTT := q.pending[len(q.pending)-1].(RTT); lastIsRTT {
			q.pending[len(q.pending)-1] = ev
			return
		}
	}
	if len(q.pending) >= maxPendingEvents && !q.discardOne() && !isCritical(ev) {
		return
	}
	q.pending = append(q.pending, ev)
	q.wake()
}

// discardOne drops the oldest expendable event and reports whether it found
// one. The caller holds q.mu.
func (q *eventQueue) discardOne() bool {
	for i, ev := range q.pending {
		if isExpendable(ev) {
			q.pending = append(q.pending[:i], q.pending[i+1:]...)
			return true
		}
	}
	return false
}

// close stops accepting events. Events already queued are still delivered,
// after which out is closed.
func (q *eventQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.wake()
}

func (q *eventQueue) wake() {
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

// deliver runs until the queue is closed and drained.
func (q *eventQueue) deliver() {
	defer close(q.out)
	for {
		ev, ok := q.next()
		if !ok {
			return
		}
		q.out <- ev
	}
}

// next waits for the next event. It returns false once the queue is closed
// and empty.
func (q *eventQueue) next() (Event, bool) {
	for {
		q.mu.Lock()
		if len(q.pending) > 0 {
			ev := q.pending[0]
			q.pending[0] = nil
			q.pending = q.pending[1:]
			q.mu.Unlock()
			return ev, true
		}
		closed := q.closed
		q.mu.Unlock()
		if closed {
			return nil, false
		}
		<-q.notify
	}
}

func isExpendable(ev Event) bool {
	switch e := ev.(type) {
	case RTT:
		return true
	case StateChanged:
		return e.State == Connecting
	}
	return false
}

func isCritical(ev Event) bool {
	switch e := ev.(type) {
	case SecurityAlert, Authenticated, Delivery, RegistrationDenied:
		return true
	case StateChanged:
		return e.State == Failed
	}
	return false
}
