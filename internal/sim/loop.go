//wirenet:deterministic

// Package sim is the deterministic simulator: one goroutine runs a control
// plane, hosts with agents and kernel models, relays, an underlay and the
// workloads using them, with every delay and fault drawn from one seed.
package sim

import (
	"container/heap"
	"time"
)

// Loop is a discrete-event scheduler over simulated time. Events at the same
// instant run in the order they were scheduled, so a run depends only on its
// seed.
type Loop struct {
	now    time.Time
	seq    uint64
	events eventHeap
	ran    uint64
}

type event struct {
	at  time.Time
	seq uint64
	fn  func()
}

type eventHeap []event

func (h eventHeap) Len() int { return len(h) }
func (h eventHeap) Less(i, j int) bool {
	if !h[i].at.Equal(h[j].at) {
		return h[i].at.Before(h[j].at)
	}
	return h[i].seq < h[j].seq
}
func (h eventHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *eventHeap) Push(x any)   { *h = append(*h, x.(event)) }
func (h *eventHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	*h = old[:len(old)-1]
	return e
}

// NewLoop returns a loop whose clock starts at start.
func NewLoop(start time.Time) *Loop {
	return &Loop{now: start}
}

// Now is the simulated time.
func (l *Loop) Now() time.Time { return l.now }

// Ran counts the events run so far.
func (l *Loop) Ran() uint64 { return l.ran }

// Pending counts the events scheduled and not yet run.
func (l *Loop) Pending() int { return len(l.events) }

// At schedules fn at t, or now if t has passed.
func (l *Loop) At(t time.Time, fn func()) {
	if t.Before(l.now) {
		t = l.now
	}
	l.seq++
	heap.Push(&l.events, event{at: t, seq: l.seq, fn: fn})
}

// After schedules fn d from now.
func (l *Loop) After(d time.Duration, fn func()) {
	l.At(l.now.Add(d), fn)
}

// Step runs the earliest event and reports whether one ran.
func (l *Loop) Step() bool {
	if len(l.events) == 0 {
		return false
	}
	e := heap.Pop(&l.events).(event)
	l.now = e.at
	l.ran++
	e.fn()
	return true
}

// RunUntil runs every event scheduled before t, then sets the clock to t.
func (l *Loop) RunUntil(t time.Time) {
	for len(l.events) > 0 && !l.events[0].at.After(t) {
		l.Step()
	}
	if l.now.Before(t) {
		l.now = t
	}
}
