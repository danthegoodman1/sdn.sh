package cpserver

import (
	"sync"
	"time"

	"sdn.sh/internal/model"
	"sdn.sh/internal/store"
)

// hub wakes long polls when a commit touches what they watch. A poll
// registers before it reads, so a commit landing between its read and its
// wait still wakes it.
type hub struct {
	mu     sync.Mutex
	hosts  map[model.HostID]map[*waiter]struct{}
	nets   map[model.NetworkID]map[*waiter]struct{}
	relays map[model.RelayID]map[*waiter]struct{}
}

// waiter is one parked poll. ch closes on the first wake; at records when.
type waiter struct {
	ch    chan struct{}
	at    time.Time
	hosts []model.HostID
	nets  []model.NetworkID
	relay model.RelayID
}

func newHub() *hub {
	return &hub{
		hosts:  map[model.HostID]map[*waiter]struct{}{},
		nets:   map[model.NetworkID]map[*waiter]struct{}{},
		relays: map[model.RelayID]map[*waiter]struct{}{},
	}
}

func add[K comparable](m map[K]map[*waiter]struct{}, k K, w *waiter) {
	if m[k] == nil {
		m[k] = map[*waiter]struct{}{}
	}
	m[k][w] = struct{}{}
}

func remove[K comparable](m map[K]map[*waiter]struct{}, k K, w *waiter) {
	delete(m[k], w)
	if len(m[k]) == 0 {
		delete(m, k)
	}
}

// watchHost parks a poll for a host and the networks it holds.
func (h *hub) watchHost(host model.HostID, nets []model.NetworkID) *waiter {
	w := &waiter{ch: make(chan struct{}), hosts: []model.HostID{host}, nets: nets}
	h.mu.Lock()
	defer h.mu.Unlock()
	add(h.hosts, host, w)
	for _, n := range nets {
		add(h.nets, n, w)
	}
	return w
}

func (h *hub) watchRelay(relay model.RelayID) *waiter {
	w := &waiter{ch: make(chan struct{}), relay: relay}
	h.mu.Lock()
	defer h.mu.Unlock()
	add(h.relays, relay, w)
	return w
}

// cancel unregisters a waiter that did not wake.
func (h *hub) cancel(w *waiter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.drop(w)
}

func (h *hub) drop(w *waiter) {
	for _, id := range w.hosts {
		remove(h.hosts, id, w)
	}
	for _, id := range w.nets {
		remove(h.nets, id, w)
	}
	if w.relay != "" {
		remove(h.relays, w.relay, w)
	}
}

// publish wakes every poll a change touches.
func (h *hub) publish(c store.Change, now time.Time) {
	if c.Empty() {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var woken []*waiter
	for _, id := range c.Hosts {
		for w := range h.hosts[id] {
			woken = append(woken, w)
		}
	}
	for _, id := range c.Networks {
		for w := range h.nets[id] {
			woken = append(woken, w)
		}
	}
	for _, id := range c.Relays {
		for w := range h.relays[id] {
			woken = append(woken, w)
		}
	}
	for _, w := range woken {
		h.wake(w, now)
	}
}

// wakeAll wakes every parked poll, as after a gap in the change feed.
func (h *hub) wakeAll(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var woken []*waiter
	for _, ws := range h.hosts {
		for w := range ws {
			woken = append(woken, w)
		}
	}
	for _, ws := range h.relays {
		for w := range ws {
			woken = append(woken, w)
		}
	}
	for _, w := range woken {
		h.wake(w, now)
	}
}

func (h *hub) wake(w *waiter, now time.Time) {
	select {
	case <-w.ch:
	default:
		w.at = now
		close(w.ch)
	}
	h.drop(w)
}

// open counts parked polls, for metrics.
func (h *hub) open() (hosts, relays int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ws := range h.hosts {
		hosts += len(ws)
	}
	for _, ws := range h.relays {
		relays += len(ws)
	}
	return hosts, relays
}
