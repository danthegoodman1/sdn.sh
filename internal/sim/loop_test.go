package sim

import (
	"testing"
	"time"

	"sdn.sh/internal/prng"
)

var epoch = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

func TestEventsAtOneInstantRunInScheduleOrder(t *testing.T) {
	l := NewLoop(epoch)
	var got []int
	for i := range 5 {
		l.After(time.Second, func() { got = append(got, i) })
	}
	l.After(0, func() { got = append(got, -1) })
	for l.Step() {
	}
	want := []int{-1, 0, 1, 2, 3, 4}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
	if !l.Now().Equal(epoch.Add(time.Second)) {
		t.Fatalf("clock at %v", l.Now())
	}
}

func TestRunUntilStopsAtItsTime(t *testing.T) {
	l := NewLoop(epoch)
	ran := 0
	l.After(time.Second, func() { ran++ })
	l.After(3*time.Second, func() { ran++ })
	l.RunUntil(epoch.Add(2 * time.Second))
	if ran != 1 || l.Pending() != 1 || !l.Now().Equal(epoch.Add(2*time.Second)) {
		t.Fatalf("ran %d, pending %d, now %v", ran, l.Pending(), l.Now())
	}
}

func TestNetworkReplaysFromItsSeed(t *testing.T) {
	run := func() []time.Duration {
		l := NewLoop(epoch)
		n := NewNetwork(l, prng.Stream(11, "network"), time.Millisecond, 50*time.Millisecond)
		n.FaultsOn = true
		n.Faults = Faults{LossPercent: 20, SpikePercent: 10, SpikeMax: time.Second}
		var arrivals []time.Duration
		for range 100 {
			n.Send("a", "b", func() { arrivals = append(arrivals, l.Now().Sub(epoch)) })
		}
		for l.Step() {
		}
		return arrivals
	}
	a, b := run(), run()
	if len(a) != len(b) || len(a) == 0 || len(a) == 100 {
		t.Fatalf("delivered %d then %d of 100", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("arrival %d at %v then %v", i, a[i], b[i])
		}
	}
}

func TestPartitionHoldsBackDelivery(t *testing.T) {
	l := NewLoop(epoch)
	n := NewNetwork(l, prng.New(1), 10*time.Millisecond, 10*time.Millisecond)
	delivered := 0
	n.Send("a", "b", func() { delivered++ })
	n.Partition("b", time.Second)
	for l.Step() {
	}
	if delivered != 0 || n.Cut != 1 {
		t.Fatalf("delivered %d, cut %d", delivered, n.Cut)
	}
	l.After(2*time.Second, func() { n.Send("a", "b", func() { delivered++ }) })
	for l.Step() {
	}
	if delivered != 1 {
		t.Fatal("a healed partition still held back a message")
	}
}
