package sim

import (
	"testing"
)

func TestSeedsPass(t *testing.T) {
	n := uint64(100)
	if testing.Short() {
		n = 20
	}
	for seed := range n {
		if _, err := New(seed).Run(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestASeedReplaysExactly(t *testing.T) {
	for _, seed := range []uint64{1, 42, 0xdeadbeef} {
		a, errA := New(seed).Run()
		b, errB := New(seed).Run()
		if a != b || (errA == nil) != (errB == nil) {
			t.Fatalf("seed %d ran differently: %v / %v; %v / %v", seed, a, b, errA, errB)
		}
	}
}
