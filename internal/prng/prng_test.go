package prng

import (
	"testing"
)

// TestMatchesReference checks the generator against the reference
// xoshiro256** outputs for the state {1, 2, 3, 4}.
func TestMatchesReference(t *testing.T) {
	r := &Rand{s: [4]uint64{1, 2, 3, 4}}
	want := []uint64{11520, 0, 1509978240, 1215971899390074240}
	for i, w := range want {
		if got := r.Uint64(); got != w {
			t.Fatalf("output %d = %d, want %d", i, got, w)
		}
	}
}

// TestSeedingIsPinned fails when seeding changes, which would make every
// recorded seed silently replay a different run.
func TestSeedingIsPinned(t *testing.T) {
	if v := New(42).Uint64(); v != 0x15780b2e0c2ec716 {
		t.Fatalf("New(42).Uint64() = %#x; seeding changed", v)
	}
	if v := Stream(42, "network").Uint64(); v != Stream(42, "network").Uint64() {
		t.Fatalf("a stream drew %#x and then something else", v)
	}
}

func TestBelowStaysInBounds(t *testing.T) {
	r := New(1)
	for bound := uint64(1); bound < 500; bound++ {
		if v := r.Below(bound); v >= bound {
			t.Fatalf("Below(%d) = %d", bound, v)
		}
	}
}

func TestStreamsAreIndependent(t *testing.T) {
	if Stream(9, "network").Uint64() == Stream(9, "faults").Uint64() {
		t.Fatal("two purposes drew the same first value")
	}
}

func TestReadFillsEveryByte(t *testing.T) {
	b := make([]byte, 37)
	New(5).Read(b)
	zero := 0
	for _, c := range b {
		if c == 0 {
			zero++
		}
	}
	if zero > 5 {
		t.Fatalf("%d of 37 bytes are zero", zero)
	}
}
