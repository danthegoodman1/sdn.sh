package model

import (
	"fmt"
	"testing"
)

func TestAnEdgeWeighsARelayTheSameFromEitherEnd(t *testing.T) {
	for i := range 100 {
		a, b := InterfaceID(fmt.Sprintf("if-a%d", i)), InterfaceID(fmt.Sprintf("if-b%d", i*7))
		if RelayWeight(a, b, "rl-1") != RelayWeight(b, a, "rl-1") {
			t.Fatalf("%s and %s weigh rl-1 differently", a, b)
		}
	}
}

// TestEdgesSpreadOverRelaysInProportion checks that the heaviest relay of
// many edges falls on each relay about equally, and that removing one
// relay moves only the edges it held.
func TestEdgesSpreadOverRelaysInProportion(t *testing.T) {
	relays := []RelayID{"rl-1", "rl-2", "rl-3"}
	heaviest := func(a, b InterfaceID, set []RelayID) RelayID {
		var best RelayID
		var w uint64
		for _, r := range set {
			if x := RelayWeight(a, b, r); best == "" || x > w {
				best, w = r, x
			}
		}
		return best
	}
	const edges = 3000
	count := map[RelayID]int{}
	moved := 0
	for i := range edges {
		a, b := InterfaceID(fmt.Sprintf("if-%d", i)), InterfaceID(fmt.Sprintf("if-%d", i+edges))
		r := heaviest(a, b, relays)
		count[r]++
		if after := heaviest(a, b, relays[1:]); after != r && r != "rl-1" {
			moved++
		}
	}
	for _, r := range relays {
		if share := float64(count[r]) / edges; share < 0.28 || share > 0.39 {
			t.Errorf("%s carries %.1f%% of the edges, want about a third", r, 100*share)
		}
	}
	if moved > 0 {
		t.Errorf("removing rl-1 moved %d edges it did not carry", moved)
	}
}
