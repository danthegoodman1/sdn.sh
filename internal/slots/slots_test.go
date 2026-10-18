package slots

import (
	"fmt"
	"math"
	"slices"
	"testing"

	"github.com/danthegoodman1/wirenet/internal/model"
)

func ids(n int) []model.InterfaceID {
	out := make([]model.InterfaceID, n)
	for i := range out {
		out[i] = model.InterfaceID(fmt.Sprintf("if-%04d", i))
	}
	return out
}

func owners(backends []model.InterfaceID) []model.InterfaceID {
	out := make([]model.InterfaceID, Count)
	for slot, i := range Assign(backends) {
		out[slot] = backends[i]
	}
	return out
}

func TestEverySlotHasAnOwner(t *testing.T) {
	if Assign(nil) != nil {
		t.Fatal("no backends assigned slots")
	}
	for n := 1; n <= 9; n++ {
		table := Assign(ids(n))
		if len(table) != Count {
			t.Fatalf("%d backends: %d slots", n, len(table))
		}
		for slot, i := range table {
			if i < 0 || i >= n {
				t.Fatalf("%d backends: slot %d owned by %d", n, slot, i)
			}
		}
	}
}

// TestShareIsNearlyEven checks that shares spread no wider than a binomial
// would: within four standard deviations of an even split.
func TestShareIsNearlyEven(t *testing.T) {
	for _, n := range []int{2, 5, 10, 20} {
		count := make([]int, n)
		for _, i := range Assign(ids(n)) {
			count[i]++
		}
		fair := float64(Count) / float64(n)
		sigma := math.Sqrt(fair * (1 - 1/float64(n)))
		for i, c := range count {
			if math.Abs(float64(c)-fair) > 4*sigma {
				t.Errorf("%d backends: backend %d owns %d slots, fair is %.0f", n, i, c, fair)
			}
		}
	}
}

func TestRemovingABackendMovesOnlyItsSlots(t *testing.T) {
	all := ids(6)
	before := owners(all)
	gone := all[2]
	after := owners(slices.Delete(slices.Clone(all), 2, 3))
	for slot := range Count {
		if before[slot] != gone && after[slot] != before[slot] {
			t.Fatalf("slot %d moved from %s to %s", slot, before[slot], after[slot])
		}
	}
}

func TestAddingABackendMovesSlotsOnlyToIt(t *testing.T) {
	all := ids(6)
	before := owners(all[:5])
	after := owners(all)
	moved := 0
	for slot := range Count {
		if after[slot] != before[slot] {
			moved++
			if after[slot] != all[5] {
				t.Fatalf("slot %d moved to %s, not to the new backend", slot, after[slot])
			}
		}
	}
	if moved == 0 {
		t.Fatal("the new backend took no slots")
	}
}

func TestOrderOfBackendsDoesNotMatter(t *testing.T) {
	all := ids(4)
	rev := slices.Clone(all)
	slices.Reverse(rev)
	if !slices.Equal(owners(all), owners(rev)) {
		t.Fatal("reordering backends changed the table")
	}
}
