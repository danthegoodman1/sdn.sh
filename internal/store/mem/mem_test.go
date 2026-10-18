package mem_test

import (
	"testing"

	"github.com/danthegoodman1/wirenet/internal/store"
	"github.com/danthegoodman1/wirenet/internal/store/locked"
	"github.com/danthegoodman1/wirenet/internal/store/mem"
	"github.com/danthegoodman1/wirenet/internal/store/storetest"
)

// TestConformance runs the suite on the memory store behind a lock, so the
// concurrency tests run too.
func TestConformance(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return locked.New(mem.New()) })
}
