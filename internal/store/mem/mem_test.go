package mem_test

import (
	"testing"

	"sdn.sh/internal/store"
	"sdn.sh/internal/store/locked"
	"sdn.sh/internal/store/mem"
	"sdn.sh/internal/store/storetest"
)

// TestConformance runs the suite on the memory store behind a lock, so the
// concurrency tests run too.
func TestConformance(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return locked.New(mem.New()) })
}
