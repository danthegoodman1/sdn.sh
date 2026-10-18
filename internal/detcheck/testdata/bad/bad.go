//wirenet:deterministic

// Package bad violates every determinism rule once.
package bad

import (
	"errors"
	"maps"
	"os"
	"slices"
	"time"
)

var ErrFine = errors.New("errors are allowed")

var counter int

func Violations(m map[string]int) []string {
	_ = os.Getpid()
	_ = time.Now()
	go func() {}()
	ch := make(chan int)
	select {
	case ch <- 1:
	case <-ch:
	}
	for k := range m {
		_ = k
	}
	unordered := slices.Collect(maps.Keys(m))
	ordered := slices.Sorted(maps.Keys(m))
	counter++
	return append(unordered, ordered...)
}
