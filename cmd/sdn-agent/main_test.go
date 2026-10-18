package main

import (
	"context"
	"testing"
	"time"
)

func TestABurstOfChangesRunsOnceAtOnceAndOnceAfter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan struct{})
	calls := make(chan time.Time, 16)
	go coalesce(ctx, events, 100*time.Millisecond, func() { calls <- time.Now() })
	start := time.Now()
	for range 5 {
		events <- struct{}{}
	}
	first := <-calls
	if took := first.Sub(start); took > 50*time.Millisecond {
		t.Fatalf("the first change ran after %v, want at once", took)
	}
	select {
	case second := <-calls:
		if gap := second.Sub(first); gap < 100*time.Millisecond {
			t.Fatalf("the trailing run came %v after the first, inside the window", gap)
		}
	case <-time.After(time.Second):
		t.Fatal("the changes after the first never ran")
	}
	select {
	case <-calls:
		t.Fatal("a burst ran more than twice")
	case <-time.After(300 * time.Millisecond):
	}
}
