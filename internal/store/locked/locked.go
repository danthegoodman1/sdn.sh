// Package locked makes a store that serves one transaction at a time safe
// for concurrent use.
package locked

import (
	"context"
	"sync"

	"sdn.sh/internal/store"
)

// Store serializes every transaction of the store it wraps.
type Store struct {
	mu    sync.Mutex
	inner store.Store
}

// New wraps inner.
func New(inner store.Store) *Store { return &Store{inner: inner} }

// Update runs fn under the lock.
func (s *Store) Update(ctx context.Context, fn func(store.Tx) error) (store.Change, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner.Update(ctx, fn)
}

// View runs fn under the lock.
func (s *Store) View(ctx context.Context, fn func(store.ReadTx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner.View(ctx, fn)
}
