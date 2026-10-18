// Package pgstore is the production store: the control plane's records in
// PostgreSQL, through pgx and queries sqlc generates from queries/ against
// the migrations in schema/.
package pgstore

//go:generate go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 generate

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"sdn.sh/internal/store"
	"sdn.sh/internal/store/pgstore/db"
)

// Store is a pool of connections to one database.
type Store struct {
	pool *pgxpool.Pool
}

var _ store.Store = (*Store)(nil)

// Open connects to the database dsn names and applies the migrations it
// lacks.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

// Close closes every connection.
func (s *Store) Close() { s.pool.Close() }

// maxAttempts bounds how many times Update runs fn.
const maxAttempts = 20

// Update runs fn in a SERIALIZABLE transaction and commits it if fn returns
// nil. When Postgres reports a serialization failure or a deadlock, it waits
// a short jittered time and runs fn again in a new transaction.
func (s *Store) Update(ctx context.Context, fn func(store.Tx) error) (store.Change, error) {
	for attempt := 1; ; attempt++ {
		ch, err := s.update(ctx, fn)
		switch {
		case err == nil || !retryable(err):
			return ch, err
		case attempt == maxAttempts:
			return store.Change{}, fmt.Errorf("after %d attempts: %w", attempt, err)
		}
		if err := sleep(ctx, backoff(attempt)); err != nil {
			return store.Change{}, err
		}
	}
}

func (s *Store) update(ctx context.Context, fn func(store.Tx) error) (store.Change, error) {
	pgtx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return store.Change{}, err
	}
	// After a commit this does nothing; otherwise the transaction already
	// failed, and the pool discards a connection that cannot roll back.
	defer func() { _ = pgtx.Rollback(ctx) }()
	t := &tx{ctx: ctx, q: db.New(pgtx)}
	err = fn(t)
	switch {
	case t.failed != nil && retryable(t.failed):
		// fn's reads may be stale, so its own error may be too.
		return store.Change{}, t.failed
	case err != nil:
		return store.Change{}, err
	case t.failed != nil:
		// fn went on past a failed statement, which aborted the
		// transaction.
		return store.Change{}, t.failed
	}
	ch := t.change
	if t.revision > 0 {
		ch.Revision = t.revision
	}
	if err := t.notify(ch); err != nil {
		return store.Change{}, err
	}
	if err := pgtx.Commit(ctx); err != nil {
		return store.Change{}, err
	}
	return ch, nil
}

// View runs fn in a REPEATABLE READ READ ONLY transaction: one snapshot,
// which neither waits nor fails to serialize, where SERIALIZABLE READ ONLY
// DEFERRABLE would wait for a safe one. Transactions that bump a revision all
// update the revision row, so no two of them overlap: a snapshot holds a
// prefix of them in commit order, which is what a long poll compares a
// generation against.
func (s *Store) View(ctx context.Context, fn func(store.ReadTx) error) error {
	pgtx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer func() { _ = pgtx.Rollback(ctx) }()
	t := &tx{ctx: ctx, q: db.New(pgtx)}
	if err := fn(t); err != nil {
		return err
	}
	if t.failed != nil {
		return t.failed
	}
	return pgtx.Commit(ctx)
}

// SQLSTATEs a backend raises for a transaction that may succeed if run
// again, and for a put that breaks a unique index.
const (
	serializationFailure = "40001"
	deadlockDetected     = "40P01"
	uniqueViolation      = "23505"
)

func retryable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && (pgErr.Code == serializationFailure || pgErr.Code == deadlockDetected)
}

// backoff draws the wait before attempt+1: up to 1ms, doubling with each
// attempt to at most 50ms.
func backoff(attempt int) time.Duration {
	ceiling := min(time.Millisecond<<min(attempt-1, 6), 50*time.Millisecond)
	return rand.N(ceiling) + 1
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
