package pgstore

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/danthegoodman1/wirenet/internal/store"
)

// Channel is the notification channel every committed change is announced
// on, as the JSON of a store.Change.
const Channel = "wirenet_changes"

// maxPayload is the longest notification payload Postgres accepts: it
// rejects one of 8000 bytes or more.
const maxPayload = 7999

// Watch delivers the changes every replica commits, so a replica wakes the
// long polls another's writes affect. It listens on a connection of its own.
// A change too large for one notification arrives as several, each carrying
// its revision. Notifications that do not decode are dropped.
//
// The channel closes when ctx ends or the connection fails; changes may have
// gone unseen since, so a caller that watches again re-reads what it serves.
// Read the channel promptly: Postgres queues notifications for a slow
// listener, and once its queue fills, every commit that notifies fails.
func (s *Store) Watch(ctx context.Context) (<-chan store.Change, error) {
	conn, err := pgx.ConnectConfig(ctx, s.pool.Config().ConnConfig)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, "LISTEN "+Channel); err != nil {
		return nil, errors.Join(err, conn.Close(ctx))
	}
	out := make(chan store.Change)
	go func() {
		defer close(out)
		// Nothing waits on the close; a connection that fails to close
		// cleanly is gone either way.
		defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
		for {
			n, err := conn.WaitForNotification(ctx)
			if err != nil {
				return
			}
			var ch store.Change
			if err := json.Unmarshal([]byte(n.Payload), &ch); err != nil {
				continue
			}
			select {
			case out <- ch:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

// payloads encodes c as notifications that each fit maxPayload and together
// name everything c touched.
func payloads(c store.Change) ([]string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	if len(b) <= maxPayload || len(c.Networks)+len(c.Hosts)+len(c.Relays) <= 1 {
		return []string{string(b)}, nil
	}
	first, second := halve(c)
	p, err := payloads(first)
	if err != nil {
		return nil, err
	}
	q, err := payloads(second)
	if err != nil {
		return nil, err
	}
	return append(p, q...), nil
}

// halve splits c's touches, taken in order across its three lists, into two
// changes of nearly equal count. Both keep c's revision.
func halve(c store.Change) (store.Change, store.Change) {
	n := (len(c.Networks) + len(c.Hosts) + len(c.Relays)) / 2
	a, b := store.Change{Revision: c.Revision}, store.Change{Revision: c.Revision}
	a.Networks, b.Networks, n = cut(c.Networks, n)
	a.Hosts, b.Hosts, n = cut(c.Hosts, n)
	a.Relays, b.Relays, _ = cut(c.Relays, n)
	return a, b
}

// cut puts up to n of s's elements in its first part and the rest in its
// second, and returns how many of n it did not use.
func cut[T any](s []T, n int) ([]T, []T, int) {
	k := min(n, len(s))
	return s[:k:k], s[k:], n - k
}
