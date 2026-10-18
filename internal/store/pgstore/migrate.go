package pgstore

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// migrations are the schema's changes, applied in file-name order. A
// released file stays as it is; each change is a new file.
//
//go:embed schema/*.sql
var migrations embed.FS

// migrationLock is the advisory lock that makes openers migrate one at a
// time. It spells "wirenet".
const migrationLock = 0x73646e2e7368

// migrate applies every migration schema_migrations does not record, in one
// transaction, so a failed migration leaves the schema as it was.
func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	names, err := fs.Glob(migrations, "schema/*.sql")
	if err != nil {
		return err
	}
	slices.Sort(names)
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(migrationLock)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			version text COLLATE "C" PRIMARY KEY,
			applied timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, "SELECT version FROM schema_migrations")
		if err != nil {
			return err
		}
		applied, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		for _, name := range names {
			version := strings.TrimSuffix(path.Base(name), ".sql")
			if slices.Contains(applied, version) {
				continue
			}
			sql, err := migrations.ReadFile(name)
			if err != nil {
				return err
			}
			// With no arguments, Exec sends the simple protocol, which
			// runs every statement in the file.
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return fmt.Errorf("migration %s: %w", version, err)
			}
			if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
				return err
			}
		}
		return nil
	})
}
