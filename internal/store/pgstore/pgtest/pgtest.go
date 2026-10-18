// Package pgtest opens Postgres stores for tests against the database
// SDN_TEST_POSTGRES names, each in a schema of its own, so tests that share
// the database never see each other's records.
package pgtest

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"sdn.sh/internal/store/pgstore"
)

// Env names the variable that holds the test database's DSN.
const Env = "SDN_TEST_POSTGRES"

// DSN returns the test database's DSN, and skips t when Env is unset.
func DSN(t testing.TB) string {
	t.Helper()
	dsn := os.Getenv(Env)
	if dsn == "" {
		t.Skip(Env + " names no Postgres database")
	}
	return dsn
}

// Open returns an empty store in a new schema.
func Open(t testing.TB) *pgstore.Store {
	t.Helper()
	return OpenDSN(t, NewSchema(t))
}

// NewSchema creates an empty schema, which t's cleanup drops, and returns a
// DSN whose connections use it.
func NewSchema(t testing.TB) string {
	t.Helper()
	dsn := DSN(t)
	schema := "sdntest_" + strings.ToLower(rand.Text())
	exec(t, dsn, "CREATE SCHEMA "+schema)
	t.Cleanup(func() { exec(t, dsn, "DROP SCHEMA "+schema+" CASCADE") })
	scoped, err := withSearchPath(dsn, schema)
	if err != nil {
		t.Fatal(err)
	}
	return scoped
}

// OpenDSN opens a store, which t's cleanup closes.
func OpenDSN(t testing.TB, dsn string) *pgstore.Store {
	t.Helper()
	s, err := pgstore.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// exec runs one statement on a connection of its own.
func exec(t testing.TB, dsn, sql string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	if _, err := conn.Exec(ctx, sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// withSearchPath adds a search_path setting to a URL or key/value DSN; pgx
// sends it as a run-time parameter on every connection.
func withSearchPath(dsn, schema string) (string, error) {
	if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
		return fmt.Sprintf("%s search_path=%s", dsn, schema), nil
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
