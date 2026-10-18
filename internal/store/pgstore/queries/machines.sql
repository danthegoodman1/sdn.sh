-- name: GetHost :one
SELECT * FROM hosts WHERE id = $1;

-- name: GetHostByName :one
SELECT * FROM hosts WHERE name = $1;

-- name: GetHostByToken :one
SELECT * FROM hosts WHERE token_hash = $1 ORDER BY id LIMIT 1;

-- name: PutHost :execrows
INSERT INTO hosts (id, name, token_hash, endpoint, revision, created)
SELECT @id, @name, @token_hash, @endpoint, @revision, @created
WHERE NOT EXISTS (SELECT 1 FROM hosts AS o WHERE o.name = @name AND o.id <> @id)
ON CONFLICT (id) DO UPDATE SET
	name = excluded.name, token_hash = excluded.token_hash, endpoint = excluded.endpoint,
	revision = excluded.revision, created = excluded.created;

-- name: DeleteHost :exec
DELETE FROM hosts WHERE id = $1;

-- name: GetRelay :one
SELECT * FROM relays WHERE id = $1;

-- name: GetRelayByName :one
SELECT * FROM relays WHERE name = $1;

-- name: GetRelayByToken :one
SELECT * FROM relays WHERE token_hash = $1 ORDER BY id LIMIT 1;

-- name: ListRelays :many
SELECT * FROM relays ORDER BY id;

-- name: PutRelay :execrows
INSERT INTO relays (id, name, token_hash, addresses, port_lo, port_hi, probe_port, revision, created)
SELECT @id, @name, @token_hash, @addresses, @port_lo, @port_hi, @probe_port, @revision, @created
WHERE NOT EXISTS (SELECT 1 FROM relays AS o WHERE o.name = @name AND o.id <> @id)
ON CONFLICT (id) DO UPDATE SET
	name = excluded.name, token_hash = excluded.token_hash, addresses = excluded.addresses,
	port_lo = excluded.port_lo, port_hi = excluded.port_hi, probe_port = excluded.probe_port,
	revision = excluded.revision, created = excluded.created;

-- name: DeleteRelay :exec
DELETE FROM relays WHERE id = $1;
