-- name: ListReleased4 :many
SELECT * FROM released4
WHERE network = @network AND at < @before
ORDER BY at, addr
LIMIT sqlc.narg('lim');

-- name: PutReleased4 :exec
INSERT INTO released4 (network, addr, at) VALUES ($1, $2, $3)
ON CONFLICT (network, addr) DO UPDATE SET at = excluded.at;

-- name: DeleteReleased4 :exec
DELETE FROM released4 WHERE network = $1 AND addr = $2;

-- name: ListReleasedPorts :many
SELECT * FROM released_ports
WHERE relay = @relay AND addr = @addr AND at < @before
ORDER BY at, port
LIMIT sqlc.narg('lim');

-- name: PutReleasedPort :exec
INSERT INTO released_ports (relay, addr, port, at) VALUES ($1, $2, $3, $4)
ON CONFLICT (relay, addr, port) DO UPDATE SET at = excluded.at;

-- name: DeleteReleasedPort :exec
DELETE FROM released_ports WHERE relay = $1 AND addr = $2 AND port = $3;

-- name: DeleteRelayPorts :exec
DELETE FROM released_ports WHERE relay = $1;

-- name: GetPortCursor :one
SELECT next FROM port_cursors WHERE relay = $1 AND addr = $2;

-- name: SetPortCursor :exec
INSERT INTO port_cursors (relay, addr, next) VALUES ($1, $2, $3)
ON CONFLICT (relay, addr) DO UPDATE SET next = excluded.next;

-- name: DeleteRelayCursors :exec
DELETE FROM port_cursors WHERE relay = $1;

-- name: GetMeta :one
SELECT value FROM meta WHERE key = $1;

-- name: SetMeta :exec
INSERT INTO meta (key, value) VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: Bump :one
UPDATE revision SET seq = seq + 1 RETURNING seq;

-- name: Notify :exec
SELECT pg_notify(@channel::text, @payload::text);
