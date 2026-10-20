-- name: GetInterface :one
SELECT * FROM interfaces WHERE id = $1;

-- name: ListInterfaces :many
SELECT * FROM interfaces WHERE network = $1 ORDER BY id;

-- name: ListHostInterfaces :many
SELECT * FROM interfaces WHERE host = $1 ORDER BY id;

-- The predicate repeats interfaces_member's, so the planner can use it.
-- name: GetHolder :one
SELECT * FROM interfaces
WHERE service = @service AND member = @member AND state = 'live' AND member <> '';

-- A NULL limit returns every match.
-- name: ListExpired :many
SELECT * FROM interfaces
WHERE state = 'live' AND expires < @before
ORDER BY expires, id
LIMIT sqlc.narg('lim');

-- name: ListUndrained :many
SELECT * FROM interfaces
WHERE state = 'released' AND NOT drained AND ended < @before
ORDER BY ended, id
LIMIT sqlc.narg('lim');

-- name: ListEnded :many
SELECT * FROM interfaces
WHERE state <> 'live' AND drained AND ended < @before
ORDER BY ended, id
LIMIT sqlc.narg('lim');

-- name: PutInterface :exec
INSERT INTO interfaces (
	id, network, service, host, kind, gateway, public_key, addr6, addr4,
	listen_port, state, expires, created, ended, drained, member
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
ON CONFLICT (id) DO UPDATE SET
	network = excluded.network, service = excluded.service, host = excluded.host,
	kind = excluded.kind, gateway = excluded.gateway, public_key = excluded.public_key,
	addr6 = excluded.addr6, addr4 = excluded.addr4, listen_port = excluded.listen_port,
	state = excluded.state, expires = excluded.expires, created = excluded.created,
	ended = excluded.ended, drained = excluded.drained, member = excluded.member;

-- name: DeleteInterface :exec
DELETE FROM interfaces WHERE id = $1;
