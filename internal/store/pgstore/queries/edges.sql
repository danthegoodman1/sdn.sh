-- name: ListEdges :many
SELECT * FROM edges WHERE network = $1 ORDER BY a, b;

-- name: ListRelayEdges :many
SELECT * FROM edges
WHERE ports @> jsonb_build_array(jsonb_build_object('relay', @relay::text))
ORDER BY network, a, b;

-- name: ListDormantEdges :many
SELECT * FROM edges
WHERE dormant IS NOT NULL AND dormant < @before::timestamptz
ORDER BY dormant, network, a, b
LIMIT sqlc.narg('lim');

-- name: PutEdge :exec
INSERT INTO edges (network, a, b, secret_ab, secret_ba, ports, created, dormant, epoch)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (network, a, b) DO UPDATE SET
	secret_ab = excluded.secret_ab, secret_ba = excluded.secret_ba,
	ports = excluded.ports, created = excluded.created, dormant = excluded.dormant,
	epoch = excluded.epoch;

-- name: DeleteEdge :exec
DELETE FROM edges WHERE network = $1 AND a = $2 AND b = $3;
