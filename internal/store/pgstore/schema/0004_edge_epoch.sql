-- epoch counts the times an edge has gone dormant; a relay forgets the
-- endpoints of a port whose epoch moves.
ALTER TABLE edges ADD COLUMN epoch bigint NOT NULL DEFAULT 0;
