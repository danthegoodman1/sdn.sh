-- changed is when a network's revision last moved: the commit time agents
-- measure convergence from.
ALTER TABLE networks ADD COLUMN changed timestamptz NOT NULL DEFAULT '0001-01-01 00:00:00+00';
