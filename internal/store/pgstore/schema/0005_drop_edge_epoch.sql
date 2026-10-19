-- Agents withdraw a dormant edge's endpoints at its relays, so no epoch
-- tells the relays to forget them.
ALTER TABLE edges DROP COLUMN epoch;
