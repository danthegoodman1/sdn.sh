-- member is a name among the interface's service's members, which the
-- interface holds while it is live; the index keeps one live holder per
-- name.
ALTER TABLE interfaces ADD COLUMN member text NOT NULL DEFAULT '';
CREATE UNIQUE INDEX interfaces_member ON interfaces (service, member) WHERE state = 'live' AND member <> '';
