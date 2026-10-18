-- Identifiers and names collate as bytes, so lists order as Go strings do.
-- Times keep microseconds, and the zero time is 0001-01-01 00:00:00 UTC.
-- Unsigned 64-bit counters keep their bits in a bigint. Records refer to
-- each other by identifier alone; the control plane keeps them consistent,
-- as it does over every backend.

CREATE TABLE networks (
	id       text COLLATE "C" PRIMARY KEY,
	name     text COLLATE "C" NOT NULL UNIQUE,
	prefix6  inet,
	prefix4  inet,
	mtu      bigint NOT NULL,
	-- relays is a JSON array of relay identifiers in preference order.
	relays   jsonb NOT NULL,
	next6    bigint NOT NULL,
	next4    bigint NOT NULL,
	revision bigint NOT NULL,
	created  timestamptz NOT NULL
);

CREATE TABLE services (
	id      text COLLATE "C" PRIMARY KEY,
	network text COLLATE "C" NOT NULL,
	name    text COLLATE "C" NOT NULL,
	ipv4    boolean NOT NULL,
	addr6   inet,
	addr4   inet,
	mode    text NOT NULL,
	created timestamptz NOT NULL,
	UNIQUE (network, name)
);
CREATE INDEX services_network ON services (network, id);

CREATE TABLE interfaces (
	id          text COLLATE "C" PRIMARY KEY,
	network     text COLLATE "C" NOT NULL,
	service     text COLLATE "C" NOT NULL,
	host        text COLLATE "C" NOT NULL,
	kind        text NOT NULL,
	gateway     text COLLATE "C" NOT NULL,
	public_key  bytea NOT NULL,
	addr6       inet,
	addr4       inet,
	listen_port integer NOT NULL,
	state       text NOT NULL,
	expires     timestamptz NOT NULL,
	created     timestamptz NOT NULL,
	ended       timestamptz NOT NULL,
	drained     boolean NOT NULL
);
CREATE INDEX interfaces_network ON interfaces (network, id);
CREATE INDEX interfaces_host ON interfaces (host, id);
-- The sweep's three scans: Expired, Undrained and Ended. Each query repeats
-- its index's predicate, so the planner can use it.
CREATE INDEX interfaces_expiry ON interfaces (expires, id) WHERE state = 'live';
CREATE INDEX interfaces_undrained ON interfaces (ended, id) WHERE state = 'released' AND NOT drained;
CREATE INDEX interfaces_ended ON interfaces (ended, id) WHERE state <> 'live' AND drained;

CREATE TABLE rules (
	id           text COLLATE "C" PRIMARY KEY,
	network      text COLLATE "C" NOT NULL,
	from_service text COLLATE "C" NOT NULL,
	to_service   text COLLATE "C" NOT NULL,
	proto        text NOT NULL,
	port_lo      integer NOT NULL,
	port_hi      integer NOT NULL,
	created      timestamptz NOT NULL
);
CREATE INDEX rules_network ON rules (network, id);

CREATE TABLE edges (
	network   text COLLATE "C" NOT NULL,
	a         text COLLATE "C" NOT NULL,
	b         text COLLATE "C" NOT NULL,
	secret_ab bytea NOT NULL,
	secret_ba bytea NOT NULL,
	-- ports is a JSON array of store.EdgePorts.
	ports     jsonb NOT NULL,
	created   timestamptz NOT NULL,
	-- dormant is NULL while policy connects the pair.
	dormant   timestamptz,
	PRIMARY KEY (network, a, b)
);
-- RelayEdges finds a relay's edges by containment: ports @> '[{"relay": id}]'.
CREATE INDEX edges_ports ON edges USING gin (ports jsonb_path_ops);
CREATE INDEX edges_dormant ON edges (dormant, network, a, b) WHERE dormant IS NOT NULL;

CREATE TABLE hosts (
	id         text COLLATE "C" PRIMARY KEY,
	name       text COLLATE "C" NOT NULL UNIQUE,
	token_hash bytea NOT NULL,
	endpoint   text NOT NULL,
	revision   bigint NOT NULL,
	created    timestamptz NOT NULL
);
CREATE INDEX hosts_token ON hosts (token_hash, id);

CREATE TABLE relays (
	id         text COLLATE "C" PRIMARY KEY,
	name       text COLLATE "C" NOT NULL UNIQUE,
	token_hash bytea NOT NULL,
	-- addresses is a JSON array of api.RelayAddress.
	addresses  jsonb NOT NULL,
	port_lo    integer NOT NULL,
	port_hi    integer NOT NULL,
	probe_port integer NOT NULL,
	revision   bigint NOT NULL,
	created    timestamptz NOT NULL
);
CREATE INDEX relays_token ON relays (token_hash, id);

CREATE TABLE released4 (
	network text COLLATE "C" NOT NULL,
	addr    inet NOT NULL,
	at      timestamptz NOT NULL,
	PRIMARY KEY (network, addr)
);
CREATE INDEX released4_at ON released4 (network, at, addr);

CREATE TABLE released_ports (
	relay text COLLATE "C" NOT NULL,
	addr  inet NOT NULL,
	port  integer NOT NULL,
	at    timestamptz NOT NULL,
	PRIMARY KEY (relay, addr, port)
);
CREATE INDEX released_ports_at ON released_ports (relay, addr, at, port);

CREATE TABLE port_cursors (
	relay text COLLATE "C" NOT NULL,
	addr  inet NOT NULL,
	next  integer NOT NULL,
	PRIMARY KEY (relay, addr)
);

CREATE TABLE meta (
	key   text COLLATE "C" PRIMARY KEY,
	value text NOT NULL
);

-- revision holds the last revision handed out, in its one row. Every
-- transaction that bumps updates the row, so bumping transactions commit one
-- at a time and their revisions follow commit order. A sequence hands out
-- numbers in call order instead, so a reader could see revision 7 committed
-- while 6 is still in flight, and a long poll past 7 would miss 6.
CREATE TABLE revision (
	id  boolean PRIMARY KEY DEFAULT true CHECK (id),
	seq bigint NOT NULL
);
INSERT INTO revision (seq) VALUES (0);
