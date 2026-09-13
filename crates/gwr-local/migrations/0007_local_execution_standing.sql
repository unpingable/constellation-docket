-- Prospective, operator-owned Docket execution standing. Revision rows are
-- immutable observations; the projection selects the latest operator state.
CREATE TABLE IF NOT EXISTS local_execution_standing_deployment (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  mode TEXT NOT NULL CHECK(mode = 'snapshot_currentness'),
  operator TEXT NOT NULL,
  max_lifetime_ms INTEGER NOT NULL CHECK(max_lifetime_ms = 300000)
) STRICT;

CREATE TABLE IF NOT EXISTS local_execution_standing_grant (
  execution_standing TEXT PRIMARY KEY,
  operator TEXT NOT NULL,
  campaign TEXT NOT NULL,
  occurrence TEXT NOT NULL,
  program TEXT NOT NULL,
  work_schema TEXT NOT NULL,
  work TEXT NOT NULL,
  subject TEXT NOT NULL,
  scope TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS local_execution_standing_revision (
  execution_standing TEXT NOT NULL,
  revision INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('current','revoked','superseded')),
  changed_at INTEGER NOT NULL,
  currentness TEXT NOT NULL UNIQUE,
  PRIMARY KEY(execution_standing, revision),
  FOREIGN KEY(execution_standing) REFERENCES local_execution_standing_grant(execution_standing)
) STRICT;

CREATE TABLE IF NOT EXISTS local_execution_standing_projection (
  execution_standing TEXT PRIMARY KEY,
  revision INTEGER NOT NULL,
  FOREIGN KEY(execution_standing, revision)
    REFERENCES local_execution_standing_revision(execution_standing, revision)
) STRICT;

-- Exact observed local receipt retained with custody. Historical external V1
-- resolver rows legitimately have no entry here.
CREATE TABLE IF NOT EXISTS governed_local_standing_snapshot (
  issuance TEXT PRIMARY KEY,
  execution_standing TEXT NOT NULL UNIQUE,
  revision INTEGER NOT NULL,
  status TEXT NOT NULL,
  resolved_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  currentness TEXT NOT NULL,
  resolution TEXT NOT NULL,
  FOREIGN KEY(issuance) REFERENCES governed_loop_attempt(issuance)
) STRICT;
