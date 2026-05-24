package store

import "context"

const schema = `
CREATE TABLE IF NOT EXISTS tokens (
  id TEXT PRIMARY KEY,
  hash BLOB NOT NULL UNIQUE,
  parent_id TEXT REFERENCES tokens(id),
  label TEXT,
  policy_id TEXT,
  upstream_id TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  revoked_at INTEGER,
  created_by TEXT,
  admin_role INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(hash);
CREATE INDEX IF NOT EXISTS idx_tokens_parent ON tokens(parent_id);

CREATE TABLE IF NOT EXISTS policies (
  id TEXT PRIMARY KEY,
  engine TEXT NOT NULL CHECK(engine IN ('opa','cedar')),
  source_ct BLOB NOT NULL,
  source_nonce BLOB NOT NULL,
  subset_of TEXT REFERENCES policies(id),
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS upstreams (
  id TEXT PRIMARY KEY,
  base_url TEXT NOT NULL,
  inject TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS keystore (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  dek_wrapped BLOB NOT NULL,
  kek_source TEXT NOT NULL,
  kdf_params BLOB,
  created_at INTEGER NOT NULL
);
`

func (s *sqliteStore) Migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schema)
	return err
}
