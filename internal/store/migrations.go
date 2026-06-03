package store

import (
	"context"
	"strings"
)

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
  created_at INTEGER NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  upstream_id TEXT REFERENCES upstreams(id)
);

CREATE TABLE IF NOT EXISTS upstreams (
  id TEXT PRIMARY KEY,
  base_url TEXT NOT NULL,
  inject TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  hostnames TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS keystore (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  dek_wrapped BLOB NOT NULL,
  kek_source TEXT NOT NULL,
  kdf_params BLOB,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS keystore_ca (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  cert_pem_ct    BLOB NOT NULL,
  cert_pem_nonce BLOB NOT NULL,
  key_pem_ct     BLOB NOT NULL,
  key_pem_nonce  BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
`

func (s *sqliteStore) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return err
	}
	if err := s.addPolicyColumns(ctx); err != nil {
		return err
	}
	if err := s.addUpstreamColumns(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_policies_upstream ON policies(upstream_id)`)
	return err
}

// addPolicyColumns brings pre-existing policies tables up to the new schema.
// Idempotent: skips columns that already exist.
func (s *sqliteStore) addPolicyColumns(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(policies)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	stmts := []struct{ col, ddl string }{
		{"name", `ALTER TABLE policies ADD COLUMN name TEXT NOT NULL DEFAULT ''`},
		{"upstream_id", `ALTER TABLE policies ADD COLUMN upstream_id TEXT REFERENCES upstreams(id)`},
	}
	for _, st := range stmts {
		if have[st.col] {
			continue
		}
		if _, err := s.db.ExecContext(ctx, st.ddl); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	return nil
}

// addUpstreamColumns brings pre-existing upstreams tables up to the new schema.
// Idempotent: skips columns that already exist.
func (s *sqliteStore) addUpstreamColumns(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(upstreams)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	stmts := []struct{ col, ddl string }{
		{"hostnames", `ALTER TABLE upstreams ADD COLUMN hostnames TEXT NOT NULL DEFAULT '[]'`},
	}
	for _, st := range stmts {
		if have[st.col] {
			continue
		}
		if _, err := s.db.ExecContext(ctx, st.ddl); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	return nil
}
