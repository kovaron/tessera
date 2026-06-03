package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

func hostnamesJSON(h []string) (string, error) {
	if h == nil {
		return "[]", nil
	}
	b, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parseHostnames(s string) ([]string, error) {
	if s == "" {
		return []string{}, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *sqliteStore) UpsertUpstream(ctx context.Context, u Upstream) error {
	hj, err := hostnamesJSON(u.Hostnames)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO upstreams(id, base_url, inject, hostnames, created_at) VALUES (?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET base_url=excluded.base_url, inject=excluded.inject, hostnames=excluded.hostnames`,
		u.ID, u.BaseURL, string(u.InjectJSON), hj, u.CreatedAt)
	return err
}

func (s *sqliteStore) GetUpstream(ctx context.Context, id string) (*Upstream, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, base_url, inject, hostnames, created_at FROM upstreams WHERE id=?`, id)
	var u Upstream
	var inject, hostnames string
	err := row.Scan(&u.ID, &u.BaseURL, &inject, &hostnames, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.InjectJSON = []byte(inject)
	h, err := parseHostnames(hostnames)
	if err != nil {
		return nil, err
	}
	u.Hostnames = h
	return &u, nil
}

func (s *sqliteStore) ListUpstreams(ctx context.Context) ([]Upstream, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, base_url, inject, hostnames, created_at FROM upstreams ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Upstream
	for rows.Next() {
		var u Upstream
		var inject, hostnames string
		if err := rows.Scan(&u.ID, &u.BaseURL, &inject, &hostnames, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.InjectJSON = []byte(inject)
		h, err := parseHostnames(hostnames)
		if err != nil {
			return nil, err
		}
		u.Hostnames = h
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *sqliteStore) DeleteUpstream(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE policies SET upstream_id=NULL WHERE upstream_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM upstreams WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}
