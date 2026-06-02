package store

import (
	"context"
	"database/sql"
	"errors"
)

func (s *sqliteStore) UpsertUpstream(ctx context.Context, u Upstream) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO upstreams(id, base_url, inject, created_at) VALUES (?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET base_url=excluded.base_url, inject=excluded.inject`,
		u.ID, u.BaseURL, string(u.InjectJSON), u.CreatedAt)
	return err
}

func (s *sqliteStore) GetUpstream(ctx context.Context, id string) (*Upstream, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, base_url, inject, created_at FROM upstreams WHERE id=?`, id)
	var u Upstream
	var inject string
	err := row.Scan(&u.ID, &u.BaseURL, &inject, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.InjectJSON = []byte(inject)
	return &u, nil
}

func (s *sqliteStore) ListUpstreams(ctx context.Context) ([]Upstream, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, base_url, inject, created_at FROM upstreams ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Upstream
	for rows.Next() {
		var u Upstream
		var inject string
		if err := rows.Scan(&u.ID, &u.BaseURL, &inject, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.InjectJSON = []byte(inject)
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
