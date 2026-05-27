package store

import (
	"context"
	"database/sql"
	"errors"
)

func (s *sqliteStore) InsertPolicy(ctx context.Context, p PolicyRow) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO policies(id, engine, source_ct, source_nonce, subset_of, created_at, name, upstream_id) VALUES (?,?,?,?,?,?,?,?)`,
		p.ID, p.Engine, p.SourceCT, p.SourceNonce, nullStr(p.SubsetOf), p.CreatedAt, p.Name, nullStr(p.UpstreamID))
	return err
}

func (s *sqliteStore) GetPolicy(ctx context.Context, id string) (*PolicyRow, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, engine, source_ct, source_nonce, subset_of, created_at, name, upstream_id FROM policies WHERE id=?`, id)
	p, err := scanPolicy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (s *sqliteStore) UpdatePolicy(ctx context.Context, p PolicyRow) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE policies SET engine=?, source_ct=?, source_nonce=?, subset_of=?, name=?, upstream_id=? WHERE id=?`,
		p.Engine, p.SourceCT, p.SourceNonce, nullStr(p.SubsetOf), p.Name, nullStr(p.UpstreamID), p.ID)
	return err
}

func (s *sqliteStore) DeletePolicy(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM policies WHERE id=?`, id)
	return err
}

func (s *sqliteStore) ListPolicies(ctx context.Context) ([]PolicyRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, engine, source_ct, source_nonce, subset_of, created_at, name, upstream_id FROM policies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PolicyRow
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanPolicy(r rowScanner) (*PolicyRow, error) {
	var p PolicyRow
	var subset, upstream sql.NullString
	if err := r.Scan(&p.ID, &p.Engine, &p.SourceCT, &p.SourceNonce, &subset, &p.CreatedAt, &p.Name, &upstream); err != nil {
		return nil, err
	}
	if subset.Valid {
		p.SubsetOf = &subset.String
	}
	if upstream.Valid {
		p.UpstreamID = &upstream.String
	}
	return &p, nil
}
