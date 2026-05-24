package store

import (
	"context"
	"database/sql"
	"errors"
)

func (s *sqliteStore) InsertPolicy(ctx context.Context, p PolicyRow) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO policies(id, engine, source_ct, source_nonce, subset_of, created_at) VALUES (?,?,?,?,?,?)`,
		p.ID, p.Engine, p.SourceCT, p.SourceNonce, nullStr(p.SubsetOf), p.CreatedAt)
	return err
}

func (s *sqliteStore) GetPolicy(ctx context.Context, id string) (*PolicyRow, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, engine, source_ct, source_nonce, subset_of, created_at FROM policies WHERE id=?`, id)
	var p PolicyRow
	var subset sql.NullString
	err := row.Scan(&p.ID, &p.Engine, &p.SourceCT, &p.SourceNonce, &subset, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if subset.Valid {
		p.SubsetOf = &subset.String
	}
	return &p, nil
}

func (s *sqliteStore) UpdatePolicy(ctx context.Context, p PolicyRow) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE policies SET engine=?, source_ct=?, source_nonce=?, subset_of=? WHERE id=?`,
		p.Engine, p.SourceCT, p.SourceNonce, nullStr(p.SubsetOf), p.ID)
	return err
}

func (s *sqliteStore) DeletePolicy(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM policies WHERE id=?`, id)
	return err
}

func (s *sqliteStore) ListPolicies(ctx context.Context) ([]PolicyRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, engine, source_ct, source_nonce, subset_of, created_at FROM policies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PolicyRow
	for rows.Next() {
		var p PolicyRow
		var subset sql.NullString
		if err := rows.Scan(&p.ID, &p.Engine, &p.SourceCT, &p.SourceNonce, &subset, &p.CreatedAt); err != nil {
			return nil, err
		}
		if subset.Valid {
			p.SubsetOf = &subset.String
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
