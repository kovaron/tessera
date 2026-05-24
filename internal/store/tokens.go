package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *sqliteStore) InsertToken(ctx context.Context, t Token) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens(id, hash, parent_id, label, policy_id, upstream_id, created_at, expires_at, revoked_at, created_by, admin_role)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		t.ID, t.Hash, nullStr(t.ParentID), t.Label, t.PolicyID, t.UpstreamID, t.CreatedAt,
		nullInt(t.ExpiresAt), nullInt(t.RevokedAt), t.CreatedBy, boolToInt(t.AdminRole))
	return err
}

func (s *sqliteStore) LookupTokenByHash(ctx context.Context, hash []byte) (*Token, error) {
	return s.scanToken(s.db.QueryRowContext(ctx, tokenSelect+` WHERE hash=?`, hash))
}

func (s *sqliteStore) GetToken(ctx context.Context, id string) (*Token, error) {
	return s.scanToken(s.db.QueryRowContext(ctx, tokenSelect+` WHERE id=?`, id))
}

func (s *sqliteStore) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx, tokenSelect+` ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		t, err := scanTokenRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (s *sqliteStore) ListChildren(ctx context.Context, parentID string) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx, tokenSelect+` WHERE parent_id=?`, parentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		t, err := scanTokenRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (s *sqliteStore) RevokeToken(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, at.Unix(), id)
	return err
}

const tokenSelect = `SELECT id, hash, parent_id, label, policy_id, upstream_id, created_at, expires_at, revoked_at, created_by, admin_role FROM tokens`

func (s *sqliteStore) scanToken(r *sql.Row) (*Token, error) {
	var t Token
	var parent sql.NullString
	var exp, rev sql.NullInt64
	var adm int
	err := r.Scan(&t.ID, &t.Hash, &parent, &t.Label, &t.PolicyID, &t.UpstreamID, &t.CreatedAt, &exp, &rev, &t.CreatedBy, &adm)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if parent.Valid {
		t.ParentID = &parent.String
	}
	if exp.Valid {
		v := exp.Int64
		t.ExpiresAt = &v
	}
	if rev.Valid {
		v := rev.Int64
		t.RevokedAt = &v
	}
	t.AdminRole = adm != 0
	return &t, nil
}

func scanTokenRows(r *sql.Rows) (*Token, error) {
	var t Token
	var parent sql.NullString
	var exp, rev sql.NullInt64
	var adm int
	if err := r.Scan(&t.ID, &t.Hash, &parent, &t.Label, &t.PolicyID, &t.UpstreamID, &t.CreatedAt, &exp, &rev, &t.CreatedBy, &adm); err != nil {
		return nil, err
	}
	if parent.Valid {
		t.ParentID = &parent.String
	}
	if exp.Valid {
		v := exp.Int64
		t.ExpiresAt = &v
	}
	if rev.Valid {
		v := rev.Int64
		t.RevokedAt = &v
	}
	t.AdminRole = adm != 0
	return &t, nil
}

func nullStr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}
func nullInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
