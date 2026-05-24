package store

import (
	"context"
	"database/sql"
	"errors"
)

func (s *sqliteStore) GetKeystore(ctx context.Context) (*Keystore, error) {
	row := s.db.QueryRowContext(ctx, `SELECT dek_wrapped, kek_source, kdf_params, created_at FROM keystore WHERE id=1`)
	var k Keystore
	if err := row.Scan(&k.DEKWrapped, &k.KEKSource, &k.KDFParams, &k.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &k, nil
}

func (s *sqliteStore) PutKeystore(ctx context.Context, k Keystore) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO keystore(id, dek_wrapped, kek_source, kdf_params, created_at)
         VALUES (1,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET dek_wrapped=excluded.dek_wrapped, kek_source=excluded.kek_source, kdf_params=excluded.kdf_params, created_at=excluded.created_at`,
		k.DEKWrapped, k.KEKSource, k.KDFParams, k.CreatedAt)
	return err
}
