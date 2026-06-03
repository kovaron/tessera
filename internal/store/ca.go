package store

import (
	"context"
	"database/sql"
	"errors"
)

func (s *sqliteStore) GetCA(ctx context.Context) (*CA, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT cert_pem_ct, cert_pem_nonce, key_pem_ct, key_pem_nonce, created_at FROM keystore_ca WHERE id=1`)
	var c CA
	if err := row.Scan(&c.CertCT, &c.CertNonce, &c.KeyCT, &c.KeyNonce, &c.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &c, nil
}

func (s *sqliteStore) PutCA(ctx context.Context, c CA) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO keystore_ca(id, cert_pem_ct, cert_pem_nonce, key_pem_ct, key_pem_nonce, created_at)
         VALUES (1,?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET
           cert_pem_ct=excluded.cert_pem_ct,
           cert_pem_nonce=excluded.cert_pem_nonce,
           key_pem_ct=excluded.key_pem_ct,
           key_pem_nonce=excluded.key_pem_nonce,
           created_at=excluded.created_at`,
		c.CertCT, c.CertNonce, c.KeyCT, c.KeyNonce, c.CreatedAt)
	return err
}
