package store

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

type sqliteStore struct {
	db *sql.DB
}

func OpenSQLite(path string) (Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	return &sqliteStore{db: db}, nil
}

func (s *sqliteStore) Close() error { return s.db.Close() }
