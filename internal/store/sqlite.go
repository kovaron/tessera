package store

import (
	"context"
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

func (s *sqliteStore) InsertPolicy(context.Context, PolicyRow) error          { panic("todo") }
func (s *sqliteStore) GetPolicy(context.Context, string) (*PolicyRow, error)  { panic("todo") }
func (s *sqliteStore) UpdatePolicy(context.Context, PolicyRow) error          { panic("todo") }
func (s *sqliteStore) DeletePolicy(context.Context, string) error             { panic("todo") }
func (s *sqliteStore) ListPolicies(context.Context) ([]PolicyRow, error)      { panic("todo") }

