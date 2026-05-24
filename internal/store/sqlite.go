package store

import (
	"context"
	"database/sql"
	"time"

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

// Panic stubs — replaced in later tasks.
func (s *sqliteStore) InsertToken(context.Context, Token) error                  { panic("todo") }
func (s *sqliteStore) LookupTokenByHash(context.Context, []byte) (*Token, error) { panic("todo") }
func (s *sqliteStore) GetToken(context.Context, string) (*Token, error)          { panic("todo") }
func (s *sqliteStore) ListTokens(context.Context) ([]Token, error)               { panic("todo") }
func (s *sqliteStore) RevokeToken(context.Context, string, time.Time) error      { panic("todo") }
func (s *sqliteStore) ListChildren(context.Context, string) ([]Token, error)     { panic("todo") }

func (s *sqliteStore) InsertPolicy(context.Context, PolicyRow) error          { panic("todo") }
func (s *sqliteStore) GetPolicy(context.Context, string) (*PolicyRow, error)  { panic("todo") }
func (s *sqliteStore) UpdatePolicy(context.Context, PolicyRow) error          { panic("todo") }
func (s *sqliteStore) DeletePolicy(context.Context, string) error             { panic("todo") }
func (s *sqliteStore) ListPolicies(context.Context) ([]PolicyRow, error)      { panic("todo") }

func (s *sqliteStore) UpsertUpstream(context.Context, Upstream) error         { panic("todo") }
func (s *sqliteStore) GetUpstream(context.Context, string) (*Upstream, error) { panic("todo") }
func (s *sqliteStore) ListUpstreams(context.Context) ([]Upstream, error)      { panic("todo") }
func (s *sqliteStore) DeleteUpstream(context.Context, string) error           { panic("todo") }

func (s *sqliteStore) GetKeystore(context.Context) (*Keystore, error) { panic("todo") }
func (s *sqliteStore) PutKeystore(context.Context, Keystore) error    { panic("todo") }
