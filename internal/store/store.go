package store

import (
	"context"
	"encoding/json"
	"time"
)

type Store interface {
	Migrate(ctx context.Context) error
	Close() error

	InsertToken(ctx context.Context, t Token) error
	LookupTokenByHash(ctx context.Context, hash []byte) (*Token, error)
	GetToken(ctx context.Context, id string) (*Token, error)
	ListTokens(ctx context.Context) ([]Token, error)
	RevokeToken(ctx context.Context, id string, at time.Time) error
	ListChildren(ctx context.Context, parentID string) ([]Token, error)

	InsertPolicy(ctx context.Context, p PolicyRow) error
	GetPolicy(ctx context.Context, id string) (*PolicyRow, error)
	UpdatePolicy(ctx context.Context, p PolicyRow) error
	DeletePolicy(ctx context.Context, id string) error
	ListPolicies(ctx context.Context) ([]PolicyRow, error)

	UpsertUpstream(ctx context.Context, u Upstream) error
	GetUpstream(ctx context.Context, id string) (*Upstream, error)
	ListUpstreams(ctx context.Context) ([]Upstream, error)
	DeleteUpstream(ctx context.Context, id string) error

	GetKeystore(ctx context.Context) (*Keystore, error)
	PutKeystore(ctx context.Context, k Keystore) error
}

type Token struct {
	ID         string
	Hash       []byte `json:"-"`
	ParentID   *string
	Label      string
	PolicyID   string
	UpstreamID string
	CreatedAt  int64
	ExpiresAt  *int64
	RevokedAt  *int64
	CreatedBy  string
	AdminRole  bool
}

type PolicyRow struct {
	ID          string
	Engine      string
	SourceCT    []byte
	SourceNonce []byte
	SubsetOf    *string
	CreatedAt   int64
}

type Upstream struct {
	ID         string
	BaseURL    string
	InjectJSON json.RawMessage
	CreatedAt  int64
}

type Keystore struct {
	DEKWrapped []byte
	KEKSource  string
	KDFParams  []byte
	CreatedAt  int64
}
