package authn

import (
	"context"
	"errors"
	"time"

	"github.com/kovaron/ai-secrets-manager/internal/store"
)

var (
	ErrUnknown = errors.New("authn: unknown token")
	ErrRevoked = errors.New("authn: token revoked")
	ErrExpired = errors.New("authn: token expired")
	ErrParent  = errors.New("authn: ancestor revoked")
)

const maxParentDepth = 16

func Resolve(ctx context.Context, s store.Store, plain string, now time.Time) (*store.Token, error) {
	t, err := s.LookupTokenByHash(ctx, Hash(plain))
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, ErrUnknown
	}
	if t.RevokedAt != nil {
		return nil, ErrRevoked
	}
	if t.ExpiresAt != nil && now.Unix() >= *t.ExpiresAt {
		return nil, ErrExpired
	}
	cur := t
	for d := 0; d < maxParentDepth; d++ {
		if cur.ParentID == nil {
			return t, nil
		}
		p, err := s.GetToken(ctx, *cur.ParentID)
		if err != nil {
			return nil, err
		}
		if p == nil {
			return nil, ErrUnknown
		}
		if p.RevokedAt != nil {
			return nil, ErrParent
		}
		if p.ExpiresAt != nil && now.Unix() >= *p.ExpiresAt {
			return nil, ErrParent
		}
		cur = p
	}
	return nil, errors.New("authn: parent chain too deep")
}
