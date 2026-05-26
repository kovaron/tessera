package proxy

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/kovaron/tessera/internal/authn"
	"github.com/kovaron/tessera/internal/store"
)

type ctxKey int

const tokenKey ctxKey = 1

func TokenFromContext(ctx context.Context) (*store.Token, bool) {
	t, ok := ctx.Value(tokenKey).(*store.Token)
	return t, ok
}

func WithToken(ctx context.Context, t *store.Token) context.Context {
	return context.WithValue(ctx, tokenKey, t)
}

func AuthnMiddleware(s store.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				http.Error(w, "missing bearer", http.StatusUnauthorized)
				return
			}
			plain := strings.TrimPrefix(h, "Bearer ")
			t, err := authn.Resolve(r.Context(), s, plain, time.Now())
			if err != nil || t == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), tokenKey, t)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
