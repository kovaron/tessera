package proxy

import (
	"context"
	"net/http"
	"strings"

	"github.com/kovaron/ai-secrets-manager/internal/authz"
)

// PolicySource returns decrypted policy text and engine name for a policy_id.
type PolicySource interface {
	Get(ctx context.Context, id string) ([]byte, string, error)
}

func AuthzMiddleware(engine authz.Engine, cache *authz.Cache, src PolicySource) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, ok := TokenFromContext(r.Context())
			if !ok {
				http.Error(w, "no token", http.StatusUnauthorized)
				return
			}
			srcBytes, _, err := src.Get(r.Context(), tok.PolicyID)
			if err != nil {
				http.Error(w, "policy unavailable", http.StatusInternalServerError)
				return
			}
			compiled, ok := cache.Get(tok.PolicyID, srcBytes)
			if !ok {
				compiled, err = engine.Compile(srcBytes)
				if err != nil {
					http.Error(w, "policy invalid", http.StatusInternalServerError)
					return
				}
				cache.Put(tok.PolicyID, srcBytes, compiled)
			}
			in := authz.Input{
				Token:    authz.TokenView{ID: tok.ID, Label: tok.Label, CreatedAt: tok.CreatedAt},
				Upstream: tok.UpstreamID,
				Request: authz.RequestView{
					Method:       r.Method,
					Path:         r.URL.Path,
					PathSegments: strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/"),
					Query:        r.URL.Query(),
				},
			}
			d, err := compiled.Eval(r.Context(), in)
			if err != nil || !d.Allow {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
