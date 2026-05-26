package proxy

import (
	"context"
	"net/http"
	"strings"

	"github.com/kovaron/tessera/internal/audit"
	"github.com/kovaron/tessera/internal/authz"
)

// PolicySource returns decrypted policy text and engine name for a policy_id.
type PolicySource interface {
	Get(ctx context.Context, id string) ([]byte, string, error)
}

func AuthzMiddleware(engine authz.Engine, cache *authz.Cache, src PolicySource, log *audit.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, ok := TokenFromContext(r.Context())
			if !ok {
				log.Emit(audit.Event{
					Method:     r.Method,
					Path:       r.URL.Path,
					Decision:   "deny",
					DenyReason: "no_token",
					Status:     http.StatusUnauthorized,
				})
				http.Error(w, "no token", http.StatusUnauthorized)
				return
			}
			srcBytes, _, err := src.Get(r.Context(), tok.PolicyID)
			if err != nil {
				log.Emit(audit.Event{
					TokenID:    tok.ID,
					TokenLabel: tok.Label,
					UpstreamID: tok.UpstreamID,
					Method:     r.Method,
					Path:       r.URL.Path,
					Decision:   "deny",
					DenyReason: "policy_unavailable",
					Status:     http.StatusInternalServerError,
				})
				http.Error(w, "policy unavailable", http.StatusInternalServerError)
				return
			}
			compiled, ok := cache.Get(tok.PolicyID, srcBytes)
			if !ok {
				compiled, err = engine.Compile(srcBytes)
				if err != nil {
					log.Emit(audit.Event{
						TokenID:    tok.ID,
						TokenLabel: tok.Label,
						UpstreamID: tok.UpstreamID,
						Method:     r.Method,
						Path:       r.URL.Path,
						Decision:   "deny",
						DenyReason: "policy_invalid",
						Status:     http.StatusInternalServerError,
					})
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
			if err != nil {
				log.Emit(audit.Event{
					TokenID:    tok.ID,
					TokenLabel: tok.Label,
					UpstreamID: tok.UpstreamID,
					Method:     r.Method,
					Path:       r.URL.Path,
					Decision:   "deny",
					DenyReason: "eval_error",
					Status:     http.StatusForbidden,
				})
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if !d.Allow {
				log.Emit(audit.Event{
					TokenID:    tok.ID,
					TokenLabel: tok.Label,
					UpstreamID: tok.UpstreamID,
					Method:     r.Method,
					Path:       r.URL.Path,
					Decision:   "deny",
					DenyReason: "policy_denied",
					Status:     http.StatusForbidden,
				})
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
