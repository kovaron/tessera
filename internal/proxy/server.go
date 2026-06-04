package proxy

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/kovaron/tessera/internal/audit"
	"github.com/kovaron/tessera/internal/authz"
	"github.com/kovaron/tessera/internal/crypto"
	"github.com/kovaron/tessera/internal/store"
	"github.com/kovaron/tessera/internal/upstreams"
)

type DataPlane struct {
	Store       store.Store
	Engine      authz.Engine
	PolicyCache *authz.Cache
	Upstreams   *upstreams.Registry
	Secrets     SecretResolver
	Audit       *audit.Logger
	IsUnlocked  IsUnlocked
	DEK         func() []byte
}

type storePolicySource struct {
	s   store.Store
	dek func() []byte
}

func (sp storePolicySource) Get(ctx context.Context, id string) ([]byte, string, error) {
	p, err := sp.s.GetPolicy(ctx, id)
	if err != nil || p == nil {
		return nil, "", err
	}
	pt, err := crypto.AEADOpen(sp.dek(), p.SourceNonce, p.SourceCT, []byte("policy"))
	if err != nil {
		return nil, "", err
	}
	return pt, p.Engine, nil
}

// buildChain wraps terminal with lock → authn → authz → inject middleware.
func (d *DataPlane) buildChain(terminal http.Handler) http.Handler {
	src := storePolicySource{s: d.Store, dek: d.DEK}
	return LockMiddleware(d.IsUnlocked)(
		AuthnMiddleware(d.Store)(
			AuthzMiddleware(d.Engine, d.PolicyCache, src, d.Audit)(
				InjectMiddleware(terminal),
			),
		),
	)
}

// Handler returns the path-based (/u/<id>/...) handler.
func (d *DataPlane) Handler() http.Handler {
	rp := NewReverseProxy(d.Upstreams, d.Secrets, d.Audit)
	chain := d.buildChain(rp)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Header().Set("Content-Type", "application/json")
			locked := !d.IsUnlocked()
			if locked {
				w.WriteHeader(503)
			} else {
				w.WriteHeader(200)
			}
			json.NewEncoder(w).Encode(map[string]any{"ok": !locked, "locked": locked})
			return
		}
		chain.ServeHTTP(w, r)
	})
}

// HandlerForHostMode returns a handler that resolves the upstream from the
// request Host header instead of the URL path. upstreamID is the ID already
// resolved by the forward listener (via registry.ByHostname); the handler
// verifies the token's upstream_id matches before forwarding.
func (d *DataPlane) HandlerForHostMode(upstreamID string) http.Handler {
	terminal := newHostTerminal(upstreamID, d.Upstreams, d.Secrets, d.Audit)
	return d.buildChain(terminal)
}

// newHostTerminal returns an http.Handler that checks upstream_id, resolves
// the upstream, and forwards via httputil.ReverseProxy.
func newHostTerminal(upstreamID string, reg *upstreams.Registry, secrets SecretResolver, log *audit.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := TokenFromContext(r.Context())
		if !ok {
			http.Error(w, "no token", http.StatusUnauthorized)
			return
		}
		if tok.UpstreamID != upstreamID {
			log.Emit(audit.Event{
				TokenID:    tok.ID,
				TokenLabel: tok.Label,
				UpstreamID: upstreamID,
				Method:     r.Method,
				Path:       r.URL.Path,
				Decision:   "deny",
				DenyReason: "upstream_mismatch",
				Status:     http.StatusForbidden,
				RemoteAddr: r.RemoteAddr,
			})
			http.Error(w, "upstream mismatch", http.StatusForbidden)
			return
		}
		forwardToUpstream(upstreamID, reg, secrets, log, w, r, tok, r.URL.Path)
	})
}
