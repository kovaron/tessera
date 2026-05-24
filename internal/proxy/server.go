package proxy

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/kovaron/ai-secrets-manager/internal/audit"
	"github.com/kovaron/ai-secrets-manager/internal/authz"
	"github.com/kovaron/ai-secrets-manager/internal/crypto"
	"github.com/kovaron/ai-secrets-manager/internal/store"
	"github.com/kovaron/ai-secrets-manager/internal/upstreams"
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

func (d *DataPlane) Handler() http.Handler {
	src := storePolicySource{s: d.Store, dek: d.DEK}
	rp := NewReverseProxy(d.Upstreams, d.Secrets, d.Audit)
	chain := LockMiddleware(d.IsUnlocked)(
		AuthnMiddleware(d.Store)(
			AuthzMiddleware(d.Engine, d.PolicyCache, src)(
				InjectMiddleware(rp),
			),
		),
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "locked": !d.IsUnlocked()})
			return
		}
		chain.ServeHTTP(w, r)
	})
}
