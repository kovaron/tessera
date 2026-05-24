package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/kovaron/ai-secrets-manager/internal/upstreams"
)

type SecretResolver interface {
	Resolve(ctx context.Context, ref string) ([]byte, error)
}

func NewReverseProxy(reg *upstreams.Registry, secrets SecretResolver) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := TokenFromContext(r.Context())
		if !ok {
			http.Error(w, "no token", http.StatusUnauthorized)
			return
		}
		id, rest, ok := ParseUpstreamPath(r.URL.Path)
		if !ok || id != tok.UpstreamID {
			http.Error(w, "upstream mismatch", http.StatusForbidden)
			return
		}
		up, ok := reg.Get(id)
		if !ok {
			http.Error(w, "unknown upstream", http.StatusNotFound)
			return
		}
		target, err := url.Parse(up.BaseURL)
		if err != nil {
			http.Error(w, "bad upstream url", http.StatusInternalServerError)
			return
		}
		sec, err := secrets.Resolve(r.Context(), up.Inject.SecretRef)
		if err != nil {
			http.Error(w, "secret resolve failed", http.StatusBadGateway)
			return
		}

		director := func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = strings.TrimSuffix(target.Path, "/") + rest
			req.Host = target.Host
			Sanitize(req.Header)
			if err := upstreams.Apply(up.Inject, req, sec); err != nil {
				req.Header.Set("X-Inject-Error", err.Error())
			}
		}
		rp := &httputil.ReverseProxy{
			Director: director,
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, e error) {
				http.Error(w, fmt.Sprintf("upstream: %v", e), http.StatusBadGateway)
			},
		}
		rp.ServeHTTP(w, r)
	})
}
