package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/kovaron/ai-secrets-manager/internal/audit"
	"github.com/kovaron/ai-secrets-manager/internal/store"
	"github.com/kovaron/ai-secrets-manager/internal/upstreams"
)

type SecretResolver interface {
	Resolve(ctx context.Context, ref string) ([]byte, error)
}

func NewReverseProxy(reg *upstreams.Registry, secrets SecretResolver, log *audit.Logger) http.Handler {
	emitFail := func(r *http.Request, tok *store.Token, id, reason string, status int) {
		ev := audit.Event{
			Method:     r.Method,
			Path:       r.URL.Path,
			Decision:   "deny",
			DenyReason: reason,
			Status:     status,
			RemoteAddr: r.RemoteAddr,
			UpstreamID: id,
		}
		if tok != nil {
			ev.TokenID = tok.ID
			ev.TokenLabel = tok.Label
		}
		log.Emit(ev)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := TokenFromContext(r.Context())
		if !ok {
			emitFail(r, nil, "", "no_token", http.StatusUnauthorized)
			http.Error(w, "no token", http.StatusUnauthorized)
			return
		}
		id, rest, ok := ParseUpstreamPath(r.URL.Path)
		if !ok || id != tok.UpstreamID {
			emitFail(r, tok, id, "upstream_mismatch", http.StatusForbidden)
			http.Error(w, "upstream mismatch", http.StatusForbidden)
			return
		}
		up, ok := reg.Get(id)
		if !ok {
			emitFail(r, tok, id, "unknown_upstream", http.StatusNotFound)
			http.Error(w, "unknown upstream", http.StatusNotFound)
			return
		}
		target, err := url.Parse(up.BaseURL)
		if err != nil {
			emitFail(r, tok, id, "bad_upstream_url: "+err.Error(), http.StatusInternalServerError)
			http.Error(w, "bad upstream url", http.StatusInternalServerError)
			return
		}
		sec, err := secrets.Resolve(r.Context(), up.Inject.SecretRef)
		if err != nil {
			emitFail(r, tok, id, "secret_resolve_failed: "+err.Error(), http.StatusBadGateway)
			http.Error(w, "secret resolve failed: "+err.Error(), http.StatusBadGateway)
			return
		}

		director := func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = path.Clean(strings.TrimSuffix(target.Path, "/") + rest)
			req.Host = target.Host
			Sanitize(req.Header) // authoritative strip; InjectMiddleware also strips upstream of here (defense in depth)
			if err := upstreams.Apply(up.Inject, req, sec); err != nil {
				req.Header.Set("X-Inject-Error", err.Error())
			}
		}
		var upstreamErr string
		rp := &httputil.ReverseProxy{
			Director: director,
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, e error) {
				upstreamErr = e.Error()
				http.Error(w, fmt.Sprintf("upstream: %v", e), http.StatusBadGateway)
			},
		}
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		rp.ServeHTTP(sw, r)
		ev := audit.Event{
			TokenID:        tok.ID,
			TokenLabel:     tok.Label,
			UpstreamID:     id,
			Method:         r.Method,
			Path:           r.URL.Path,
			QueryKeys:      keysOf(r.URL.Query()),
			Decision:       "allow",
			UpstreamStatus: sw.status,
			Status:         sw.status,
			LatencyMS:      time.Since(start).Milliseconds(),
			RemoteAddr:     r.RemoteAddr,
		}
		if upstreamErr != "" {
			ev.DenyReason = "upstream_error: " + upstreamErr
		}
		log.Emit(ev)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func keysOf(v map[string][]string) []string {
	out := make([]string, 0, len(v))
	for k := range v {
		out = append(out, k)
	}
	return out
}
