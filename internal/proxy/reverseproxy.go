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
	"github.com/kovaron/ai-secrets-manager/internal/upstreams"
)

type SecretResolver interface {
	Resolve(ctx context.Context, ref string) ([]byte, error)
}

func NewReverseProxy(reg *upstreams.Registry, secrets SecretResolver, log *audit.Logger) http.Handler {
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
