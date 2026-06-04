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

	"github.com/kovaron/tessera/internal/audit"
	"github.com/kovaron/tessera/internal/store"
	"github.com/kovaron/tessera/internal/upstreams"
)

type SecretResolver interface {
	Resolve(ctx context.Context, ref string) ([]byte, error)
}

// forwardToUpstream resolves the upstream by id, resolves the secret, and
// reverse-proxies the request. r.URL.Path is the upstream-relative path used
// for the director; auditPath is logged in audit events (pass r.URL.Path when
// no rewriting is needed, or the original pre-rewrite path in path-mode).
func forwardToUpstream(id string, reg *upstreams.Registry, secrets SecretResolver, log *audit.Logger, w http.ResponseWriter, r *http.Request, tok *store.Token, auditPath string) {
	emitFail := func(reason string, status int) {
		ev := audit.Event{
			Method:     r.Method,
			Path:       auditPath,
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

	up, ok := reg.Get(id)
	if !ok {
		emitFail("unknown_upstream", http.StatusNotFound)
		http.Error(w, "unknown upstream", http.StatusNotFound)
		return
	}
	target, err := url.Parse(up.BaseURL)
	if err != nil {
		emitFail("bad_upstream_url: "+err.Error(), http.StatusInternalServerError)
		http.Error(w, "bad upstream url", http.StatusInternalServerError)
		return
	}
	sec, err := secrets.Resolve(r.Context(), up.Inject.SecretRef)
	if err != nil {
		emitFail("secret_resolve_failed: "+err.Error(), http.StatusBadGateway)
		http.Error(w, "secret resolve failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	reqPath := r.URL.Path
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = path.Clean(strings.TrimSuffix(target.Path, "/") + reqPath)
		req.Host = target.Host
		Sanitize(req.Header)
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
		Path:           auditPath,
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
		// Rewrite path to strip the /u/<id> prefix before passing to forwardToUpstream.
		// Pass the original full path as auditPath so audit logs /u/<id>/... not just rest.
		origPath := r.URL.Path
		r2 := r.Clone(r.Context())
		r2.URL.Path = rest
		forwardToUpstream(id, reg, secrets, log, w, r2, tok, origPath)
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
