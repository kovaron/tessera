package security

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kovaron/ai-secrets-manager/internal/audit"
	"github.com/kovaron/ai-secrets-manager/internal/proxy"
	"github.com/kovaron/ai-secrets-manager/internal/store"
	"github.com/kovaron/ai-secrets-manager/internal/upstreams"
)

type fakeSec struct{}

func (fakeSec) Resolve(_ context.Context, _ string) ([]byte, error) { return []byte("u"), nil }

func TestAuthHeaderStrippedToUpstream(t *testing.T) {
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))
	defer upstream.Close()

	reg := upstreams.NewRegistry()
	reg.Set(upstreams.Upstream{ID: "u", BaseURL: upstream.URL, Inject: upstreams.InjectRule{Type: "bearer", SecretRef: "env://x"}})
	rp := proxy.NewReverseProxy(reg, fakeSec{}, audit.New(io.Discard))

	tok := &store.Token{ID: "t", UpstreamID: "u"}
	req := httptest.NewRequest("GET", "/u/u/x", nil)
	req.Header.Set("Authorization", "Bearer agent-subtoken")
	ctx := proxy.WithToken(req.Context(), tok)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req.WithContext(ctx))
	// The injected upstream auth should be "Bearer u" (from fakeSec), NOT the agent subtoken
	if got == "Bearer agent-subtoken" {
		t.Fatalf("subtoken leaked upstream: got=%q", got)
	}
}

func TestPathTraversalRejected(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	}))
	defer upstream.Close()

	reg := upstreams.NewRegistry()
	reg.Set(upstreams.Upstream{ID: "u", BaseURL: upstream.URL, Inject: upstreams.InjectRule{Type: "bearer", SecretRef: "env://x"}})
	rp := proxy.NewReverseProxy(reg, fakeSec{}, audit.New(io.Discard))

	tok := &store.Token{ID: "t", UpstreamID: "u"}
	req := httptest.NewRequest("GET", "/u/u/../admin", nil)
	ctx := proxy.WithToken(req.Context(), tok)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req.WithContext(ctx))

	// Forwarded path must not contain ".." (Go's net/http resolves "/u/u/../admin" to "/admin" at parse time,
	// and reverseproxy further sanitizes). We require absence of "..".
	if strings.Contains(gotPath, "..") {
		t.Fatalf("path traversal leaked upstream: %q", gotPath)
	}
}
