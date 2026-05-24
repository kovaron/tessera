package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kovaron/ai-secrets-manager/internal/audit"
	"github.com/kovaron/ai-secrets-manager/internal/authz"
	"github.com/kovaron/ai-secrets-manager/internal/store"
)

const policySrc = `package proxy.authz
default allow := false
allow if { input.request.method == "GET" }
`

type fixedPolicySource struct{ src []byte }

func (f fixedPolicySource) Get(_ context.Context, _ string) ([]byte, string, error) {
	return f.src, "opa", nil
}

func TestAuthzAllowsGet(t *testing.T) {
	mw := AuthzMiddleware(authz.NewOPA(), authz.NewCache(), fixedPolicySource{src: []byte(policySrc)}, audit.New(io.Discard))

	tok := &store.Token{ID: "t", PolicyID: "p", UpstreamID: "u"}
	req := httptest.NewRequest("GET", "/u/u/x", nil)
	ctx := context.WithValue(req.Context(), tokenKey, tok)

	rec := httptest.NewRecorder()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mw(next).ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != 200 {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestAuthzDeniesPost(t *testing.T) {
	mw := AuthzMiddleware(authz.NewOPA(), authz.NewCache(), fixedPolicySource{src: []byte(policySrc)}, audit.New(io.Discard))
	tok := &store.Token{ID: "t", PolicyID: "p", UpstreamID: "u"}
	req := httptest.NewRequest("POST", "/u/u/x", nil)
	ctx := context.WithValue(req.Context(), tokenKey, tok)
	rec := httptest.NewRecorder()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	mw(next).ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != 403 {
		t.Fatalf("code=%d", rec.Code)
	}
}
