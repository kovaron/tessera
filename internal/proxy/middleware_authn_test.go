package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kovaron/tessera/internal/authn"
	"github.com/kovaron/tessera/internal/store"
)

func TestAuthnAcceptsValid(t *testing.T) {
	ctx := context.Background()
	s, _ := store.OpenSQLite(t.TempDir() + "/db")
	s.Migrate(ctx)
	plain, hash, _ := authn.Generate()
	s.InsertToken(ctx, store.Token{ID: "t", Hash: hash, Label: "x", PolicyID: "p", UpstreamID: "u", CreatedAt: time.Now().Unix()})

	mw := AuthnMiddleware(s)
	var seen *store.Token
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = TokenFromContext(r.Context())
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+plain)
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)
	if rec.Code != 200 || seen == nil || seen.ID != "t" {
		t.Fatalf("code=%d seen=%v", rec.Code, seen)
	}
}

func TestAuthnRejects401(t *testing.T) {
	ctx := context.Background()
	s, _ := store.OpenSQLite(t.TempDir() + "/db")
	s.Migrate(ctx)

	mw := AuthnMiddleware(s)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer nope")
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("code=%d", rec.Code)
	}
}
