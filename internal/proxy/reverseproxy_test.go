package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kovaron/tessera/internal/audit"
	"github.com/kovaron/tessera/internal/store"
	"github.com/kovaron/tessera/internal/upstreams"
)

type fakeSecrets struct{ v string }

func (f fakeSecrets) Resolve(_ context.Context, _ string) ([]byte, error) {
	return []byte(f.v), nil
}

func TestReverseProxyInjectsAndForwards(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	reg := upstreams.NewRegistry()
	reg.Set(upstreams.Upstream{
		ID: "u", BaseURL: upstream.URL,
		Inject: upstreams.InjectRule{Type: "bearer", SecretRef: "fake://"},
	})

	rp := NewReverseProxy(reg, fakeSecrets{v: "upstream-token"}, audit.New(io.Discard))
	h := InjectMiddleware(rp)
	tok := &store.Token{ID: "t", UpstreamID: "u"}
	req := httptest.NewRequest("GET", "/u/u/echo", nil)
	req.Header.Set("Authorization", "Bearer subtoken")
	ctx := context.WithValue(req.Context(), tokenKey, tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != 200 {
		t.Fatalf("code=%d", rec.Code)
	}
	if gotAuth != "Bearer upstream-token" {
		t.Fatalf("upstream auth=%q", gotAuth)
	}
}
