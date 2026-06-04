package admin

// install path not tested — shells out to macOS 'security' command

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kovaron/tessera/internal/pki"
)

func TestGetCA_Locked(t *testing.T) {
	// State with no leaf factory (locked / not bootstrapped)
	st := &State{}
	h := NewHandlers(st)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/ca", nil))

	if rec.Code != 503 {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestGetCA_OK(t *testing.T) {
	ca, err := pki.Generate("Tessera Test CA")
	if err != nil {
		t.Fatalf("pki.Generate: %v", err)
	}
	factory := pki.NewLeafFactory(ca)

	st := &State{}
	st.setLeafFactory(factory)
	h := NewHandlers(st)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/ca", nil))

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "application/x-pem-file" {
		t.Fatalf("unexpected Content-Type: %s", ct)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("body does not start with PEM header: %q", body[:min(len(body), 40)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
