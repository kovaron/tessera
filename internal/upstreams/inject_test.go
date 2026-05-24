package upstreams

import (
	"net/http"
	"testing"
)

func TestInjectBearer(t *testing.T) {
	rule := InjectRule{Type: "bearer", SecretRef: "env://X"}
	req, _ := http.NewRequest("GET", "https://api/x", nil)
	if err := Apply(rule, req, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer abc" {
		t.Fatalf("got %q", got)
	}
}

func TestInjectHeaderTemplate(t *testing.T) {
	rule := InjectRule{Type: "header", Name: "X-API-Key", ValueTemplate: "Key ${secret}"}
	req, _ := http.NewRequest("GET", "https://api/x", nil)
	Apply(rule, req, []byte("zz"))
	if got := req.Header.Get("X-API-Key"); got != "Key zz" {
		t.Fatalf("got %q", got)
	}
}

func TestInjectQuery(t *testing.T) {
	rule := InjectRule{Type: "query", Name: "api_key"}
	req, _ := http.NewRequest("GET", "https://api/x", nil)
	Apply(rule, req, []byte("kkk"))
	if got := req.URL.Query().Get("api_key"); got != "kkk" {
		t.Fatalf("got %q", got)
	}
}
