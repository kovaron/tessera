package proxy

import (
	"net/http/httptest"
	"testing"
)

func TestParseUpstreamPath(t *testing.T) {
	id, rest, ok := ParseUpstreamPath("/u/github/repos/x/y")
	if !ok || id != "github" || rest != "/repos/x/y" {
		t.Fatalf("got %q %q %v", id, rest, ok)
	}
	if _, _, ok := ParseUpstreamPath("/nope"); ok {
		t.Fatal("expected ok=false")
	}
	if _, _, ok := ParseUpstreamPath("/u/"); ok {
		t.Fatal("expected ok=false")
	}
}

func TestParseUpstreamRequest(t *testing.T) {
	req := httptest.NewRequest("GET", "/u/github/repos/x?state=open", nil)
	id, _, ok := ParseUpstreamPath(req.URL.Path)
	if !ok || id != "github" {
		t.Fatalf("id=%q ok=%v", id, ok)
	}
}
