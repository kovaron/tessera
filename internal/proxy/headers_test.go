package proxy

import (
	"net/http"
	"testing"
)

func TestStripAndAllowlist(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer x")
	h.Set("Cookie", "c=1")
	h.Set("X-Trace", "abc")
	h.Set("User-Agent", "test")
	Sanitize(h)
	if h.Get("Authorization") != "" || h.Get("Cookie") != "" {
		t.Fatal("auth/cookie not stripped")
	}
	if h.Get("X-Trace") != "abc" || h.Get("User-Agent") != "test" {
		t.Fatal("allowlisted header lost")
	}
}
