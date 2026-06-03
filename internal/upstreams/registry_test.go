package upstreams

import (
	"testing"
)

func TestRegistry_ByHostname(t *testing.T) {
	r := NewRegistry()
	r.Set(Upstream{ID: "openai", BaseURL: "https://api.openai.com",
		Hostnames: []string{"api.openai.com", "api.openai.cn"}})
	u, ok := r.ByHostname("api.openai.com")
	if !ok || u.ID != "openai" {
		t.Fatal("lookup failed")
	}
	u, ok = r.ByHostname("api.openai.cn")
	if !ok || u.ID != "openai" {
		t.Fatal("alt host lookup failed")
	}
	_, ok = r.ByHostname("api.github.com")
	if ok {
		t.Fatal("expected miss")
	}
}

func TestRegistry_UpdateHostnames(t *testing.T) {
	r := NewRegistry()
	r.Set(Upstream{ID: "x", Hostnames: []string{"a.test", "b.test"}})
	r.Set(Upstream{ID: "x", Hostnames: []string{"b.test", "c.test"}}) // a.test removed
	if _, ok := r.ByHostname("a.test"); ok {
		t.Fatal("a.test should be gone")
	}
	if _, ok := r.ByHostname("b.test"); !ok {
		t.Fatal("b.test should remain")
	}
	if _, ok := r.ByHostname("c.test"); !ok {
		t.Fatal("c.test should be added")
	}
}

func TestRegistry_DeleteClearsHostnames(t *testing.T) {
	r := NewRegistry()
	r.Set(Upstream{ID: "x", Hostnames: []string{"a.test"}})
	r.Delete("x")
	if _, ok := r.ByHostname("a.test"); ok {
		t.Fatal("a.test should be cleared")
	}
}
