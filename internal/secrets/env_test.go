package secrets

import (
	"context"
	"testing"
)

func TestEnvProviderResolve(t *testing.T) {
	t.Setenv("UPSTREAM_TOKEN", "supersecret")
	r := NewRegistry()
	r.Register(NewEnvProvider())

	sec, err := r.Resolve(context.Background(), "env://UPSTREAM_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if string(sec.Value) != "supersecret" {
		t.Fatalf("got %q", sec.Value)
	}
}

func TestRefParse(t *testing.T) {
	p, rest, err := ParseRef("doppler://prod/api/NAME")
	if err != nil {
		t.Fatal(err)
	}
	if p != "doppler" || rest != "prod/api/NAME" {
		t.Fatalf("got %q %q", p, rest)
	}
}
