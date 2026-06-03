package store

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestUpstreamHostnamesRoundTrip(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()
	u := Upstream{
		ID: "openai", BaseURL: "https://api.openai.com",
		InjectJSON: json.RawMessage(`{"type":"bearer","secret_ref":"env://OPENAI"}`),
		Hostnames:  []string{"api.openai.com", "api.openai.cn"},
		CreatedAt:  time.Now().Unix(),
	}
	if err := s.UpsertUpstream(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUpstream(ctx, "openai")
	if err != nil || got == nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Hostnames, u.Hostnames) {
		t.Fatalf("got %v want %v", got.Hostnames, u.Hostnames)
	}
}

func TestUpstreamHostnamesEmpty(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()
	u := Upstream{ID: "x", BaseURL: "https://x.test", CreatedAt: 1}
	if err := s.UpsertUpstream(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetUpstream(ctx, "x")
	if len(got.Hostnames) != 0 {
		t.Fatalf("expected empty, got %v", got.Hostnames)
	}
}

func TestUpstreamsCRUD(t *testing.T) {
	ctx := context.Background()
	s := mustOpen(t)
	defer s.Close()

	u := Upstream{ID: "github", BaseURL: "https://api.github.com", InjectJSON: []byte(`{"type":"bearer"}`), CreatedAt: time.Now().Unix()}
	if err := s.UpsertUpstream(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUpstream(ctx, "github")
	if err != nil || got.BaseURL != u.BaseURL {
		t.Fatalf("got %v err %v", got, err)
	}
	list, _ := s.ListUpstreams(ctx)
	if len(list) != 1 {
		t.Fatalf("list len %d", len(list))
	}
	if err := s.DeleteUpstream(ctx, "github"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetUpstream(ctx, "github"); got != nil {
		t.Fatal("expected nil after delete")
	}
}
