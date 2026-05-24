package store

import (
	"context"
	"testing"
	"time"
)

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
