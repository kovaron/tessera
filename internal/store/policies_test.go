package store

import (
	"context"
	"testing"
	"time"
)

func TestPoliciesCRUD(t *testing.T) {
	ctx := context.Background()
	s := mustOpen(t)
	defer s.Close()

	p := PolicyRow{
		ID: "p1", Engine: "opa",
		SourceCT: []byte("ct"), SourceNonce: []byte("nonce"),
		CreatedAt: time.Now().Unix(),
	}
	if err := s.InsertPolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPolicy(ctx, "p1")
	if err != nil || got.Engine != "opa" {
		t.Fatalf("got %v err %v", got, err)
	}
	p.SourceCT = []byte("ct2")
	s.UpdatePolicy(ctx, p)
	got, _ = s.GetPolicy(ctx, "p1")
	if string(got.SourceCT) != "ct2" {
		t.Fatal("update failed")
	}
	if err := s.DeletePolicy(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetPolicy(ctx, "p1"); got != nil {
		t.Fatal("expected nil")
	}
}
