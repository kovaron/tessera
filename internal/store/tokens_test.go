package store

import (
	"context"
	"testing"
	"time"
)

func mkTok(id string, parent *string) Token {
	return Token{
		ID: id, Hash: []byte(id + "-hash"), ParentID: parent,
		Label: id, PolicyID: "p", UpstreamID: "u", CreatedAt: time.Now().Unix(),
	}
}

func TestTokensInsertLookupGet(t *testing.T) {
	ctx := context.Background()
	s := mustOpen(t)
	defer s.Close()

	tok := mkTok("a", nil)
	if err := s.InsertToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	got, err := s.LookupTokenByHash(ctx, tok.Hash)
	if err != nil || got == nil || got.ID != "a" {
		t.Fatalf("got %v err %v", got, err)
	}
	got, _ = s.GetToken(ctx, "a")
	if got == nil || got.Label != "a" {
		t.Fatal("get failed")
	}
}

func TestTokensRevokeChildren(t *testing.T) {
	ctx := context.Background()
	s := mustOpen(t)
	defer s.Close()

	aID := "a"
	s.InsertToken(ctx, mkTok("a", nil))
	s.InsertToken(ctx, mkTok("b", &aID))
	bID := "b"
	s.InsertToken(ctx, mkTok("c", &bID))

	kids, _ := s.ListChildren(ctx, "a")
	if len(kids) != 1 || kids[0].ID != "b" {
		t.Fatalf("children of a = %+v", kids)
	}

	if err := s.RevokeToken(ctx, "a", time.Now()); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetToken(ctx, "a")
	if got.RevokedAt == nil {
		t.Fatal("not revoked")
	}
}
