package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestForeignKeysEnforced(t *testing.T) {
	s := mustOpen(t)
	defer s.Close()
	ctx := context.Background()
	bogus := "nonexistent"
	err := s.InsertToken(ctx, Token{ID: "child", Hash: []byte("h"), ParentID: &bogus, Label: "c", PolicyID: "p", UpstreamID: "u", CreatedAt: 0})
	if err == nil {
		t.Fatal("expected FK violation, got nil")
	}
}

func TestOpenAndMigrate(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenSQLite(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate twice: %v", err)
	}
}
