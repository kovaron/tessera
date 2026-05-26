package authn

import (
	"context"
	"testing"
	"time"

	"github.com/kovaron/tessera/internal/store"
)

func TestGenerateAndHash(t *testing.T) {
	plain, hash, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) < 40 {
		t.Fatalf("short token: %q", plain)
	}
	if len(hash) != 32 {
		t.Fatalf("hash len = %d", len(hash))
	}
	if got := Hash(plain); !bytesEqual(got, hash) {
		t.Fatal("hash mismatch")
	}
}

func TestAuthLookupAcceptRejectRevoked(t *testing.T) {
	ctx := context.Background()
	s := mustOpenStore(t)
	defer s.Close()

	plain, hash, _ := Generate()
	parentID := "p1"
	_ = s.InsertToken(ctx, store.Token{ID: parentID, Hash: []byte("phash"), Label: "p", PolicyID: "pol", UpstreamID: "u", CreatedAt: time.Now().Unix()})
	_ = s.InsertToken(ctx, store.Token{ID: "c1", Hash: hash, ParentID: &parentID, Label: "c", PolicyID: "pol", UpstreamID: "u", CreatedAt: time.Now().Unix()})

	tok, err := Resolve(ctx, s, plain, time.Now())
	if err != nil || tok == nil {
		t.Fatalf("resolve: %v %v", tok, err)
	}

	if err := s.RevokeToken(ctx, parentID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(ctx, s, plain, time.Now()); err == nil {
		t.Fatal("expected revoked-parent rejection")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestExpiryAtBoundary(t *testing.T) {
	ctx := context.Background()
	s := mustOpenStore(t)
	defer s.Close()

	plain, hash, _ := Generate()
	now := time.Now().Unix()
	exp := now
	s.InsertToken(ctx, store.Token{ID: "t", Hash: hash, Label: "x", PolicyID: "p", UpstreamID: "u", CreatedAt: now - 10, ExpiresAt: &exp})

	if _, err := Resolve(ctx, s, plain, time.Unix(now, 0)); err == nil {
		t.Fatal("expected expired at boundary")
	}
}

func mustOpenStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.OpenSQLite(t.TempDir() + "/x.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}
