package store

import (
	"context"
	"testing"
	"time"
)

func TestKeystoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := mustOpen(t)
	defer s.Close()

	if k, err := s.GetKeystore(ctx); err != nil || k != nil {
		t.Fatalf("expected nil keystore, got %v %v", k, err)
	}

	in := Keystore{
		DEKWrapped: []byte("wrapped"),
		KEKSource:  "passphrase",
		KDFParams:  []byte("{}"),
		CreatedAt:  time.Now().Unix(),
	}
	if err := s.PutKeystore(ctx, in); err != nil {
		t.Fatal(err)
	}
	out, err := s.GetKeystore(ctx)
	if err != nil || out == nil {
		t.Fatalf("got %v %v", out, err)
	}
	if string(out.DEKWrapped) != "wrapped" || out.KEKSource != "passphrase" {
		t.Fatalf("mismatch: %+v", out)
	}
}

func mustOpen(t *testing.T) Store {
	t.Helper()
	s, err := OpenSQLite(t.TempDir() + "/x.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}
