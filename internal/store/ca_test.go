package store

import (
	"bytes"
	"context"
	"testing"
)

func TestCARoundTrip(t *testing.T) {
	s := mustOpen(t)
	defer s.Close()
	ctx := context.Background()

	in := CA{CertCT: []byte("ct"), CertNonce: []byte("n1"),
		KeyCT: []byte("kct"), KeyNonce: []byte("kn"), CreatedAt: 42}
	if err := s.PutCA(ctx, in); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCA(ctx)
	if err != nil || got == nil {
		t.Fatalf("get: %v %v", err, got)
	}
	if !bytes.Equal(got.CertCT, in.CertCT) || got.CreatedAt != 42 {
		t.Fatal("mismatch")
	}

	// second PutCA replaces the row, not error
	in2 := in
	in2.CertCT = []byte("ct2")
	if err := s.PutCA(ctx, in2); err != nil {
		t.Fatal(err)
	}
	got2, err := s.GetCA(ctx)
	if err != nil || got2 == nil {
		t.Fatal(err, got2)
	}
	if !bytes.Equal(got2.CertCT, []byte("ct2")) {
		t.Fatal("upsert failed")
	}
}

func TestGetCA_EmptyStore(t *testing.T) {
	s := mustOpen(t)
	defer s.Close()
	got, err := s.GetCA(context.Background())
	if err != nil || got != nil {
		t.Fatalf("expected nil CA on empty store, got %v %v", got, err)
	}
}
