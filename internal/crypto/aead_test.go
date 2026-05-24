package crypto

import (
	"bytes"
	"testing"
)

func TestAEADRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("hello world")
	aad := []byte("policy:abc")

	ct, nonce, err := AEADSeal(key, plaintext, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(nonce) != 24 {
		t.Fatalf("nonce len = %d, want 24", len(nonce))
	}

	pt, err := AEADOpen(key, nonce, ct, aad)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("got %q want %q", pt, plaintext)
	}
}

func TestAEADTamperFails(t *testing.T) {
	key := make([]byte, 32)
	ct, nonce, _ := AEADSeal(key, []byte("x"), nil)
	ct[0] ^= 0xff
	if _, err := AEADOpen(key, nonce, ct, nil); err == nil {
		t.Fatal("expected tamper to fail")
	}
}

func TestAEADWrongAAD(t *testing.T) {
	key := make([]byte, 32)
	ct, nonce, _ := AEADSeal(key, []byte("x"), []byte("a"))
	if _, err := AEADOpen(key, nonce, ct, []byte("b")); err == nil {
		t.Fatal("expected wrong AAD to fail")
	}
}
