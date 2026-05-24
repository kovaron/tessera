package crypto

import (
	"bytes"
	"testing"
)

func TestArgon2Deterministic(t *testing.T) {
	p := Argon2Params{Time: 1, MemoryKB: 8 * 1024, Parallelism: 1, KeyLen: 32}
	salt := []byte("abcdefghijklmnop")
	a := DeriveKey([]byte("hunter2"), salt, p)
	b := DeriveKey([]byte("hunter2"), salt, p)
	if !bytes.Equal(a, b) {
		t.Fatal("non-deterministic")
	}
	if len(a) != 32 {
		t.Fatalf("len=%d", len(a))
	}
}

func TestArgon2DifferentPasswords(t *testing.T) {
	p := Argon2Params{Time: 1, MemoryKB: 8 * 1024, Parallelism: 1, KeyLen: 32}
	salt := []byte("abcdefghijklmnop")
	a := DeriveKey([]byte("a"), salt, p)
	b := DeriveKey([]byte("b"), salt, p)
	if bytes.Equal(a, b) {
		t.Fatal("collision")
	}
}
