package crypto

import (
	"context"
	"testing"
)

func TestPassphraseWrapUnwrap(t *testing.T) {
	p := &PassphraseProvider{Params: DefaultArgon2()}
	ctx := context.Background()

	wrapped, salt, err := p.WrapNewDEK(ctx, []byte("correct horse"))
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	dek, err := p.UnwrapDEK(ctx, wrapped, salt, []byte("correct horse"))
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if len(dek) != 32 {
		t.Fatalf("dek len=%d", len(dek))
	}

	if _, err := p.UnwrapDEK(ctx, wrapped, salt, []byte("wrong")); err == nil {
		t.Fatal("expected wrong passphrase to fail")
	}
}
