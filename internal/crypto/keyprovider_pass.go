package crypto

import (
	"context"
	"sync"
)

type PassphraseProvider struct {
	Params Argon2Params
	mu     sync.Mutex
	dek    []byte
}

func (p *PassphraseProvider) Name() string { return "passphrase" }

func (p *PassphraseProvider) WrapNewDEK(_ context.Context, passphrase []byte) (wrapped, salt []byte, err error) {
	dek, err := NewDEK()
	if err != nil {
		return nil, nil, err
	}
	salt, err = NewSalt()
	if err != nil {
		return nil, nil, err
	}
	kek := DeriveKey(passphrase, salt, p.Params)
	ct, nonce, err := AEADSeal(kek, dek, []byte("envelope:v1"))
	if err != nil {
		return nil, nil, err
	}
	wrapped = append(nonce, ct...)
	zero(dek)
	zero(kek)
	return wrapped, salt, nil
}

func (p *PassphraseProvider) UnwrapDEK(_ context.Context, wrapped, salt, passphrase []byte) ([]byte, error) {
	if len(wrapped) < 24 {
		return nil, errShort
	}
	nonce, ct := wrapped[:24], wrapped[24:]
	kek := DeriveKey(passphrase, salt, p.Params)
	defer zero(kek)
	return AEADOpen(kek, nonce, ct, []byte("envelope:v1"))
}

// Unlock is the KeyProvider entrypoint at server start.
// input must be a struct{ Wrapped, Salt, Passphrase []byte }.
func (p *PassphraseProvider) Unlock(ctx context.Context, input any) ([]byte, error) {
	in, ok := input.(PassphraseUnlockInput)
	if !ok {
		return nil, errBadInput
	}
	dek, err := p.UnwrapDEK(ctx, in.Wrapped, in.Salt, in.Passphrase)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.dek = append([]byte(nil), dek...)
	p.mu.Unlock()
	return dek, nil
}

func (p *PassphraseProvider) Lock() {
	p.mu.Lock()
	defer p.mu.Unlock()
	zero(p.dek)
	p.dek = nil
}

type PassphraseUnlockInput struct {
	Wrapped    []byte
	Salt       []byte
	Passphrase []byte
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

var (
	errShort    = errString("crypto: wrapped DEK too short")
	errBadInput = errString("crypto: bad unlock input")
)

type errString string

func (e errString) Error() string { return string(e) }
