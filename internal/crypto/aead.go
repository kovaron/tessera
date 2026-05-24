package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEADSeal encrypts and authenticates plaintext under key with optional aad,
// returning the ciphertext+tag and a randomly generated nonce.
// key must be chacha20poly1305.KeySize (32) bytes.
func AEADSeal(key, plaintext, aad []byte) (ct, nonce []byte, err error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, nil, fmt.Errorf("crypto: key must be %d bytes", chacha20poly1305.KeySize)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ct = aead.Seal(nil, nonce, plaintext, aad)
	return ct, nonce, nil
}

// AEADOpen decrypts and authenticates ct under key, nonce, and optional aad.
// key must be chacha20poly1305.KeySize (32) bytes.
func AEADOpen(key, nonce, ct, aad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("crypto: key must be %d bytes", chacha20poly1305.KeySize)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, aad)
}
