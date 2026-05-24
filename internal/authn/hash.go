package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
)

const prefix = "pxy_"

func Generate() (plain string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	plain = prefix + enc
	hash = Hash(plain)
	return plain, hash, nil
}

func Hash(plain string) []byte {
	sum := sha256.Sum256([]byte(plain))
	return sum[:]
}

func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
