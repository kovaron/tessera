package crypto

import "golang.org/x/crypto/argon2"

type Argon2Params struct {
	Time        uint32
	MemoryKB    uint32
	Parallelism uint8
	KeyLen      uint32
}

func DefaultArgon2() Argon2Params {
	return Argon2Params{Time: 3, MemoryKB: 64 * 1024, Parallelism: 4, KeyLen: 32}
}

func DeriveKey(passphrase, salt []byte, p Argon2Params) []byte {
	return argon2.IDKey(passphrase, salt, p.Time, p.MemoryKB, p.Parallelism, p.KeyLen)
}
