package crypto

import "crypto/rand"

func NewDEK() ([]byte, error) {
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	return dek, err
}

func NewSalt() ([]byte, error) {
	s := make([]byte, 16)
	_, err := rand.Read(s)
	return s, err
}
