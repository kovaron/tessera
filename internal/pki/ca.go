package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"

	"github.com/kovaron/tessera/internal/crypto"
	"github.com/kovaron/tessera/internal/store"
)

type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

func Generate(commonName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.AddDate(10, 0, 0),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		MaxPathLen:     0,
		MaxPathLenZero: true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &CA{Cert: cert, Key: key}, nil
}

func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
}

func (c *CA) WrapWithDEK(dek []byte) (store.CA, error) {
	certPEM := c.CertPEM()

	keyDER, err := x509.MarshalECPrivateKey(c.Key)
	if err != nil {
		return store.CA{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certCT, certNonce, err := crypto.AEADSeal(dek, certPEM, []byte("ca-cert"))
	if err != nil {
		return store.CA{}, err
	}

	keyCT, keyNonce, err := crypto.AEADSeal(dek, keyPEM, []byte("ca-key"))
	if err != nil {
		return store.CA{}, err
	}

	return store.CA{
		CertCT:    certCT,
		CertNonce: certNonce,
		KeyCT:     keyCT,
		KeyNonce:  keyNonce,
		CreatedAt: time.Now().UnixMilli(),
	}, nil
}

func UnwrapWithDEK(dek []byte, w *store.CA) (*CA, error) {
	certPEM, err := crypto.AEADOpen(dek, w.CertNonce, w.CertCT, []byte("ca-cert"))
	if err != nil {
		return nil, err
	}

	keyPEM, err := crypto.AEADOpen(dek, w.KeyNonce, w.KeyCT, []byte("ca-key"))
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("pki: invalid cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("pki: invalid key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &CA{Cert: cert, Key: key}, nil
}
