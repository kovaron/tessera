package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"time"
)

type LeafFactory struct {
	ca    *CA
	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

func NewLeafFactory(ca *CA) *LeafFactory {
	return &LeafFactory{ca: ca, cache: make(map[string]*tls.Certificate)}
}

func (f *LeafFactory) LeafFor(host string) (*tls.Certificate, error) {
	f.mu.Lock()
	if c, ok := f.cache[host]; ok && time.Until(c.Leaf.NotAfter) >= 24*time.Hour {
		f.mu.Unlock()
		return c, nil
	}
	f.mu.Unlock()

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
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.AddDate(0, 0, 30),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca.Cert, &key.PublicKey, f.ca.Key)
	if err != nil {
		return nil, err
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{der, f.ca.Cert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}

	f.mu.Lock()
	if existing, ok := f.cache[host]; ok && time.Until(existing.Leaf.NotAfter) >= 24*time.Hour {
		f.mu.Unlock()
		return existing, nil
	}
	f.cache[host] = cert
	f.mu.Unlock()

	return cert, nil
}

func (f *LeafFactory) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return f.LeafFor(hello.ServerName)
}

// CAPEM returns the PEM-encoded CA certificate.
func (f *LeafFactory) CAPEM() []byte {
	return f.ca.CertPEM()
}
