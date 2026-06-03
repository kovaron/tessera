package pki

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestGenerate(t *testing.T) {
	ca, err := Generate("Tessera CA")
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Cert.IsCA {
		t.Fatal("not a CA")
	}
	if ca.Cert.Subject.CommonName != "Tessera CA" {
		t.Fatalf("CN: %s", ca.Cert.Subject.CommonName)
	}
	if !ca.Cert.NotAfter.After(time.Now().AddDate(9, 11, 0)) {
		t.Fatal("validity < 10y")
	}
	if ca.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("CertSign missing")
	}
	if ca.Cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("DigitalSignature missing")
	}
	if ca.Cert.MaxPathLen != 0 {
		t.Fatalf("MaxPathLen: %d", ca.Cert.MaxPathLen)
	}
	if !ca.Cert.BasicConstraintsValid {
		t.Fatal("BasicConstraintsValid false")
	}
}

func TestWrapUnwrapWithDEK(t *testing.T) {
	dek := bytes.Repeat([]byte{0xAB}, 32)
	ca, err := Generate("Tessera CA")
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := ca.WrapWithDEK(dek)
	if err != nil {
		t.Fatal(err)
	}
	if wrap.CreatedAt == 0 {
		t.Fatal("CreatedAt zero")
	}
	got, err := UnwrapWithDEK(dek, &wrap)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Cert.Equal(ca.Cert) {
		t.Fatal("cert mismatch after round-trip")
	}
	if got.Key.D.Cmp(ca.Key.D) != 0 {
		t.Fatal("key mismatch after round-trip")
	}
}

func TestUnwrapWithWrongDEK(t *testing.T) {
	dek := bytes.Repeat([]byte{0xAB}, 32)
	bad := bytes.Repeat([]byte{0xCD}, 32)
	ca, err := Generate("Tessera CA")
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := ca.WrapWithDEK(dek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapWithDEK(bad, &wrap); err == nil {
		t.Fatal("expected error with wrong DEK")
	}
}

func TestLeafFor_SANAndChain(t *testing.T) {
	ca, err := Generate("Tessera CA")
	if err != nil {
		t.Fatal(err)
	}
	f := NewLeafFactory(ca)
	cert, err := f.LeafFor("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf.DNSNames[0] != "api.openai.com" {
		t.Fatalf("SAN: %v", cert.Leaf.DNSNames)
	}
	if cert.Leaf.Subject.CommonName != "api.openai.com" {
		t.Fatalf("CN: %s", cert.Leaf.Subject.CommonName)
	}
	if cert.Leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		cert.Leaf.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Fatal("KeyUsage flags missing")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "api.openai.com"}); err != nil {
		t.Fatal("verify:", err)
	}
	if len(cert.Certificate) != 2 {
		t.Fatalf("chain len: %d", len(cert.Certificate))
	}
}

func TestLeafFor_Cache(t *testing.T) {
	ca, err := Generate("Tessera CA")
	if err != nil {
		t.Fatal(err)
	}
	f := NewLeafFactory(ca)
	a, err := f.LeafFor("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.LeafFor("api.openai.com")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("expected same cached cert pointer")
	}
}

func TestLeafFor_DifferentHosts(t *testing.T) {
	ca, err := Generate("Tessera CA")
	if err != nil {
		t.Fatal(err)
	}
	f := NewLeafFactory(ca)
	a, err := f.LeafFor("a.test")
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.LeafFor("b.test")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("expected different certs for different hosts")
	}
	if a.Leaf.DNSNames[0] != "a.test" || b.Leaf.DNSNames[0] != "b.test" {
		t.Fatal("SAN mismatch")
	}
}

func TestGetCertificate(t *testing.T) {
	ca, err := Generate("Tessera CA")
	if err != nil {
		t.Fatal(err)
	}
	f := NewLeafFactory(ca)
	cert, err := f.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.openai.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf.DNSNames[0] != "api.openai.com" {
		t.Fatal("SAN")
	}
}

func TestLeafFor_RefreshNearExpiry(t *testing.T) {
	ca, err := Generate("Tessera CA")
	if err != nil {
		t.Fatal(err)
	}
	f := NewLeafFactory(ca)
	stale := &tls.Certificate{
		Leaf: &x509.Certificate{
			NotAfter: time.Now().Add(1 * time.Hour),
		},
	}
	f.cache["refresh.test"] = stale

	got, err := f.LeafFor("refresh.test")
	if err != nil {
		t.Fatal(err)
	}
	if got == stale {
		t.Fatal("expected stale cert to be replaced")
	}
}
