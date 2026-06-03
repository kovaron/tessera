package pki

import (
	"bytes"
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
	ca, _ := Generate("Tessera CA")
	wrap, _ := ca.WrapWithDEK(dek)
	if _, err := UnwrapWithDEK(bad, &wrap); err == nil {
		t.Fatal("expected error with wrong DEK")
	}
}
