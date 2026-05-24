package secrets

import (
	"context"
	"os"
	"testing"
)

func shim(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/" + name
	sh := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(path, []byte(sh), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOnePasswordResolve(t *testing.T) {
	bin := shim(t, "op", `printf "secret-from-1p"`)
	p := &opProvider{cmd: []string{bin, "read"}}
	sec, err := p.Resolve(context.Background(), "Vault/Item/field")
	if err != nil {
		t.Fatal(err)
	}
	if string(sec.Value) != "secret-from-1p" {
		t.Fatalf("got %q", sec.Value)
	}
}

func TestDopplerResolve(t *testing.T) {
	bin := shim(t, "doppler", `printf "doppler-val"`)
	p := &dopplerProvider{cmd: []string{bin, "secrets", "get", "--plain"}}
	sec, err := p.Resolve(context.Background(), "prod/api/X")
	if err != nil {
		t.Fatal(err)
	}
	if string(sec.Value) != "doppler-val" {
		t.Fatalf("got %q", sec.Value)
	}
}
