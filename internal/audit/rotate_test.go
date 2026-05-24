package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotateAtThreshold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	rw, err := NewRotatingWriter(path, 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()

	line := strings.Repeat("x", 49) + "\n"
	for i := 0; i < 5; i++ {
		if _, err := rw.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected audit.log, %v", err)
	}
	for _, suffix := range []string{".1", ".2"} {
		if _, err := os.Stat(path + suffix); err != nil {
			t.Fatalf("expected audit.log%s, %v", suffix, err)
		}
	}
}

func TestRotateKeepsLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	rw, err := NewRotatingWriter(path, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()

	for i := 0; i < 10; i++ {
		rw.Write([]byte("xxxxxxxxxxx\n"))
	}
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Fatal(".3 should not exist")
	}
}
