package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kovaron/tessera/internal/crypto"
	"github.com/kovaron/tessera/internal/store"
)

func TestUnlockFlow(t *testing.T) {
	ctx := context.Background()
	s, _ := store.OpenSQLite(t.TempDir() + "/db")
	s.Migrate(ctx)

	kp := &crypto.PassphraseProvider{Params: crypto.DefaultArgon2()}
	wrapped, salt, _ := kp.WrapNewDEK(ctx, []byte("pw"))
	s.PutKeystore(ctx, store.Keystore{
		DEKWrapped: wrapped,
		KEKSource:  "passphrase",
		KDFParams:  salt,
		CreatedAt:  time.Now().Unix(),
	})

	state := NewState(s, kp)
	h := NewHandlers(state)
	body, _ := json.Marshal(map[string]string{"passphrase": "pw"})
	req := httptest.NewRequest("POST", "/v1/unlock", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 204 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	if !state.Unlocked() {
		t.Fatal("not unlocked")
	}

	req = httptest.NewRequest("POST", "/v1/lock", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if state.Unlocked() {
		t.Fatal("still unlocked")
	}
}

// TestUnlockGeneratesCAOnce verifies that the CA is persisted on first unlock
// and that subsequent lock/unlock cycles reuse the same stored CA row
// (no regeneration — idempotent).
func TestUnlockGeneratesCAOnce(t *testing.T) {
	ctx := context.Background()
	s, _ := store.OpenSQLite(t.TempDir() + "/db")
	s.Migrate(ctx)

	kp := &crypto.PassphraseProvider{Params: crypto.DefaultArgon2()}
	wrapped, salt, _ := kp.WrapNewDEK(ctx, []byte("pw"))
	s.PutKeystore(ctx, store.Keystore{
		DEKWrapped: wrapped,
		KEKSource:  "passphrase",
		KDFParams:  salt,
		CreatedAt:  time.Now().Unix(),
	})

	state := NewState(s, kp)
	h := NewHandlers(state)

	doUnlock := func(t *testing.T) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"passphrase": "pw"})
		req := httptest.NewRequest("POST", "/v1/unlock", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 204 {
			t.Fatalf("unlock: code=%d body=%s", rec.Code, rec.Body.String())
		}
	}
	doLock := func(t *testing.T) {
		t.Helper()
		req := httptest.NewRequest("POST", "/v1/lock", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 204 {
			t.Fatalf("lock: code=%d body=%s", rec.Code, rec.Body.String())
		}
	}

	// First unlock: CA should be generated and persisted.
	doUnlock(t)
	if state.LeafFactory() == nil {
		t.Fatal("LeafFactory should be non-nil after first unlock")
	}
	caFirst, err := s.GetCA(ctx)
	if err != nil || caFirst == nil {
		t.Fatalf("expected CA row after first unlock, got err=%v row=%v", err, caFirst)
	}

	// Lock: factory should be cleared.
	doLock(t)
	if state.LeafFactory() != nil {
		t.Fatal("LeafFactory should be nil after lock")
	}

	// Second unlock: same CA row must be returned (no regeneration).
	doUnlock(t)
	if state.LeafFactory() == nil {
		t.Fatal("LeafFactory should be non-nil after second unlock")
	}
	caSecond, err := s.GetCA(ctx)
	if err != nil || caSecond == nil {
		t.Fatalf("expected CA row after second unlock, got err=%v row=%v", err, caSecond)
	}

	if !bytes.Equal(caFirst.CertCT, caSecond.CertCT) {
		t.Fatal("CA cert ciphertext changed between unlock cycles — CA was regenerated (not idempotent)")
	}
	if !bytes.Equal(caFirst.KeyCT, caSecond.KeyCT) {
		t.Fatal("CA key ciphertext changed between unlock cycles — CA was regenerated (not idempotent)")
	}
}
