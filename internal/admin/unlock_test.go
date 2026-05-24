package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kovaron/ai-secrets-manager/internal/crypto"
	"github.com/kovaron/ai-secrets-manager/internal/store"
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
