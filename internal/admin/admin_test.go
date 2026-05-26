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

func setup(t *testing.T) *Handlers {
	ctx := context.Background()
	s, _ := store.OpenSQLite(t.TempDir() + "/db")
	s.Migrate(ctx)
	kp := &crypto.PassphraseProvider{Params: crypto.DefaultArgon2()}
	wrapped, salt, _ := kp.WrapNewDEK(ctx, []byte("pw"))
	s.PutKeystore(ctx, store.Keystore{DEKWrapped: wrapped, KEKSource: "passphrase", KDFParams: salt, CreatedAt: time.Now().Unix()})

	st := NewState(s, kp)
	h := NewHandlers(st)

	body, _ := json.Marshal(map[string]string{"passphrase": "pw"})
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/unlock", bytes.NewReader(body)))
	return h
}

func TestUpstreamsCreateGetList(t *testing.T) {
	h := setup(t)
	body, _ := json.Marshal(map[string]any{
		"id": "github", "base_url": "https://api.github.com",
		"inject": map[string]string{"type": "bearer", "secret_ref": "env://X"},
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/upstreams", bytes.NewReader(body)))
	if rec.Code != 201 {
		t.Fatalf("create code=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/upstreams", nil))
	if rec.Code != 200 {
		t.Fatalf("list code=%d", rec.Code)
	}
}

func TestPoliciesAndMint(t *testing.T) {
	h := setup(t)

	body, _ := json.Marshal(map[string]any{"id": "u", "base_url": "https://x", "inject": map[string]string{"type": "bearer", "secret_ref": "env://X"}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/upstreams", bytes.NewReader(body)))

	policy := `package proxy.authz
default allow := true`
	body, _ = json.Marshal(map[string]any{"engine": "opa", "source": policy})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/policies", bytes.NewReader(body)))
	if rec.Code != 201 {
		t.Fatalf("policy code=%d body=%s", rec.Code, rec.Body.String())
	}
	var pres map[string]string
	json.Unmarshal(rec.Body.Bytes(), &pres)
	policyID := pres["id"]

	body, _ = json.Marshal(map[string]any{"label": "ci", "upstream_id": "u", "policy_id": policyID, "ttl_seconds": 3600})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/tokens", bytes.NewReader(body)))
	if rec.Code != 201 {
		t.Fatalf("mint code=%d body=%s", rec.Code, rec.Body.String())
	}
	var mres map[string]string
	json.Unmarshal(rec.Body.Bytes(), &mres)
	if mres["secret"] == "" {
		t.Fatal("no secret returned")
	}
}
