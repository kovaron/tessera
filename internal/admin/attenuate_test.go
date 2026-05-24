package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/kovaron/ai-secrets-manager/internal/authn"
	"github.com/kovaron/ai-secrets-manager/internal/store"
)

func TestAttenuationCreatesChild(t *testing.T) {
	h := setup(t)
	ctx := context.Background()

	parentPlain, parentHash, _ := authn.Generate()
	h.st.store.InsertToken(ctx, store.Token{ID: "P", Hash: parentHash, Label: "p", PolicyID: "polP", UpstreamID: "u", CreatedAt: 0})
	h.st.store.InsertPolicy(ctx, store.PolicyRow{ID: "polP", Engine: "opa", SourceCT: []byte("x"), SourceNonce: []byte("y")})
	h.st.store.InsertPolicy(ctx, store.PolicyRow{ID: "polC", Engine: "opa", SourceCT: []byte("x"), SourceNonce: []byte("y"), SubsetOf: strPtr("polP")})

	body, _ := json.Marshal(map[string]any{"label": "child", "policy_id": "polC", "ttl_seconds": 60})
	req := httptest.NewRequest("POST", "/v1/tokens/attenuate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+parentPlain)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 201 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAttenuationRejectsZeroTTL(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	parentPlain, parentHash, _ := authn.Generate()
	h.st.store.InsertToken(ctx, store.Token{ID: "P2", Hash: parentHash, Label: "p", PolicyID: "polP", UpstreamID: "u", CreatedAt: 0})
	h.st.store.InsertPolicy(ctx, store.PolicyRow{ID: "polP", Engine: "opa", SourceCT: []byte("x"), SourceNonce: []byte("y")})

	body, _ := json.Marshal(map[string]any{"label": "c", "policy_id": "polP", "ttl_seconds": 0})
	req := httptest.NewRequest("POST", "/v1/tokens/attenuate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+parentPlain)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("code=%d", rec.Code)
	}
}

func strPtr(s string) *string { return &s }
