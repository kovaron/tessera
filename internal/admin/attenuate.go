package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/kovaron/ai-secrets-manager/internal/authn"
	"github.com/kovaron/ai-secrets-manager/internal/store"
	"github.com/oklog/ulid/v2"
)

func (h *Handlers) registerAttenuate() {
	h.mux.HandleFunc("/v1/tokens/attenuate", h.attenuate)
}

func (h *Handlers) attenuate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	// Note: attenuation accepts any data-plane bearer token, not just admin tokens.
	// This is intentional: the admin unix socket is mode 0600 so only the OS owner
	// can reach it; self-service attenuation by a parent is the design goal.
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer == "" {
		http.Error(w, "missing bearer", 401)
		return
	}
	parent, err := authn.Resolve(r.Context(), h.st.store, bearer, time.Now())
	if err != nil || parent == nil {
		http.Error(w, "bad parent", 401)
		return
	}
	var body struct {
		Label      string `json:"label"`
		PolicyID   string `json:"policy_id"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if body.TTLSeconds <= 0 {
		http.Error(w, "ttl_seconds must be > 0", 400)
		return
	}
	if err := h.assertSubset(r, body.PolicyID, parent.PolicyID); err != nil {
		http.Error(w, err.Error(), 403)
		return
	}
	now := time.Now().Unix()
	childExp := now + body.TTLSeconds
	if parent.ExpiresAt != nil && childExp > *parent.ExpiresAt {
		http.Error(w, "child ttl exceeds parent", 400)
		return
	}
	plain, hash, err := authn.Generate()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	parentID := parent.ID
	var exp *int64
	if body.TTLSeconds > 0 {
		exp = &childExp
	}
	child := store.Token{
		ID: ulid.Make().String(), Hash: hash, ParentID: &parentID,
		Label: body.Label, PolicyID: body.PolicyID, UpstreamID: parent.UpstreamID,
		CreatedAt: now, ExpiresAt: exp, CreatedBy: parent.ID,
	}
	if err := h.st.store.InsertToken(r.Context(), child); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 201, map[string]string{"id": child.ID, "secret": plain})
}

func (h *Handlers) assertSubset(r *http.Request, childID, parentID string) error {
	cur := childID
	for d := 0; d < 16; d++ {
		if cur == parentID {
			return nil
		}
		p, err := h.st.store.GetPolicy(r.Context(), cur)
		if err != nil || p == nil || p.SubsetOf == nil {
			return errString("policy not a subset of parent")
		}
		cur = *p.SubsetOf
	}
	return errString("subset chain too deep")
}

type errString string

func (e errString) Error() string { return string(e) }
