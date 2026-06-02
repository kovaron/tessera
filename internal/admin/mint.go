package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/kovaron/tessera/internal/authn"
	"github.com/kovaron/tessera/internal/store"
	"github.com/oklog/ulid/v2"
)

func (h *Handlers) registerMint() {
	h.mux.HandleFunc("/v1/tokens", h.tokensRoot)
}

func (h *Handlers) tokensRoot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		h.mint(w, r)
	case "GET":
		list, err := h.st.store.ListTokens(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if list == nil {
			list = []store.Token{}
		}
		writeJSON(w, 200, list)
	default:
		w.WriteHeader(405)
	}
}

func (h *Handlers) mint(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label      string `json:"label"`
		UpstreamID string `json:"upstream_id"`
		PolicyID   string `json:"policy_id"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	plain, hash, err := authn.Generate()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	now := time.Now().Unix()
	var exp *int64
	if body.TTLSeconds > 0 {
		e := now + body.TTLSeconds
		exp = &e
	}
	tok := store.Token{
		ID: ulid.Make().String(), Hash: hash, Label: body.Label,
		PolicyID: body.PolicyID, UpstreamID: body.UpstreamID,
		CreatedAt: now, ExpiresAt: exp, CreatedBy: "admin",
	}
	if err := h.st.store.InsertToken(r.Context(), tok); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 201, map[string]string{"id": tok.ID, "secret": plain})
}
