package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/kovaron/tessera/internal/crypto"
	"github.com/kovaron/tessera/internal/store"
	"github.com/oklog/ulid/v2"
)

func (h *Handlers) registerPolicies() {
	h.mux.HandleFunc("/v1/policies", h.policiesRoot)
}

func (h *Handlers) policiesRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	var body struct {
		Engine   string `json:"engine"`
		Source   string `json:"source"`
		SubsetOf string `json:"subset_of,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	dek := h.st.DEK()
	if dek == nil {
		http.Error(w, "locked", 503)
		return
	}
	ct, nonce, err := crypto.AEADSeal(dek, []byte(body.Source), []byte("policy"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	p := store.PolicyRow{ID: ulid.Make().String(), Engine: body.Engine, SourceCT: ct, SourceNonce: nonce, CreatedAt: time.Now().Unix()}
	if body.SubsetOf != "" {
		p.SubsetOf = &body.SubsetOf
	}
	if err := h.st.store.InsertPolicy(r.Context(), p); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, 201, map[string]string{"id": p.ID})
}
