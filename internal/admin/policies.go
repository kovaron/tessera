package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/kovaron/tessera/internal/crypto"
	"github.com/kovaron/tessera/internal/store"
	"github.com/oklog/ulid/v2"
)

func (h *Handlers) registerPolicies() {
	h.mux.HandleFunc("/v1/policies", h.policiesRoot)
	h.mux.HandleFunc("/v1/policies/", h.policiesByID)
}

type policyView struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	UpstreamID *string `json:"upstream_id,omitempty"`
	Engine     string  `json:"engine"`
	SubsetOf   *string `json:"subset_of,omitempty"`
	CreatedAt  int64   `json:"created_at"`
	Source     string  `json:"source,omitempty"`
}

func (h *Handlers) policiesRoot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		var body struct {
			Name       string  `json:"name"`
			UpstreamID *string `json:"upstream_id,omitempty"`
			Engine     string  `json:"engine"`
			Source     string  `json:"source"`
			SubsetOf   string  `json:"subset_of,omitempty"`
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
		p := store.PolicyRow{
			ID:          ulid.Make().String(),
			Name:        body.Name,
			UpstreamID:  body.UpstreamID,
			Engine:      body.Engine,
			SourceCT:    ct,
			SourceNonce: nonce,
			CreatedAt:   time.Now().Unix(),
		}
		if body.SubsetOf != "" {
			p.SubsetOf = &body.SubsetOf
		}
		if err := h.st.store.InsertPolicy(r.Context(), p); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 201, map[string]string{"id": p.ID})
	case "GET":
		list, err := h.st.store.ListPolicies(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		out := make([]policyView, 0, len(list))
		for _, p := range list {
			out = append(out, policyView{
				ID: p.ID, Name: p.Name, UpstreamID: p.UpstreamID,
				Engine: p.Engine, SubsetOf: p.SubsetOf, CreatedAt: p.CreatedAt,
			})
		}
		writeJSON(w, 200, out)
	default:
		w.WriteHeader(405)
	}
}

func (h *Handlers) policiesByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/policies/")
	if id == "" {
		w.WriteHeader(404)
		return
	}
	switch r.Method {
	case "DELETE":
		if err := h.st.store.DeletePolicy(r.Context(), id); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(204)
	case "GET":
		p, err := h.st.store.GetPolicy(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if p == nil {
			w.WriteHeader(404)
			return
		}
		dek := h.st.DEK()
		view := policyView{
			ID: p.ID, Name: p.Name, UpstreamID: p.UpstreamID,
			Engine: p.Engine, SubsetOf: p.SubsetOf, CreatedAt: p.CreatedAt,
		}
		if dek != nil {
			pt, err := crypto.AEADOpen(dek, p.SourceNonce, p.SourceCT, []byte("policy"))
			if err == nil {
				view.Source = string(pt)
			}
		}
		writeJSON(w, 200, view)
	case "PUT":
		var body struct {
			Name       string  `json:"name"`
			UpstreamID *string `json:"upstream_id,omitempty"`
			Engine     string  `json:"engine"`
			Source     string  `json:"source"`
			SubsetOf   string  `json:"subset_of,omitempty"`
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
		existing, err := h.st.store.GetPolicy(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if existing == nil {
			w.WriteHeader(404)
			return
		}
		ct, nonce, err := crypto.AEADSeal(dek, []byte(body.Source), []byte("policy"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		existing.Name = body.Name
		existing.UpstreamID = body.UpstreamID
		existing.Engine = body.Engine
		existing.SourceCT = ct
		existing.SourceNonce = nonce
		if body.SubsetOf != "" {
			existing.SubsetOf = &body.SubsetOf
		} else {
			existing.SubsetOf = nil
		}
		if err := h.st.store.UpdatePolicy(r.Context(), *existing); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(204)
	default:
		w.WriteHeader(405)
	}
}
