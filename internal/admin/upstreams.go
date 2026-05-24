package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/kovaron/ai-secrets-manager/internal/store"
)

func (h *Handlers) registerUpstreams() {
	h.mux.HandleFunc("/v1/upstreams", h.upstreamsRoot)
	h.mux.HandleFunc("/v1/upstreams/", h.upstreamsByID)
}

func (h *Handlers) upstreamsRoot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		var body struct {
			ID      string          `json:"id"`
			BaseURL string          `json:"base_url"`
			Inject  json.RawMessage `json:"inject"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		u := store.Upstream{ID: body.ID, BaseURL: body.BaseURL, InjectJSON: []byte(body.Inject), CreatedAt: time.Now().Unix()}
		if err := h.st.store.UpsertUpstream(r.Context(), u); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 201, u)
	case "GET":
		list, err := h.st.store.ListUpstreams(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 200, list)
	default:
		w.WriteHeader(405)
	}
}

func (h *Handlers) upstreamsByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/upstreams/")
	if r.Method == "DELETE" {
		if err := h.st.store.DeleteUpstream(r.Context(), id); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(204)
		return
	}
	w.WriteHeader(405)
}
