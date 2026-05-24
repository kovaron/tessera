package admin

import (
	"net/http"
	"strings"
	"time"
)

func (h *Handlers) registerRevoke() {
	h.mux.HandleFunc("/v1/tokens/", h.tokensByID)
}

func (h *Handlers) tokensByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/tokens/")
	if r.Method == "DELETE" {
		if err := h.revokeCascade(r, id); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(204)
		return
	}
	w.WriteHeader(405)
}

func (h *Handlers) revokeCascade(r *http.Request, id string) error {
	now := time.Now()
	if err := h.st.store.RevokeToken(r.Context(), id, now); err != nil {
		return err
	}
	kids, err := h.st.store.ListChildren(r.Context(), id)
	if err != nil {
		return err
	}
	for _, k := range kids {
		if err := h.revokeCascade(r, k.ID); err != nil {
			return err
		}
	}
	return nil
}
