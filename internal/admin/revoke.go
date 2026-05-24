package admin

import (
	"errors"
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
	seen := make(map[string]bool)
	queue := []string{id}
	for depth := 0; len(queue) > 0; depth++ {
		if depth > 16 {
			return errors.New("revoke chain too deep")
		}
		var next []string
		for _, cur := range queue {
			if seen[cur] {
				continue
			}
			seen[cur] = true
			if err := h.st.store.RevokeToken(r.Context(), cur, now); err != nil {
				return err
			}
			kids, err := h.st.store.ListChildren(r.Context(), cur)
			if err != nil {
				return err
			}
			for _, k := range kids {
				next = append(next, k.ID)
			}
		}
		queue = next
	}
	return nil
}
