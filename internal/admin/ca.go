package admin

import "net/http"

func (h *Handlers) registerCA() {
	h.mux.HandleFunc("/v1/ca", h.getCA)
	h.mux.HandleFunc("/v1/ca/install", h.installCA)
}

func (h *Handlers) getCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	factory := h.st.LeafFactory()
	if factory == nil {
		msg := "locked"
		if h.st.Unlocked() {
			msg = "ca not initialized"
		}
		http.Error(w, msg, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(factory.CAPEM())
}
