//go:build !darwin

package admin

import "net/http"

func (h *Handlers) installCA(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "CA trust install not supported on this platform", http.StatusNotImplemented)
}
