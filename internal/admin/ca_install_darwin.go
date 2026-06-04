//go:build darwin

package admin

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

// Uses the daemon user's login keychain. Tessera is single-user local-only by design.
func (h *Handlers) installCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	factory := h.st.LeafFactory()
	if factory == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}

	tmp, err := os.CreateTemp("", "tessera-ca-*.pem")
	if err != nil {
		http.Error(w, fmt.Sprintf("create temp file: %v", err), http.StatusInternalServerError)
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(factory.CAPEM()); err != nil {
		tmp.Close()
		http.Error(w, fmt.Sprintf("write temp file: %v", err), http.StatusInternalServerError)
		return
	}
	tmp.Close()

	home, err := os.UserHomeDir()
	if err != nil {
		http.Error(w, fmt.Sprintf("home dir: %v", err), http.StatusInternalServerError)
		return
	}
	keychainDB := home + "/Library/Keychains/login.keychain-db"

	cmd := exec.CommandContext(r.Context(), "security", "add-trusted-cert",
		"-d", "-r", "trustAsRoot", "-k", keychainDB, tmpPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, string(out), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
