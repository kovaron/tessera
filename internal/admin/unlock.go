package admin

import (
	"encoding/json"
	"net/http"

	"github.com/kovaron/ai-secrets-manager/internal/crypto"
)

func (h *Handlers) unlock(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	k, err := h.st.store.GetKeystore(r.Context())
	if err != nil || k == nil {
		http.Error(w, "no keystore", 500)
		return
	}
	dek, err := h.st.key.Unlock(r.Context(), crypto.PassphraseUnlockInput{
		Wrapped:    k.DEKWrapped,
		Salt:       k.KDFParams,
		Passphrase: []byte(body.Passphrase),
	})
	if err != nil {
		http.Error(w, "wrong passphrase", 401)
		return
	}
	h.st.dek.Store(dek)
	h.st.unlocked.Store(true)
	w.WriteHeader(204)
}

func (h *Handlers) lock(w http.ResponseWriter, r *http.Request) {
	if v := h.st.dek.Load(); v != nil {
		if b, ok := v.([]byte); ok {
			for i := range b {
				b[i] = 0
			}
		}
	}
	h.st.key.Lock()
	h.st.unlocked.Store(false)
	h.st.dek.Store([]byte(nil))
	w.WriteHeader(204)
}
