package admin

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/kovaron/tessera/internal/crypto"
	"github.com/kovaron/tessera/internal/pki"
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

	// Build (or restore) the CA leaf factory so the forward proxy can serve TLS.
	// Errors here are non-fatal — the path-based proxy still works without a CA.
	h.bootstrapCA(r.Context(), dek)

	w.WriteHeader(204)
}

// bootstrapCA loads or generates the CA and stores the resulting LeafFactory.
// On any error it logs and returns without failing the unlock.
func (h *Handlers) bootstrapCA(ctx context.Context, dek []byte) {
	caRow, err := h.st.store.GetCA(ctx)
	if err != nil {
		log.Printf("admin: CA bootstrap: GetCA: %v", err)
		return
	}

	var ca *pki.CA
	if caRow == nil {
		// First unlock — generate a new CA and persist it encrypted with the DEK.
		ca, err = pki.Generate("Tessera CA")
		if err != nil {
			log.Printf("admin: CA bootstrap: Generate: %v", err)
			return
		}
		wrapped, err := ca.WrapWithDEK(dek)
		if err != nil {
			log.Printf("admin: CA bootstrap: WrapWithDEK: %v", err)
			return
		}
		if err := h.st.store.PutCA(ctx, wrapped); err != nil {
			log.Printf("admin: CA bootstrap: PutCA: %v", err)
			return
		}
	} else {
		// Subsequent unlock — recover the existing CA from encrypted storage.
		ca, err = pki.UnwrapWithDEK(dek, caRow)
		if err != nil {
			log.Printf("admin: CA bootstrap: UnwrapWithDEK: %v", err)
			return
		}
	}

	h.st.setLeafFactory(pki.NewLeafFactory(ca))
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
	h.st.setLeafFactory(nil)
	h.st.unlocked.Store(false)
	h.st.dek.Store([]byte(nil))
	w.WriteHeader(204)
}
