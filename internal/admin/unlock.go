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
	// Build (or restore) the CA leaf factory before flipping unlocked=true so
	// there is no window where unlocked==true but leafFactory==nil.
	h.bootstrapCA(r.Context(), dek)

	h.st.dek.Store(dek)
	h.st.unlocked.Store(true)

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
	// Snapshot the old DEK slice before replacing the atomic so any concurrent
	// DEK() load sees either the valid slice or nil — never the zeroed slice.
	old := h.st.dek.Load()
	h.st.setLeafFactory(nil)
	h.st.unlocked.Store(false)
	h.st.dek.Store([]byte(nil))
	h.st.key.Lock()
	// Zero the old slice after it has been swapped out.
	if old != nil {
		if b, ok := old.([]byte); ok {
			for i := range b {
				b[i] = 0
			}
		}
	}
	w.WriteHeader(204)
}
