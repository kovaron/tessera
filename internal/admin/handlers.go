package admin

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"github.com/kovaron/tessera/internal/crypto"
	"github.com/kovaron/tessera/internal/pki"
	"github.com/kovaron/tessera/internal/store"
	"github.com/kovaron/tessera/internal/upstreams"
)

type State struct {
	store       store.Store
	key         *crypto.PassphraseProvider
	unlocked    atomic.Bool
	dek         atomic.Value // []byte
	leafFactory atomic.Pointer[pki.LeafFactory]
}

func NewState(s store.Store, key *crypto.PassphraseProvider) *State {
	return &State{store: s, key: key}
}

func (s *State) Unlocked() bool { return s.unlocked.Load() }

func (s *State) DEK() []byte {
	v := s.dek.Load()
	if v == nil {
		return nil
	}
	return v.([]byte)
}

// LeafFactory returns the current leaf factory, or nil if the CA has not been
// loaded (vault is locked or CA bootstrap failed).
func (s *State) LeafFactory() *pki.LeafFactory { return s.leafFactory.Load() }

func (s *State) setLeafFactory(f *pki.LeafFactory) { s.leafFactory.Store(f) }

type Handlers struct {
	mux *http.ServeMux
	st  *State
	reg *upstreams.Registry
}

// NewHandlers creates admin HTTP handlers. reg may be nil (no live upstream sync).
func NewHandlers(st *State) *Handlers {
	return NewHandlersWithRegistry(st, nil)
}

// NewHandlersWithRegistry wires in the upstream registry so POST /v1/upstreams
// updates the in-memory registry as well as the store.
func NewHandlersWithRegistry(st *State, reg *upstreams.Registry) *Handlers {
	h := &Handlers{mux: http.NewServeMux(), st: st, reg: reg}
	h.mux.HandleFunc("/v1/status", h.status)
	h.mux.HandleFunc("/v1/unlock", h.unlock)
	h.mux.HandleFunc("/v1/lock", h.lock)
	h.registerUpstreams()
	h.registerPolicies()
	h.registerMint()
	h.registerRevoke()
	h.registerAttenuate()
	h.registerCA()
	return h
}

func (h *Handlers) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

func (h *Handlers) status(w http.ResponseWriter, r *http.Request) {
	k, _ := h.st.store.GetKeystore(r.Context())
	writeJSON(w, 200, map[string]any{
		"locked":      !h.st.Unlocked(),
		"version":     "dev",
		"initialized": k != nil,
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
