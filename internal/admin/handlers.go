package admin

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"github.com/kovaron/ai-secrets-manager/internal/crypto"
	"github.com/kovaron/ai-secrets-manager/internal/store"
	"github.com/kovaron/ai-secrets-manager/internal/upstreams"
)

type State struct {
	store    store.Store
	key      *crypto.PassphraseProvider
	unlocked atomic.Bool
	dek      atomic.Value // []byte
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
	return h
}

func (h *Handlers) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

func (h *Handlers) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"locked":  !h.st.Unlocked(),
		"version": "dev",
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
