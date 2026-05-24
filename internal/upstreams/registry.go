package upstreams

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/kovaron/ai-secrets-manager/internal/store"
)

type Upstream struct {
	ID      string
	BaseURL string
	Inject  InjectRule
}

type Registry struct {
	mu sync.RWMutex
	m  map[string]Upstream
}

func NewRegistry() *Registry { return &Registry{m: map[string]Upstream{}} }

func (r *Registry) Set(u Upstream) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[u.ID] = u
}

func (r *Registry) Get(id string) (Upstream, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.m[id]
	return u, ok
}

func (r *Registry) HydrateFromStore(ctx context.Context, s store.Store) error {
	list, err := s.ListUpstreams(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range list {
		var rule InjectRule
		if err := json.Unmarshal(row.InjectJSON, &rule); err != nil {
			return err
		}
		r.m[row.ID] = Upstream{ID: row.ID, BaseURL: row.BaseURL, Inject: rule}
	}
	return nil
}
