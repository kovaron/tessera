package upstreams

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/kovaron/tessera/internal/store"
)

type Upstream struct {
	ID        string
	BaseURL   string
	Inject    InjectRule
	Hostnames []string
}

type Registry struct {
	mu     sync.RWMutex
	m      map[string]Upstream
	byHost map[string]string // hostname -> upstream id
}

func NewRegistry() *Registry {
	return &Registry{
		m:      map[string]Upstream{},
		byHost: map[string]string{},
	}
}

func (r *Registry) Set(u Upstream) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Remove any previous hostname mappings owned by this upstream id.
	if prev, ok := r.m[u.ID]; ok {
		for _, h := range prev.Hostnames {
			if r.byHost[h] == u.ID {
				delete(r.byHost, h)
			}
		}
	}
	r.m[u.ID] = u
	for _, h := range u.Hostnames {
		r.byHost[h] = u.ID
	}
}

func (r *Registry) Delete(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if u, ok := r.m[id]; ok {
		for _, h := range u.Hostnames {
			if r.byHost[h] == id {
				delete(r.byHost, h)
			}
		}
	}
	delete(r.m, id)
}

func (r *Registry) Get(id string) (Upstream, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.m[id]
	return u, ok
}

func (r *Registry) ByHostname(host string) (Upstream, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.byHost[host]
	if !ok {
		return Upstream{}, false
	}
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
		u := Upstream{
			ID:        row.ID,
			BaseURL:   row.BaseURL,
			Inject:    rule,
			Hostnames: row.Hostnames,
		}
		r.m[row.ID] = u
		for _, h := range u.Hostnames {
			r.byHost[h] = u.ID
		}
	}
	return nil
}
