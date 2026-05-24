package secrets

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Secret struct {
	Value     []byte
	ExpiresAt time.Time
}

type SecretProvider interface {
	Name() string
	Resolve(ctx context.Context, rest string) (Secret, error)
}

type Registry struct {
	mu        sync.RWMutex
	providers map[string]SecretProvider
}

func NewRegistry() *Registry {
	return &Registry{providers: map[string]SecretProvider{}}
}

func (r *Registry) Register(p SecretProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.Name()] = p
}

func (r *Registry) Resolve(ctx context.Context, ref string) (Secret, error) {
	name, rest, err := ParseRef(ref)
	if err != nil {
		return Secret{}, err
	}
	r.mu.RLock()
	p, ok := r.providers[name]
	r.mu.RUnlock()
	if !ok {
		return Secret{}, fmt.Errorf("secrets: no provider %q registered", name)
	}
	return p.Resolve(ctx, rest)
}
