package secrets

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type Cache struct {
	r       *Registry
	ttl     time.Duration
	mu      sync.RWMutex
	entries map[string]Secret
	sf      singleflight.Group
}

func NewCache(r *Registry, ttl time.Duration) *Cache {
	return &Cache{r: r, ttl: ttl, entries: map[string]Secret{}}
}

func (c *Cache) Get(ctx context.Context, ref string) (Secret, error) {
	c.mu.RLock()
	e, ok := c.entries[ref]
	c.mu.RUnlock()
	if ok && time.Now().Before(e.ExpiresAt) {
		return e, nil
	}
	v, err, _ := c.sf.Do(ref, func() (any, error) {
		sec, err := c.r.Resolve(context.WithoutCancel(ctx), ref)
		if err != nil {
			return Secret{}, err
		}
		if sec.ExpiresAt.IsZero() {
			sec.ExpiresAt = time.Now().Add(c.ttl)
		}
		c.mu.Lock()
		c.entries[ref] = sec
		c.mu.Unlock()
		return sec, nil
	})
	if err != nil {
		return Secret{}, err
	}
	return v.(Secret), nil
}

func (c *Cache) Invalidate(ref string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[ref]; ok {
		for i := range e.Value {
			e.Value[i] = 0
		}
		delete(c.entries, ref)
	}
}
