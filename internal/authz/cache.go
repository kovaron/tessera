package authz

import (
	"crypto/sha256"
	"sync"
)

type Cache struct {
	mu sync.RWMutex
	m  map[string]entry
}

type entry struct {
	hash [32]byte
	c    Compiled
}

func NewCache() *Cache { return &Cache{m: map[string]entry{}} }

func (c *Cache) Get(id string, src []byte) (Compiled, bool) {
	h := sha256.Sum256(src)
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.m[id]
	if !ok || e.hash != h {
		return nil, false
	}
	return e.c, true
}

func (c *Cache) Put(id string, src []byte, compiled Compiled) {
	h := sha256.Sum256(src)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[id] = entry{hash: h, c: compiled}
}

func (c *Cache) Invalidate(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, id)
}
