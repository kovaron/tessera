package secrets

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type counterProvider struct{ calls int64 }

func (counterProvider) Name() string { return "ctr" }
func (p *counterProvider) Resolve(_ context.Context, rest string) (Secret, error) {
	atomic.AddInt64(&p.calls, 1)
	return Secret{Value: []byte("v:" + rest), ExpiresAt: time.Now().Add(100 * time.Millisecond)}, nil
}

func TestCacheHitsAvoidProvider(t *testing.T) {
	r := NewRegistry()
	cp := &counterProvider{}
	r.Register(cp)
	c := NewCache(r, 50*time.Millisecond)

	for i := 0; i < 5; i++ {
		if _, err := c.Get(context.Background(), "ctr://x"); err != nil {
			t.Fatal(err)
		}
	}
	if cp.calls != 1 {
		t.Fatalf("calls=%d", cp.calls)
	}
}
