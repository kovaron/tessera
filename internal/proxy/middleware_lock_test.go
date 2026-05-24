package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestLockMiddleware503(t *testing.T) {
	var unlocked atomic.Bool
	mw := LockMiddleware(func() bool { return unlocked.Load() })
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 503 {
		t.Fatalf("code=%d", rec.Code)
	}
	unlocked.Store(true)
	rec = httptest.NewRecorder()
	mw(next).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 {
		t.Fatalf("code=%d", rec.Code)
	}
}
