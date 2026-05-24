package proxy

import "net/http"

type IsUnlocked func() bool

func LockMiddleware(isUnlocked IsUnlocked) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isUnlocked() {
				http.Error(w, "proxy locked", http.StatusServiceUnavailable)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
