package proxy

import "net/http"

// InjectMiddleware sanitizes incoming headers before the ReverseProxy runs
// (which performs secret resolution + injection in Director).
func InjectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Sanitize(r.Header)
		next.ServeHTTP(w, r)
	})
}
