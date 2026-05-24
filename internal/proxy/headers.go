package proxy

import "net/http"

var forwardDeny = map[string]struct{}{
	"Authorization":       {},
	"Cookie":              {},
	"Proxy-Authorization": {},
}

func Sanitize(h http.Header) {
	for k := range forwardDeny {
		h.Del(k)
	}
}
