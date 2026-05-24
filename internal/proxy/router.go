package proxy

import "strings"

// ParseUpstreamPath splits "/u/<id>/<rest...>".
func ParseUpstreamPath(p string) (id, rest string, ok bool) {
	if !strings.HasPrefix(p, "/u/") {
		return "", "", false
	}
	p = p[3:]
	slash := strings.Index(p, "/")
	if slash < 0 {
		if p == "" {
			return "", "", false
		}
		return p, "/", true
	}
	id = p[:slash]
	if id == "" {
		return "", "", false
	}
	return id, p[slash:], true
}
