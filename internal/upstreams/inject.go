package upstreams

import (
	"fmt"
	"net/http"
	"strings"
)

type InjectRule struct {
	Type          string `json:"type"` // bearer | header | query
	Name          string `json:"name,omitempty"`
	ValueTemplate string `json:"value_template,omitempty"`
	SecretRef     string `json:"secret_ref"`
}

func Apply(r InjectRule, req *http.Request, secret []byte) error {
	switch r.Type {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+string(secret))
	case "header":
		if r.Name == "" {
			return fmt.Errorf("upstreams: header inject missing name")
		}
		v := r.ValueTemplate
		if v == "" {
			v = string(secret)
		} else {
			v = strings.ReplaceAll(v, "${secret}", string(secret))
		}
		req.Header.Set(r.Name, v)
	case "query":
		if r.Name == "" {
			return fmt.Errorf("upstreams: query inject missing name")
		}
		q := req.URL.Query()
		q.Set(r.Name, string(secret))
		req.URL.RawQuery = q.Encode()
	default:
		return fmt.Errorf("upstreams: unknown inject type %q", r.Type)
	}
	return nil
}
