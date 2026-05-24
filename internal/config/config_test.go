package config

import "testing"

const sample = `
server: { listen: "127.0.0.1:8080", admin_socket: "/tmp/x.sock" }
store: { driver: sqlite, path: "/tmp/db" }
secrets:
  default_ttl: 5m
  providers:
    - { name: env,       prefix: "env://" }
upstreams:
  - id: github
    base_url: "https://api.github.com"
    inject: { type: bearer, secret_ref: "env://GH" }
`

func TestParseConfig(t *testing.T) {
	cfg, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != "127.0.0.1:8080" {
		t.Fatal("listen")
	}
	if len(cfg.Upstreams) != 1 || cfg.Upstreams[0].ID != "github" {
		t.Fatal("upstream")
	}
}
