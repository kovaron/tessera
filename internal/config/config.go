package config

import (
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Listen      string `yaml:"listen"`
		AdminSocket string `yaml:"admin_socket"`
	} `yaml:"server"`
	Store struct {
		Driver string `yaml:"driver"`
		Path   string `yaml:"path"`
	} `yaml:"store"`
	Secrets struct {
		DefaultTTL       time.Duration    `yaml:"default_ttl"`
		BodyPreviewLimit int              `yaml:"body_preview_limit"`
		Providers        []map[string]any `yaml:"providers"`
	} `yaml:"secrets"`
	Audit struct {
		Format      string `yaml:"format"`
		Destination string `yaml:"destination"`
	} `yaml:"audit"`
	Upstreams []struct {
		ID      string         `yaml:"id"`
		BaseURL string         `yaml:"base_url"`
		Inject  map[string]any `yaml:"inject"`
	} `yaml:"upstreams"`
}

func Parse(b []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
