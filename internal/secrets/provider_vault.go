package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type VaultConfig struct {
	Addr     string
	TokenEnv string // env var name; default VAULT_TOKEN
}

type vaultProvider struct {
	cfg VaultConfig
	hc  *http.Client
}

func NewVaultProvider(cfg VaultConfig) SecretProvider {
	if cfg.TokenEnv == "" {
		cfg.TokenEnv = "VAULT_TOKEN"
	}
	return &vaultProvider{cfg: cfg, hc: &http.Client{Timeout: 5 * time.Second}}
}

func (vaultProvider) Name() string { return "vault" }

// rest = "<path>#<key>"
func (p *vaultProvider) Resolve(ctx context.Context, rest string) (Secret, error) {
	idx := strings.LastIndex(rest, "#")
	if idx < 0 {
		return Secret{}, errors.New("vault: ref must be path#key")
	}
	path, key := rest[:idx], rest[idx+1:]
	tok := os.Getenv(p.cfg.TokenEnv)
	if tok == "" {
		return Secret{}, fmt.Errorf("vault: %s not set", p.cfg.TokenEnv)
	}
	url := strings.TrimRight(p.cfg.Addr, "/") + "/v1/" + strings.TrimLeft(path, "/")
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("X-Vault-Token", tok)
	resp, err := p.hc.Do(req)
	if err != nil {
		return Secret{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Secret{}, fmt.Errorf("vault: %s", resp.Status)
	}
	body, _ := io.ReadAll(resp.Body)
	var env struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return Secret{}, err
	}
	v, ok := env.Data.Data[key]
	if !ok {
		return Secret{}, fmt.Errorf("vault: key %q not found", key)
	}
	return Secret{Value: []byte(v), ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
}
