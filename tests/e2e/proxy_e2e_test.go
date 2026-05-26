//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kovaron/tessera/internal/crypto"
	"github.com/kovaron/tessera/internal/store"
)

// adminClient talks to tessera's unix-socket admin API.
type adminClient struct {
	hc *http.Client
}

func newAdminClient(sockPath string) *adminClient {
	return &adminClient{
		hc: &http.Client{Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		}},
	}
}

func (c *adminClient) do(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://unix"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin %s %s → %s: %s", method, path, resp.Status, b)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// freePort picks a random free TCP port and returns the address.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// bootstrapDB creates the SQLite DB and keystore using the internal packages
// directly (avoids the CLI's term.ReadPassword which requires a real TTY).
func bootstrapDB(t *testing.T, dbPath string, passphrase string) {
	t.Helper()
	s, err := store.OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("bootstrapDB open: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("bootstrapDB migrate: %v", err)
	}
	kp := &crypto.PassphraseProvider{Params: crypto.DefaultArgon2()}
	wrapped, salt, err := kp.WrapNewDEK(context.Background(), []byte(passphrase))
	if err != nil {
		t.Fatalf("bootstrapDB WrapNewDEK: %v", err)
	}
	if err := s.PutKeystore(context.Background(), store.Keystore{
		DEKWrapped: wrapped,
		KEKSource:  "passphrase",
		KDFParams:  salt,
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatalf("bootstrapDB PutKeystore: %v", err)
	}
}

func buildBinary(t *testing.T, pkg, dest string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", dest, pkg)
	cmd.Dir = "/Users/kovaron/projects/ai-secrets-manager"
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, out)
	}
}

func TestMintCallRevoke(t *testing.T) {
	const passphrase = "testpassword"

	// 1. Build tessera binary.
	proxydBin := filepath.Join(t.TempDir(), "tessera")
	buildBinary(t, "./cmd/tessera", proxydBin)

	// 2. Allocate temp paths.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "data.db")
	sockPath := filepath.Join(dir, "admin.sock")
	dataAddr := freePort(t)

	// 3. Bootstrap keystore (programmatic — no TTY needed).
	bootstrapDB(t, dbPath, passphrase)

	// 4. Start fake upstream that records what Authorization header it receives.
	var lastAuthHeader atomic.Value
	fakeUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuthHeader.Store(r.Header.Get("Authorization"))
		w.WriteHeader(200)
	}))
	defer fakeUpstream.Close()

	// 5. Start tessera with UPSTREAM_TOKEN env var.
	proxydCmd := exec.Command(proxydBin,
		"-addr", dataAddr,
		"-db", dbPath,
		"-admin-socket", sockPath,
	)
	proxydCmd.Env = append(os.Environ(), "UPSTREAM_TOKEN=real-upstream-token")
	proxydCmd.Stdout = os.Stdout
	proxydCmd.Stderr = os.Stderr
	if err := proxydCmd.Start(); err != nil {
		t.Fatalf("start tessera: %v", err)
	}
	defer proxydCmd.Process.Kill()

	// 6. Wait for admin socket to appear (up to 10s).
	ac := newAdminClient(sockPath)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := ac.do("GET", "/v1/status", nil, nil); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// 7. Unlock via admin socket.
	if err := ac.do("POST", "/v1/unlock", map[string]string{"passphrase": passphrase}, nil); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	// 8. Register upstream.
	upstreamBody := map[string]any{
		"id":       "u",
		"base_url": fakeUpstream.URL,
		"inject": map[string]string{
			"type":       "bearer",
			"secret_ref": "env://UPSTREAM_TOKEN",
		},
	}
	if err := ac.do("POST", "/v1/upstreams", upstreamBody, nil); err != nil {
		t.Fatalf("create upstream: %v", err)
	}

	// 9. Create policy.
	policySource := `package proxy.authz
default allow := true`
	var policyResp struct {
		ID string `json:"id"`
	}
	if err := ac.do("POST", "/v1/policies", map[string]any{
		"engine": "opa",
		"source": policySource,
	}, &policyResp); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if policyResp.ID == "" {
		t.Fatal("policy response missing id")
	}

	// 10. Mint token.
	var tokenResp struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := ac.do("POST", "/v1/tokens", map[string]any{
		"label":       "e2e-test",
		"upstream_id": "u",
		"policy_id":   policyResp.ID,
		"ttl_seconds": 3600,
	}, &tokenResp); err != nil {
		t.Fatalf("mint token: %v", err)
	}
	if tokenResp.Secret == "" {
		t.Fatal("token response missing secret")
	}

	// 11. Wait for data plane to be ready (healthz).
	dpClient := &http.Client{Timeout: 5 * time.Second}
	healthURL := fmt.Sprintf("http://%s/healthz", dataAddr)
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := dpClient.Get(healthURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	// 12. Make data-plane request with the minted subtoken.
	dataURL := fmt.Sprintf("http://%s/u/u/x", dataAddr)
	req, _ := http.NewRequest("GET", dataURL, nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.Secret)
	resp, err := dpClient.Do(req)
	if err != nil {
		t.Fatalf("data-plane request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("data-plane: expected 200, got %d", resp.StatusCode)
	}

	// 13. Assert fake upstream received the real upstream token (not the subtoken).
	got := lastAuthHeader.Load()
	if got == nil || got.(string) != "Bearer real-upstream-token" {
		t.Fatalf("upstream Authorization: want %q, got %q", "Bearer real-upstream-token", got)
	}

	// 14. Revoke the token.
	if err := ac.do("DELETE", "/v1/tokens/"+tokenResp.ID, nil, nil); err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	// 15. Data-plane request after revocation should be 401.
	req2, _ := http.NewRequest("GET", dataURL, nil)
	req2.Header.Set("Authorization", "Bearer "+tokenResp.Secret)
	resp2, err := dpClient.Do(req2)
	if err != nil {
		t.Fatalf("post-revoke request: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 401 {
		t.Fatalf("post-revoke: expected 401, got %d", resp2.StatusCode)
	}
}
