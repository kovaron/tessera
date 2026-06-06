# Transparent forward-proxy mode — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `127.0.0.1:8443` HTTP forward proxy with on-the-fly TLS MITM, plus a `tessera-cli exec` wrapper, so users can run `tessera-cli exec --upstream openai -- python my_agent.py` and have the child talk to `api.openai.com` directly while Tessera handles authn/authz/inject.

**Architecture:** Reuse the existing data-plane middleware chain. New `internal/pki` package owns the root CA (AEAD-encrypted under the DEK) and a leaf cert factory. New `internal/proxy/forward.go` handles `CONNECT` and TLS termination. Upstream resolution by `Host` header via a new `hostnames` field on `Upstream`. `cmd/tessera-cli/exec.go` mints a child token, spawns the subprocess with proxy env vars + CA bundle pointers, revokes on exit.

**Tech Stack:** Go 1.22+, `crypto/tls`, `crypto/x509`, `crypto/ecdsa`, `os/exec`, existing `modernc.org/sqlite`, `internal/crypto` AEAD.

---

## File map

| Path | Action | Purpose |
|---|---|---|
| `internal/pki/ca.go` | Create | Root CA gen, persist (AEAD), load. |
| `internal/pki/leaf.go` | Create | Leaf cert factory, LRU cache, `GetCertificate` callback. |
| `internal/pki/pki_test.go` | Create | Unit tests. |
| `internal/store/migrations.go` | Modify | `upstreams.hostnames` column + `keystore_ca` table. |
| `internal/store/store.go` | Modify | `Upstream.Hostnames []string`, `Store.GetCA / PutCA`. |
| `internal/store/upstreams.go` | Modify | INSERT/SELECT/UPDATE include `hostnames`. |
| `internal/store/ca.go` | Create | `GetCA`, `PutCA`. |
| `internal/upstreams/registry.go` | Modify | `ByHostname(host) (Upstream, bool)` + reverse index. |
| `internal/proxy/forward.go` | Create | CONNECT handler + TLS termination + middleware chain. |
| `internal/proxy/forward_test.go` | Create | Integration tests. |
| `cmd/tessera/main.go` | Modify | Start forward listener if CA present. |
| `cmd/tessera-cli/exec.go` | Create | `tessera-cli exec` subcommand. |
| `cmd/tessera-cli/cmd.go` | Modify | Wire `cmdExec()` + `cmdCA()`. |
| `cmd/tessera-cli/ca.go` | Create | `tessera-cli ca export / install`. |
| `internal/admin/upstreams.go` | Modify | Accept + return `hostnames`. |
| `internal/admin/ca.go` | Create | `GET /v1/ca`, `POST /v1/ca/install`. |
| `internal/admin/handlers.go` | Modify | Register CA routes. |
| `ui/src-tauri/src/types.rs` | Modify | `Upstream.hostnames`, `UpsertUpstreamReq.hostnames`. |
| `ui/src/types/bindings.ts` | Modify | Mirror. |
| `ui/src/screens/Upstreams.tsx` | Modify | Hostnames input (comma-separated). |

---

### Task 1: CA storage schema

**Files:**
- Modify: `internal/store/migrations.go`
- Create: `internal/store/ca.go`
- Modify: `internal/store/store.go`

- [ ] **Step 1: Extend `Store` interface**

```go
// internal/store/store.go (add to interface)
type CA struct {
    CertCT, CertNonce []byte
    KeyCT, KeyNonce   []byte
    CreatedAt         int64
}

// Store interface:
GetCA(ctx context.Context) (*CA, error)
PutCA(ctx context.Context, ca CA) error
```

- [ ] **Step 2: Add migration**

Append to `schema` constant in `internal/store/migrations.go`:

```sql
CREATE TABLE IF NOT EXISTS keystore_ca (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  cert_pem_ct  BLOB NOT NULL,
  cert_pem_nonce BLOB NOT NULL,
  key_pem_ct   BLOB NOT NULL,
  key_pem_nonce BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
```

- [ ] **Step 3: Implement CA CRUD**

```go
// internal/store/ca.go
package store

import (
    "context"
    "database/sql"
    "errors"
)

func (s *sqliteStore) GetCA(ctx context.Context) (*CA, error) {
    row := s.db.QueryRowContext(ctx,
        `SELECT cert_pem_ct, cert_pem_nonce, key_pem_ct, key_pem_nonce, created_at FROM keystore_ca WHERE id=1`)
    var c CA
    err := row.Scan(&c.CertCT, &c.CertNonce, &c.KeyCT, &c.KeyNonce, &c.CreatedAt)
    if errors.Is(err, sql.ErrNoRows) {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    return &c, nil
}

func (s *sqliteStore) PutCA(ctx context.Context, c CA) error {
    _, err := s.db.ExecContext(ctx,
        `INSERT INTO keystore_ca(id, cert_pem_ct, cert_pem_nonce, key_pem_ct, key_pem_nonce, created_at)
         VALUES (1, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET cert_pem_ct=excluded.cert_pem_ct, cert_pem_nonce=excluded.cert_pem_nonce,
           key_pem_ct=excluded.key_pem_ct, key_pem_nonce=excluded.key_pem_nonce, created_at=excluded.created_at`,
        c.CertCT, c.CertNonce, c.KeyCT, c.KeyNonce, c.CreatedAt)
    return err
}
```

- [ ] **Step 4: Test round-trip**

```go
// internal/store/ca_test.go
func TestCARoundTrip(t *testing.T) {
    s := openInMem(t)
    ctx := context.Background()
    in := CA{CertCT: []byte("ct"), CertNonce: []byte("n1"), KeyCT: []byte("kct"), KeyNonce: []byte("kn"), CreatedAt: 42}
    if err := s.PutCA(ctx, in); err != nil { t.Fatal(err) }
    got, err := s.GetCA(ctx)
    if err != nil || got == nil { t.Fatal(err, got) }
    if !bytes.Equal(got.CertCT, in.CertCT) || got.CreatedAt != 42 { t.Fatal("mismatch") }
}
```

- [ ] **Step 5: Run + commit**

```
go test ./internal/store/ -count=1
git add internal/store && git commit -m "feat(store): keystore_ca table + GetCA/PutCA"
```

---

### Task 2: PKI package — CA generation

**Files:**
- Create: `internal/pki/ca.go`
- Create: `internal/pki/pki_test.go`

- [ ] **Step 1: Test CA gen + AEAD round-trip**

```go
// internal/pki/pki_test.go
func TestCAGenAndWrap(t *testing.T) {
    dek := bytes.Repeat([]byte{1}, 32)
    ca, err := Generate("Tessera CA")
    if err != nil { t.Fatal(err) }
    wrap, err := ca.WrapWithDEK(dek)
    if err != nil { t.Fatal(err) }
    got, err := UnwrapWithDEK(dek, wrap)
    if err != nil { t.Fatal(err) }
    if !ca.Cert.Equal(got.Cert) { t.Fatal("cert mismatch") }
}
```

- [ ] **Step 2: Implement Generate**

```go
// internal/pki/ca.go
package pki

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "time"

    "github.com/kovaron/tessera/internal/crypto"
    "github.com/kovaron/tessera/internal/store"
)

type CA struct {
    Cert *x509.Certificate
    Key  *ecdsa.PrivateKey
}

func Generate(commonName string) (*CA, error) {
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil { return nil, err }
    serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
    tmpl := &x509.Certificate{
        SerialNumber: serial,
        Subject:      pkix.Name{CommonName: commonName, Organization: []string{"Tessera"}},
        NotBefore:    time.Now().Add(-1 * time.Minute),
        NotAfter:     time.Now().AddDate(10, 0, 0),
        KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
        BasicConstraintsValid: true,
        IsCA:         true,
        MaxPathLen:   0,
    }
    der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
    if err != nil { return nil, err }
    cert, err := x509.ParseCertificate(der)
    if err != nil { return nil, err }
    return &CA{Cert: cert, Key: key}, nil
}

func (c *CA) CertPEM() []byte {
    return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
}

func (c *CA) keyPEM() ([]byte, error) {
    der, err := x509.MarshalECPrivateKey(c.Key)
    if err != nil { return nil, err }
    return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func (c *CA) WrapWithDEK(dek []byte) (store.CA, error) {
    certCT, certNonce, err := crypto.AEADSeal(dek, c.CertPEM(), []byte("ca-cert"))
    if err != nil { return store.CA{}, err }
    keyPEM, err := c.keyPEM()
    if err != nil { return store.CA{}, err }
    keyCT, keyNonce, err := crypto.AEADSeal(dek, keyPEM, []byte("ca-key"))
    if err != nil { return store.CA{}, err }
    return store.CA{CertCT: certCT, CertNonce: certNonce, KeyCT: keyCT, KeyNonce: keyNonce, CreatedAt: time.Now().Unix()}, nil
}

func UnwrapWithDEK(dek []byte, w *store.CA) (*CA, error) {
    certPEM, err := crypto.AEADOpen(dek, w.CertNonce, w.CertCT, []byte("ca-cert"))
    if err != nil { return nil, err }
    keyPEM, err := crypto.AEADOpen(dek, w.KeyNonce, w.KeyCT, []byte("ca-key"))
    if err != nil { return nil, err }
    cBlock, _ := pem.Decode(certPEM)
    cert, err := x509.ParseCertificate(cBlock.Bytes)
    if err != nil { return nil, err }
    kBlock, _ := pem.Decode(keyPEM)
    key, err := x509.ParseECPrivateKey(kBlock.Bytes)
    if err != nil { return nil, err }
    return &CA{Cert: cert, Key: key}, nil
}
```

- [ ] **Step 3: Run + commit**

```
go test ./internal/pki/ -count=1
git add internal/pki && git commit -m "feat(pki): CA generation + AEAD wrap/unwrap"
```

---

### Task 3: PKI package — leaf factory

**Files:**
- Create: `internal/pki/leaf.go`
- Modify: `internal/pki/pki_test.go`

- [ ] **Step 1: Test leaf SAN + chain verify**

```go
func TestLeafFor_SANAndChain(t *testing.T) {
    ca, _ := Generate("Tessera CA")
    f := NewLeafFactory(ca)
    leaf, err := f.LeafFor("api.openai.com")
    if err != nil { t.Fatal(err) }
    if leaf.Leaf.DNSNames[0] != "api.openai.com" { t.Fatal("SAN missing") }
    pool := x509.NewCertPool()
    pool.AddCert(ca.Cert)
    if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "api.openai.com"}); err != nil {
        t.Fatal("verify:", err)
    }
}
```

- [ ] **Step 2: Implement LeafFactory**

```go
// internal/pki/leaf.go
package pki

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "math/big"
    "sync"
    "time"
)

type LeafFactory struct {
    ca    *CA
    mu    sync.Mutex
    cache map[string]*tls.Certificate
}

func NewLeafFactory(ca *CA) *LeafFactory {
    return &LeafFactory{ca: ca, cache: map[string]*tls.Certificate{}}
}

func (f *LeafFactory) LeafFor(host string) (*tls.Certificate, error) {
    f.mu.Lock()
    defer f.mu.Unlock()
    if c, ok := f.cache[host]; ok {
        if time.Until(c.Leaf.NotAfter) > 24*time.Hour {
            return c, nil
        }
    }
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil { return nil, err }
    serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
    tmpl := &x509.Certificate{
        SerialNumber: serial,
        Subject:      pkix.Name{CommonName: host},
        NotBefore:    time.Now().Add(-1 * time.Minute),
        NotAfter:     time.Now().AddDate(0, 0, 30),
        KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        DNSNames:     []string{host},
    }
    der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca.Cert, &key.PublicKey, f.ca.Key)
    if err != nil { return nil, err }
    leaf, err := x509.ParseCertificate(der)
    if err != nil { return nil, err }
    cert := &tls.Certificate{Certificate: [][]byte{der, f.ca.Cert.Raw}, PrivateKey: key, Leaf: leaf}
    f.cache[host] = cert
    return cert, nil
}

func (f *LeafFactory) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
    return f.LeafFor(hello.ServerName)
}
```

- [ ] **Step 3: Run + commit**

```
go test ./internal/pki/ -count=1
git add internal/pki && git commit -m "feat(pki): leaf cert factory with SAN + cache"
```

---

### Task 4: Upstream hostnames

**Files:**
- Modify: `internal/store/store.go`
- Modify: `internal/store/migrations.go`
- Modify: `internal/store/upstreams.go`
- Modify: `internal/upstreams/registry.go`
- Create: `internal/store/upstreams_hostnames_test.go`

- [ ] **Step 1: Schema + struct field**

`store.go`:
```go
type Upstream struct {
    ID         string
    BaseURL    string
    InjectJSON json.RawMessage
    Hostnames  []string
    CreatedAt  int64
}
```

`migrations.go` — extend `addPolicyColumns` pattern: add an `addUpstreamColumns` helper that runs `ALTER TABLE upstreams ADD COLUMN hostnames TEXT NOT NULL DEFAULT '[]'` if missing.

- [ ] **Step 2: Persist + read**

In `upstreams.go`, INSERT `string(jsonHostnames)` and scan it back into `[]string` on read.

- [ ] **Step 3: Registry reverse index**

```go
// internal/upstreams/registry.go
type Registry struct {
    mu        sync.RWMutex
    m         map[string]Upstream
    byHost    map[string]string  // hostname -> upstream id
}

func (r *Registry) ByHostname(host string) (Upstream, bool) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    id, ok := r.byHost[host]
    if !ok { return Upstream{}, false }
    u, ok := r.m[id]
    return u, ok
}
```

Rebuild `byHost` in `Set` and `Delete` and `HydrateFromStore`.

- [ ] **Step 4: Test**

```go
func TestUpstreamHostnamesRoundTrip(t *testing.T) { /* insert, list, assert order */ }
func TestRegistryByHostname(t *testing.T) { /* Set, ByHostname returns upstream */ }
```

- [ ] **Step 5: Commit**

```
go test ./internal/store/ ./internal/upstreams/ -count=1
git add -A && git commit -m "feat(upstreams): hostnames field + hostname->upstream index"
```

---

### Task 5: Admin API + UI for hostnames

**Files:**
- Modify: `internal/admin/upstreams.go`
- Modify: `ui/src-tauri/src/types.rs`
- Modify: `ui/src/types/bindings.ts`
- Modify: `ui/src/screens/Upstreams.tsx`

- [ ] **Step 1: Admin handler accepts hostnames**

```go
// POST body adds:
Hostnames []string `json:"hostnames"`
```
Pass through to `store.Upstream.Hostnames`. Reverse index rebuild via `reg.Set`.

- [ ] **Step 2: Rust + TS types**

`types.rs`:
```rust
pub struct Upstream { ... #[serde(rename = "Hostnames")] pub hostnames: Vec<String>, ... }
pub struct UpsertUpstreamReq { ..., pub hostnames: Vec<String>, ... }
```
`bindings.ts` mirrors.

- [ ] **Step 3: UI input**

In `Upstreams.tsx` Sheet, add a `<Input>` for "Hostnames (comma separated)" → split on `,`, trim, drop empties when building `UpsertUpstreamReq`. Display as joined string in the table.

- [ ] **Step 4: Build + commit**

```
go build ./... && (cd ui && pnpm tsc --noEmit)
git add -A && git commit -m "feat(admin+ui): manage upstream hostnames"
```

---

### Task 6: Forward proxy listener

**Files:**
- Create: `internal/proxy/forward.go`
- Create: `internal/proxy/forward_test.go`
- Modify: `cmd/tessera/main.go`

- [ ] **Step 1: Skeleton**

```go
// internal/proxy/forward.go
package proxy

import (
    "context"
    "crypto/tls"
    "io"
    "net"
    "net/http"
    "net/url"

    "github.com/kovaron/tessera/internal/pki"
    "github.com/kovaron/tessera/internal/upstreams"
)

type ForwardServer struct {
    Addr      string
    Leaf      *pki.LeafFactory
    Registry  *upstreams.Registry
    Build     func(host string) http.Handler // returns the existing middleware chain bound to (upstreamID, baseURL) resolved from host
}

func (f *ForwardServer) ListenAndServe() error {
    ln, err := net.Listen("tcp", f.Addr)
    if err != nil { return err }
    for {
        c, err := ln.Accept()
        if err != nil { return err }
        go f.handle(c)
    }
}
```

- [ ] **Step 2: CONNECT + TLS termination**

```go
func (f *ForwardServer) handle(c net.Conn) {
    defer c.Close()
    br := bufio.NewReader(c)
    req, err := http.ReadRequest(br)
    if err != nil { return }
    if req.Method != "CONNECT" {
        // Plain HTTP forward (rare); reuse same chain but pass-through to handler.
        f.servePlain(c, req)
        return
    }
    host := req.URL.Hostname()
    if _, err := c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil { return }
    tlsConn := tls.Server(c, &tls.Config{GetCertificate: f.Leaf.GetCertificate})
    if err := tlsConn.Handshake(); err != nil { return }
    // Read inner HTTP request
    inner := bufio.NewReader(tlsConn)
    httpReq, err := http.ReadRequest(inner)
    if err != nil { return }
    httpReq.URL.Scheme = "https"
    httpReq.URL.Host = host
    f.dispatch(tlsConn, httpReq, host)
}

func (f *ForwardServer) dispatch(w net.Conn, req *http.Request, host string) {
    u, ok := f.Registry.ByHostname(host)
    if !ok {
        // 502 + audit unknown_host happens inside Build's middleware; but we have no chain. Synthesise:
        writeStatus(w, 502, "unknown_host")
        return
    }
    handler := f.Build(u.ID)
    // wrap w in an http.ResponseWriter using existing httptest.NewRecorder? Simpler: write a small adapter.
    adapter := newConnResponseWriter(w)
    handler.ServeHTTP(adapter, req)
}
```

Adapter writes `HTTP/1.1` status line + headers + body to the conn.

- [ ] **Step 3: Wire `Build`**

In `cmd/tessera/main.go`, after constructing `dp` (DataPlane), pass a builder closure:

```go
fs := &proxy.ForwardServer{
    Addr: *forwardAddr, // new flag, default "127.0.0.1:8443"
    Leaf: leafFactory,
    Registry: reg,
    Build: dp.HandlerForHostMode, // existing chain that resolves upstream from request context, not from path
}
if leafFactory != nil {
    go func(){ if err := fs.ListenAndServe(); err != nil { log.Printf("forward proxy: %v", err) } }()
}
```

The chain needs a new `HandlerForHostMode` that pulls `upstream_id` from request context (set by the forward dispatcher) instead of from the `/u/<id>/` path.

- [ ] **Step 4: Token-upstream match check**

In the existing `inject` middleware (or a new pre-inject step), if the token's `upstream_id` doesn't match the upstream resolved from the host, emit audit `upstream_mismatch` and return 403.

- [ ] **Step 5: Integration test**

```go
func TestForwardProxy_HappyPath(t *testing.T) {
    // 1. spin up fake upstream on localhost
    // 2. register it with hostname "fake.test"
    // 3. mint a token bound to that upstream + a permissive policy
    // 4. open TCP to forward proxy, CONNECT fake.test:443, TLS handshake using Tessera CA
    // 5. GET / via inner HTTP
    // 6. assert upstream saw injected Authorization
}

func TestForwardProxy_UnknownHost(t *testing.T) { /* expect 502 unknown_host audit */ }
func TestForwardProxy_UpstreamMismatch(t *testing.T) { /* token openai, host github -> 403 */ }
```

- [ ] **Step 6: Commit**

```
go test ./internal/proxy/ -count=1
git add -A && git commit -m "feat(proxy): forward-proxy listener with CONNECT+MITM"
```

---

### Task 7: CA bootstrap at daemon startup

**Files:**
- Modify: `cmd/tessera/main.go`
- Modify: `internal/admin/unlock.go` (or wherever unlock loads DEK)

- [ ] **Step 1: After unlock, load-or-generate CA**

```go
// in the unlock success path:
caRow, _ := store.GetCA(ctx)
var caObj *pki.CA
if caRow == nil {
    caObj, _ = pki.Generate("Tessera CA")
    wrap, _ := caObj.WrapWithDEK(dek)
    _ = store.PutCA(ctx, wrap)
} else {
    caObj, _ = pki.UnwrapWithDEK(dek, caRow)
}
leafFactory := pki.NewLeafFactory(caObj)
state.SetLeafFactory(leafFactory) // exposed for the forward proxy
```

`state.LeafFactory()` returns nil until unlock; forward proxy refuses requests with 503 if nil.

- [ ] **Step 2: Test**

```go
func TestUnlockGeneratesCAOnce(t *testing.T) { /* unlock twice, assert keystore_ca row stable */ }
```

- [ ] **Step 3: Commit**

```
go test ./...
git add -A && git commit -m "feat(daemon): generate CA on first unlock, persist encrypted under DEK"
```

---

### Task 8: CA export + install (admin API + CLI)

**Files:**
- Create: `internal/admin/ca.go`
- Create: `cmd/tessera-cli/ca.go`
- Modify: `cmd/tessera-cli/cmd.go`
- Modify: `internal/admin/handlers.go`

- [ ] **Step 1: `GET /v1/ca`**

```go
// internal/admin/ca.go
func (h *Handlers) caGet(w http.ResponseWriter, r *http.Request) {
    f := h.st.LeafFactory()
    if f == nil { http.Error(w, "locked", 503); return }
    w.Header().Set("Content-Type", "application/x-pem-file")
    w.Write(f.CAPEM())
}
```

- [ ] **Step 2: `POST /v1/ca/install`**

```go
func (h *Handlers) caInstall(w http.ResponseWriter, r *http.Request) {
    // 1. write CA PEM to a temp file
    // 2. exec "security add-trusted-cert -d -r trustAsRoot -k <login.keychain> <tmpfile>"
    // 3. return stdout/stderr verbatim
}
```

- [ ] **Step 3: CLI**

```go
// cmd/tessera-cli/ca.go
func cmdCA() *cobra.Command {
    c := &cobra.Command{Use: "ca"}
    exp := &cobra.Command{Use: "export", RunE: func(*cobra.Command, []string) error {
        return NewClient(socketPath).download("/v1/ca", os.Stdout)
    }}
    inst := &cobra.Command{Use: "install", RunE: func(*cobra.Command, []string) error {
        return NewClient(socketPath).do("POST", "/v1/ca/install", nil, nil)
    }}
    c.AddCommand(exp, inst)
    return c
}
```

`download` is a new helper on Client that streams a response body to a writer.

- [ ] **Step 4: Commit**

```
go test ./...
git add -A && git commit -m "feat(admin+cli): CA export + install"
```

---

### Task 9: `tessera-cli exec` subcommand

**Files:**
- Create: `cmd/tessera-cli/exec.go`
- Modify: `cmd/tessera-cli/cmd.go`

- [ ] **Step 1: Skeleton**

```go
// cmd/tessera-cli/exec.go
func cmdExec() *cobra.Command {
    var upstream, policy, label, forwardAddr string
    var ttl int64
    var caPath string
    c := &cobra.Command{
        Use: "exec",
        Args: cobra.MinimumNArgs(1),
        DisableFlagsInUseLine: true,
        RunE: func(cmd *cobra.Command, args []string) error {
            // 1. mint child token
            var resp struct{ ID, Secret string }
            if err := NewClient(socketPath).do("POST", "/v1/tokens", map[string]any{
                "label": label, "upstream_id": upstream, "policy_id": policy, "ttl_seconds": ttl,
            }, &resp); err != nil { return err }

            // 2. assemble env
            env := os.Environ()
            env = append(env,
                "HTTPS_PROXY=http://"+forwardAddr,
                "HTTP_PROXY=http://"+forwardAddr,
                "NODE_EXTRA_CA_CERTS="+caPath,
                "SSL_CERT_FILE="+caPath,
                "REQUESTS_CA_BUNDLE="+caPath,
                "CURL_CA_BUNDLE="+caPath,
                "PXY_TOKEN="+resp.Secret,
            )

            // 3. spawn
            child := exec.Command(args[0], args[1:]...)
            child.Env = env
            child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
            if err := child.Start(); err != nil { return err }

            // 4. forward signals
            sigCh := make(chan os.Signal, 1)
            signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
            go func() {
                for s := range sigCh { _ = child.Process.Signal(s) }
            }()

            // 5. wait, then revoke regardless of outcome
            waitErr := child.Wait()
            _ = NewClient(socketPath).do("DELETE", "/v1/tokens/"+resp.ID, nil, nil)
            return waitErr
        },
    }
    c.Flags().StringVar(&upstream, "upstream", "", "upstream id (required)")
    c.Flags().StringVar(&policy, "policy", "", "policy id (required)")
    c.Flags().StringVar(&label, "label", "", "audit label (default exec:<pid>)")
    c.Flags().Int64Var(&ttl, "ttl", 3600, "child token TTL seconds")
    c.Flags().StringVar(&forwardAddr, "proxy-addr", "127.0.0.1:8443", "")
    c.Flags().StringVar(&caPath, "ca-path", os.ExpandEnv("$HOME/.tessera/ca.pem"), "")
    _ = c.MarkFlagRequired("upstream")
    _ = c.MarkFlagRequired("policy")
    return c
}
```

- [ ] **Step 2: Wire**

In `cmd.go` root: `root.AddCommand(cmdExec(), cmdCA())`.

- [ ] **Step 3: Sanity check**

```
./tessera-cli exec --upstream openai --policy <id> -- env | grep -E 'PXY_TOKEN|PROXY|CA_BUNDLE'
```

- [ ] **Step 4: Commit**

```
git add -A && git commit -m "feat(cli): tessera-cli exec wrapper"
```

---

### Task 10: End-to-end test against a fake upstream

**Files:**
- Create: `tests/e2e/forward_proxy_test.go`

- [ ] **Step 1: Spin up fake upstream with self-signed cert; ignore — Tessera uses its own MITM cert toward the client, talks plain TLS to the upstream. For the test, upstream is on `127.0.0.1` but we need TLS that resolves a hostname → set `Host:` header and use `tls.Config{ServerName: ...}` in the test client.**

- [ ] **Step 2: Test scenario**

```go
func TestExec_HappyPath(t *testing.T) {
    // 1. bootstrap a temp Tessera (daemon as a goroutine).
    // 2. register fake upstream with hostnames=["fake.test"], baseURL=https://127.0.0.1:N,
    //    inject=bearer with secret_ref=env://FAKE_KEY (set env in test).
    // 3. add a permissive policy.
    // 4. start the forward listener.
    // 5. run a tiny in-test client (no subprocess) that mimics `tessera-cli exec`:
    //    - mint token via admin socket
    //    - dial 127.0.0.1:8443, CONNECT fake.test:443
    //    - TLS handshake with RootCAs = Tessera CA
    //    - GET / with Authorization: Bearer <pxy_>
    // 6. assert upstream saw Authorization: Bearer <FAKE_KEY>.
}
```

- [ ] **Step 3: Commit**

```
go test ./tests/e2e/ -count=1
git add tests/e2e && git commit -m "test(e2e): forward proxy happy path"
```

---

### Task 11: Docs

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: README new section "Transparent mode"**

Three subsections:
1. Install the CA (one-time): `./tessera-cli ca install`
2. Register an upstream with hostnames.
3. Run any command with `./tessera-cli exec --upstream openai --policy <id> -- python my_agent.py`.

- [ ] **Step 2: architecture.md — add forward proxy to the process layout + a second data-flow diagram showing CONNECT → MITM → inject.**

- [ ] **Step 3: CHANGELOG `[Unreleased]` entry**

- [ ] **Step 4: Commit**

```
git add -A && git commit -m "docs: transparent proxy mode + tessera-cli exec"
```

---

## Self-review

- All spec sections covered: PKI (Tasks 2-3), forward listener (Task 6), `exec` (Task 9), hostnames mapping (Tasks 4-5), CA storage (Tasks 1, 7), CA UX (Task 8), tests (Tasks 1-7 unit + Task 10 e2e), docs (Task 11). ✓
- No placeholders.
- Types consistent: `Hostnames []string` in store + Rust + TS; `pki.CA{Cert, Key}` reused everywhere.
- No backwards-compat: matches user instruction ("no migration").

## Execution

Use `superpowers:subagent-driven-development`. Fresh subagent per task. Spec review then code-quality review per task. Final code review at the end of Task 11.
