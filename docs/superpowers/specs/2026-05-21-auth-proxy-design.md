# AI Agent Auth Proxy — Design

**Date:** 2026-05-21
**Status:** Draft (approved through brainstorming)
**Repo:** ai-secrets-manager

## 1. Purpose

A single-binary, local-first authentication and authorization proxy that issues narrow, scoped credentials to AI agents and translates them into upstream third-party API credentials at request time. Upstream credentials never leave the proxy host (or, in service mode, the proxy process). Local-first today, deployable as a shared service later. Open source.

Concrete example: an operator owns a single GitHub API token with read/write on a whole org. The proxy mints a `pxy_…` subtoken for an AI agent whose policy permits only `GET /repos/acme/widgets/issues*` on the `github` upstream. The agent calls the proxy; the proxy authenticates the subtoken, evaluates the policy, strips the subtoken from the outbound request, injects the real GitHub token (resolved live from 1Password), and forwards the request to `api.github.com`.

## 2. Goals & non-goals

### Goals (v1)

- Generic multi-tenant gateway — any HTTP API can be registered via config or admin API.
- Opaque random subtokens stored as `sha256` only; revocation is instant.
- Full policy engine (OPA Rego default; Cedar adapter scaffolded).
- Pluggable `SecretProvider` interface with 1Password, Doppler, Vault, env implementations; lazy-fetch + TTL cache.
- Pluggable `KeyProvider` interface for the envelope KEK (passphrase locally, KMS in service mode).
- Encrypted-at-rest sensitive columns in SQLite via app-layer AEAD (XChaCha20-Poly1305).
- Locked-by-default behavior: 503 on any agent request while the DEK is not in memory.
- Admin via Unix socket (local) or HTTPS + admin token (service). Mint, attenuate, revoke, list, unlock, lock.
- Parent → child token attenuation with cascading revoke.
- Structured JSON audit log to stdout.
- Library core + two reference binaries: `proxyd`, `proxyctl`.

### Non-goals (v1)

- Rate limiting, quotas, per-token billing (policy obligation hook reserved).
- Response body filtering / redaction.
- Hardware-key KEK (YubiKey, TPM).
- mTLS to upstreams.
- Multi-region replication. Single-node SQLite.
- Provable policy subset for attenuation (admin-asserted only in v1).
- Web UI.

## 3. Architecture overview

```
                ┌──────────────────────────── proxyd ────────────────────────────┐
                │                                                                │
agent ─bearer──▶│  authn ─▶ authz (OPA) ─▶ transform ─▶ inject upstream cred ─▶ │──▶ upstream API
                │      │            │                              ▲             │
                │      ▼            ▼                              │             │
                │   Store      compiled policy cache        SecretProvider       │
                │  (sqlite)                                  (1P/Doppler/Vault)  │
                │      ▲                                                         │
                │      │                                                         │
                │   KeyProvider (passphrase | KMS) ──── DEK in memory ───────────│
                │                                                                │
                │   audit log (stdout, JSON)                                     │
                │                                                                │
                │   admin api  ◀── unix socket (local) | HTTPS (service)         │
                └────────────────────────────────────────────────────────────────┘
                                              ▲
                                              │
                                          proxyctl
```

Approach chosen: reverse-proxy with embedded policy engine (in-process). Rejected: Envoy + ext_authz (too heavy for local-first OSS MVP); rule matcher without policy engine (operator asked for full engine).

## 4. Repo layout

```
ai-secrets-manager/
  cmd/
    proxyd/        # server binary
    proxyctl/      # admin CLI
  internal/
    proxy/         # core reverse-proxy + middleware chain
    authn/         # subtoken lookup, hashing, parent-chain checks
    authz/         # policy engine adapter (OPA, Cedar)
    secrets/       # SecretProvider interface + impls
    crypto/        # KeyProvider + envelope encryption helpers
    store/         # Store interface + sqlite impl
    upstreams/     # upstream registry, credential injectors
    audit/         # structured request logger
    admin/         # admin API handlers (shared for socket + HTTPS)
  pkg/             # exported public types for library reuse
  config/
    example.yaml
  docs/
```

## 5. Data model (SQLite)

```sql
CREATE TABLE tokens (
  id            TEXT PRIMARY KEY,                       -- ulid/uuid
  hash          BLOB NOT NULL UNIQUE,                   -- sha256(subtoken)
  parent_id    TEXT REFERENCES tokens(id),              -- null = admin-minted root
  label         TEXT,
  policy_id     TEXT NOT NULL REFERENCES policies(id),
  upstream_id   TEXT NOT NULL REFERENCES upstreams(id),
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER,                                -- null = no expiry
  revoked_at    INTEGER,
  created_by    TEXT                                    -- "admin" or parent token id
);
CREATE INDEX idx_tokens_hash ON tokens(hash);
CREATE INDEX idx_tokens_parent ON tokens(parent_id);

CREATE TABLE policies (
  id            TEXT PRIMARY KEY,
  engine        TEXT NOT NULL CHECK (engine IN ('opa','cedar')),
  source        BLOB NOT NULL,                          -- ENCRYPTED policy text
  source_nonce  BLOB NOT NULL,
  subset_of     TEXT REFERENCES policies(id),           -- attenuation parent (admin-asserted)
  created_at    INTEGER NOT NULL
);

CREATE TABLE upstreams (
  id            TEXT PRIMARY KEY,
  base_url      TEXT NOT NULL,
  inject        TEXT NOT NULL,                          -- JSON: {type, header|query, secret_ref, value_template}
  created_at    INTEGER NOT NULL
);

CREATE TABLE keystore (
  id            INTEGER PRIMARY KEY CHECK (id = 1),     -- singleton
  dek_wrapped   BLOB NOT NULL,                          -- DEK encrypted under KEK
  kek_source    TEXT NOT NULL,                          -- 'passphrase' | 'kms:...'
  kdf_params    BLOB,                                   -- argon2id params (passphrase mode)
  created_at    INTEGER NOT NULL
);
```

Rationale:
- Subtoken plaintext is never persisted. Only `sha256(subtoken)` for lookup. No reversible storage.
- Policy text encrypted at rest with the DEK (XChaCha20-Poly1305, nonce per row). Policy text may contain identifying scope information (path patterns, IDs).
- Token rows are not encrypted: they need indexed hash lookup at request time, and contain no plaintext secrets.
- Upstream credentials are never stored in the proxy — only `secret_ref` strings pointing at the external secret manager.
- Parent chain enables attenuation tracking and cascade revoke.

## 6. Request flow (data plane)

```
agent → proxyd :8080

  0. if KeyProvider not unlocked → 503 locked

  1. extract Bearer subtoken from Authorization
  2. authn:
       hash = sha256(subtoken)
       row = store.LookupTokenByHash(hash)
       reject 401 if: not found, revoked_at != null, expires_at past,
                     or any ancestor revoked (recursive walk, bounded depth)

  3. route resolution:
       path must match /u/<upstream_id>/<rest>
       upstream = store.GetUpstream(token.upstream_id)
       reject 404 if upstream_id mismatch or unknown
       reject 403 if token.upstream_id != path upstream_id

  4. authz:
       compiled = policyCache.Get(token.policy_id)
       input = {
         token:   { id, label, parent_chain, created_at },
         upstream: token.upstream_id,
         request: { method, path, path_segments, query, headers (allowlist),
                    body_preview (json|nil; first N KB if policy refs it) }
       }
       decision = compiled.Eval(ctx, input)
       reject 403 if !decision.Allow (record decision.Reason in audit)

  5. transform request:
       strip Authorization (subtoken)
       rewrite URL: trimPrefix("/u/"+upstream_id) → upstream.base_url + path
       inject upstream credential:
         secret = secretCache.Resolve(upstream.inject.secret_ref)
         apply inject rule (bearer header / custom header / query / template)
       copy method, query, body, allowlisted headers

  6. forward via http.ReverseProxy (streaming)

  7. response:
       strip Set-Cookie and any upstream auth-related headers
       stream body unchanged

  8. audit emit (see §10)
```

Path routing convention: `https://proxy/u/<upstream_id>/<rest>` → `<upstream.base_url>/<rest>`. Disambiguates multi-upstream without host-header tricks; SSRF-safe because `base_url` is fixed per upstream and not derivable from the request.

Body handling: streamed by default. Policies that reference `input.request.body_preview` cause the proxy to buffer up to `body_preview_limit` bytes (config). Larger requests fail closed for such policies.

## 7. Policy engine adapter

```go
type Engine interface {
    Name() string                                          // "opa" | "cedar"
    Compile(src []byte) (Compiled, error)
}

type Compiled interface {
    Eval(ctx context.Context, input Input) (Decision, error)
}

type Input struct {
    Token    TokenView
    Upstream string
    Request  RequestView
}

type Decision struct {
    Allow       bool
    Reason      string
    Obligations map[string]any                             // reserved for future hooks (rate, redact)
}
```

- Default engine: OPA via the OPA Go SDK, in-process. No sidecar.
- Cedar adapter scaffolded via `cedar-go`; chosen per row by `policies.engine`.
- Compiled policies cached in memory keyed by `(policy_id, content_hash)`. Cache entry invalidated on admin update.
- Engine evaluation budget: per-request timeout (config, default 50 ms). Exceeded → 503.

Example Rego (token scoped to GET issues on one repo):

```rego
package proxy.authz
default allow := false
allow if {
    input.request.method == "GET"
    glob.match("/repos/acme/widgets/issues*", [], input.request.path)
}
```

## 8. Secret provider and key provider

### SecretProvider — upstream credentials

```go
type SecretProvider interface {
    Name() string                                          // "1password" | "doppler" | "vault" | "env"
    Resolve(ctx context.Context, ref string) (Secret, error)
}

type Secret struct {
    Value     []byte                                       // zeroed on release
    ExpiresAt time.Time                                    // provider-suggested TTL; zero = use cache default
}
```

`ref` syntax is provider-prefixed and routed to the registered implementation:

- `op://Vault/Item/field` — 1Password CLI (`op read`)
- `doppler://project/config/NAME` — `doppler secrets get --plain`
- `vault://path#key` — Vault KV v2 over HTTP
- `env://NAME` — env var (development only; warned in logs)

Caching:
- Single in-memory map `ref → cachedSecret`.
- Default TTL from config (e.g. 5 m); provider may override per-secret via `Secret.ExpiresAt`.
- Single-flight on miss to prevent stampedes.
- Background sweeper evicts expired entries and zeros the byte slice. Best-effort `mlock` for cached values on supported OSes.

### KeyProvider — KEK for envelope encryption

```go
type KeyProvider interface {
    Name() string                                          // "passphrase" | "kms"
    Unlock(ctx context.Context, input any) (KEK, error)    // input: passphrase, KMS params, etc
    Lock()                                                 // zero KEK
}
```

Local mode (`passphrase`):
- `proxyctl unlock` prompts passphrase, sends over the Unix socket to `proxyd`.
- Server runs Argon2id(passphrase, `keystore.kdf_params`) → KEK.
- Server unwraps `keystore.dek_wrapped` with KEK → DEK held in memory.
- DEK used to decrypt policy rows on read.
- `proxyctl lock` zeroes KEK and DEK.

Service mode (`kms`):
- DEK wrapped under a cloud KMS CMK at bootstrap.
- Server calls KMS `Decrypt` at startup to unwrap DEK. No passphrase.

Both providers are swappable via config without DB migration: only `keystore.kek_source` and the wrapping change.

## 9. Admin API and CLI

### Transport

- **Local mode**: Unix socket `~/.proxyd/admin.sock`, perms 0600. Authentication is filesystem ownership.
- **Service mode**: HTTPS on a separate port (e.g. `:8443`). Admin authentication via a bootstrap root admin token, stored as `tokens` row with an `admin` role flag (separate from agent tokens; bypasses upstream/policy fields).

Both transports share the same handler set.

### Endpoints

```
POST   /v1/unlock         { provider, passphrase|kms_params }            → 204
POST   /v1/lock                                                          → 204
GET    /v1/status                                                        → { locked, upstreams, version, build }

POST   /v1/upstreams      { id, base_url, inject }                       → upstream
GET    /v1/upstreams                                                     → [upstream]
DELETE /v1/upstreams/:id

POST   /v1/policies       { engine, source, subset_of? }                 → { id }
GET    /v1/policies/:id
PUT    /v1/policies/:id   { source }
DELETE /v1/policies/:id

POST   /v1/tokens         { label, upstream_id, policy_id, ttl_seconds } → { id, secret }   # admin mint
POST   /v1/tokens/attenuate
       Authorization: Bearer <parent_subtoken>
       Body: { label, policy_id, ttl_seconds }                           → { id, secret }
       Rules:
         - child.policy.subset_of chain must reach parent.policy_id
         - child.ttl ≤ parent remaining ttl
         - child.upstream_id == parent.upstream_id

GET    /v1/tokens                                                        → [token meta, no secret]
DELETE /v1/tokens/:id                                                    # revoke; cascades to descendants
```

### Subtoken format

`pxy_<base32(32 random bytes)>`. 256-bit entropy. Returned exactly once on mint; not retrievable thereafter.

### Attenuation semantics (v1 limitation)

Child policy must declare `subset_of` parent's policy ID; the proxy walks the chain and accepts. Subset-ness is **admin-asserted**, not proven. Documented as a known limitation. Future work: SMT-based subset proof, or migration to macaroon-style attenuable tokens.

### CLI

```
proxyctl unlock
proxyctl lock
proxyctl status

proxyctl upstream add github \
    --base-url https://api.github.com \
    --inject 'bearer:op://Vault/GH/token'
proxyctl upstream list
proxyctl upstream remove github

proxyctl policy add github-issues-ro --engine opa --file policy.rego
proxyctl policy list
proxyctl policy remove github-issues-ro

proxyctl token mint   --label ci-bot --upstream github --policy github-issues-ro --ttl 24h
proxyctl token list
proxyctl token revoke <id>
```

## 10. Audit log

Structured JSON, one record per agent request, written to stdout. Operator pipes to file or log stack.

```json
{
  "ts": "2026-05-21T10:23:14.221Z",
  "req_id": "01J...",
  "token_id": "tok_abc123",
  "token_label": "ci-bot",
  "parent_id": "tok_root99",
  "upstream_id": "github",
  "method": "GET",
  "path": "/repos/acme/widgets/issues",
  "query_keys": ["state","per_page"],
  "decision": "allow",
  "deny_reason": "",
  "upstream_status": 200,
  "status": 200,
  "latency_ms": 142,
  "bytes_in": 0,
  "bytes_out": 8421,
  "remote_addr": "127.0.0.1"
}
```

Admin events emit a parallel `audit.admin` record:

```json
{ "ts": "...", "actor": "admin|tok_xyz", "action": "token.mint", "target": "tok_abc123", "fields": {...} }
```

Never logged: subtoken plaintext, upstream credentials, request/response bodies, full query values, sensitive headers (Authorization, Cookie, Set-Cookie). Query keys are logged, query values are not.

## 11. Configuration

`config.yaml`. Non-secret fields hot-reloadable on `SIGHUP`. Secrets (`secret_ref`) resolved live, not from file.

```yaml
server:
  listen: "127.0.0.1:8080"
  admin_socket: "~/.proxyd/admin.sock"
  admin_https: null                 # service mode: { listen: ":8443", tls_cert: ..., tls_key: ... }

store:
  driver: sqlite
  path: "~/.proxyd/data.db"

crypto:
  key_provider: passphrase          # | kms
  passphrase:
    argon2id: { time: 3, memory_mb: 64, parallelism: 4 }
  # kms: { provider: aws, key_id: "arn:..." }

secrets:
  default_ttl: 5m
  body_preview_limit: 65536
  providers:
    - { name: 1password, prefix: "op://",      cmd: ["op", "read"] }
    - { name: doppler,   prefix: "doppler://", cmd: ["doppler", "secrets", "get", "--plain"] }
    - { name: vault,     prefix: "vault://",   addr: "https://vault.internal", auth: "token-file:~/.vault-token" }
    - { name: env,       prefix: "env://" }

audit:
  format: json
  destination: stdout
  redact_query: true

# Upstreams and policies may also be managed via admin API; config-defined entries are immutable at runtime.
upstreams:
  - id: github
    base_url: "https://api.github.com"
    inject: { type: bearer, secret_ref: "op://Vault/GitHub/token" }
  - id: linear
    base_url: "https://api.linear.app"
    inject:
      type: header
      name: "Authorization"
      value_template: "Bearer ${secret}"
      secret_ref: "doppler://prod/api/LINEAR_TOKEN"
```

## 12. Threat model & mitigations

| Threat | Mitigation |
|---|---|
| Subtoken leak from agent environment | Short default TTL (24 h), instant revoke, audit visibility, attenuation enables narrow tokens |
| Proxy DB stolen at rest | Policy text + DEK encrypted; subtoken plaintext never stored (only sha256); upstream credentials never stored (resolved live) |
| Process memory dump | DEK + cached upstream secrets held as `[]byte`, zeroed on lock or eviction; best-effort `mlock` |
| Passphrase brute force | Argon2id with tuned params; params persisted in `keystore.kdf_params` |
| Policy bypass via header smuggling | `Authorization` stripped; allowlisted headers only forwarded; CRLF and path normalization before authz eval |
| SSRF via path manipulation | Upstream `base_url` fixed per registered upstream; only `path` and `query` derived from request after normalization |
| Body-constraint bypass via large body | Bodies > `body_preview_limit` fail closed for policies referencing `body_preview` |
| Replay of revoked token | Per-request DB lookup on opaque token model — revocation is instant |
| Admin socket hijack | Unix socket perms 0600, owner-only; service mode requires HTTPS + admin token |
| Audit log tampering | Append-only stream to stdout; downstream integrity is operator's responsibility |
| Upstream credential leak via error body | Bodies passed through unchanged; documentation tells operators not to log response bodies |
| Timing side-channel on token lookup | Constant-time hash compare; secret lookup happens after authn; valid/invalid paths share structure |
| Locked proxy serving stale traffic | Hard 503 on any agent request when DEK absent; same for compromised KEK provider failure |

## 13. Testing strategy

- **Unit**: each interface (`Store`, `SecretProvider`, `KeyProvider`, `Engine`) with table-driven tests + fakes. Crypto round-trips against KAT vectors.
- **Integration**: real `proxyd` in-process with sqlite-in-tmpdir, fake upstream via `httptest.Server`, stub `SecretProvider`. Scenarios: mint→use→revoke, attenuation TTL/scope, locked→503, policy deny path, body-preview constraint, header stripping.
- **Property**: parent-chain revocation cascade — random tree, random revoke node, assert all descendants denied.
- **Fuzz**: path normalizer, header allowlist parser, `secret_ref` parser, attenuation TTL math.
- **E2E**: cucumber-style scenarios via real `proxyctl` + `proxyd` over Unix socket. `op` / `doppler` shimmed in test mode.
- **Security tests**: smuggled `Authorization`, path traversal (`../`), oversized body, JWT-shaped subtoken rejection, expired token race against unlock, revoked-parent race against in-flight child.
- **CI matrix**: linux + macos, Go current + previous minor.

## 14. Out of scope (deferred)

- Rate limiting, quotas (policy `Obligations` field reserved).
- Response body filtering and redaction.
- Hardware-key KEK (YubiKey, TPM).
- mTLS to upstreams; mTLS for agent → proxy.
- Multi-region replication, HA SQLite alternatives.
- Provable policy subset for attenuation.
- Web UI.
- Per-token usage analytics in DB.

## 15. Open questions / explicit limitations carried into implementation

1. **Attenuation subset is admin-asserted in v1.** A child token's scope can be declared narrower than the parent's without proof. Documented; revisit when macaroons or SMT subset checking is on the table.
2. **OPA Go SDK vs `cedar-go` maturity.** OPA picked as default; Cedar adapter ships behind a build tag if upstream stability is acceptable at start of implementation.
3. **`mlock` portability.** Best-effort, behavior differs across macOS / Linux / WSL. Document expectations; do not depend on it for security claims.
4. **Audit log integrity.** v1 ships stdout JSON. Tamper-evident log (hash chain, signing) deferred.
5. **Hot reload scope.** Config reload covers `server.listen`, `secrets.providers`, `upstreams` (config-defined), `audit`. Crypto provider and store driver require restart.
