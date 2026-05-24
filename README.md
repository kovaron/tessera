# ai-secrets-manager

A local-first HTTP auth/authorization proxy for AI agents. Agents receive short-lived opaque subtokens (`pxy_*`) scoped to a single upstream service. On each request the proxy validates the subtoken against an OPA policy, resolves the real API credentials live from your secret provider (1Password, Doppler, or HashiCorp Vault), injects them, and forwards the request — real credentials never leave the server or touch agent memory.

---

## Install

```bash
make build
```

Produces two binaries in the project root:

| Binary | Role |
|--------|------|
| `proxyd` | Reverse-proxy daemon — handles agent HTTP traffic and admin socket |
| `proxyctl` | CLI tool — manages keystore, upstreams, policies, and tokens |

Requires Go 1.22+.

---

## Quickstart

### 1. Initialize the keystore

```bash
./proxyctl bootstrap
```

Prompts for a passphrase. Derives a key-encryption key (KEK) via Argon2id and writes an envelope-encrypted SQLite store to `~/.proxyd/keystore.db`.

### 2. Start the proxy daemon

In a separate terminal:

```bash
./proxyd
```

Listens on `http://127.0.0.1:8080` for agent traffic and exposes an admin socket at `$HOME/.proxyd/admin.sock` (mode 0600).

### 3. Unlock the keystore

```bash
./proxyctl unlock
```

Prompts for the same passphrase. Decrypts the DEK and loads it into the running daemon via the admin socket.

### 4. Register an upstream

The `parseInject` helper in proxyctl is currently a stub. Register upstreams directly against the admin socket:

```bash
curl --unix-socket $HOME/.proxyd/admin.sock -s \
  -X POST http://localhost/v1/upstreams \
  -H "Content-Type: application/json" \
  -d '{
    "id": "openai",
    "base_url": "https://api.openai.com",
    "provider": "doppler",
    "secret_path": "OPENAI_API_KEY",
    "inject_header": "Authorization",
    "inject_prefix": "Bearer "
  }'
```

### 5. Add a policy

```bash
./proxyctl policy add --engine opa --file policy.rego
```

Example `policy.rego`:

```rego
package proxy

default allow = false

allow {
    input.token.upstream == input.request.upstream_id
    input.request.method == "POST"
}
```

The command prints the policy `<id>` — keep it for the next step.

### 6. Mint a subtoken

```bash
./proxyctl token mint \
  --label ci \
  --upstream openai \
  --policy <id> \
  --ttl-seconds 3600
```

Prints a `pxy_*` token. Hand this to your agent — it never sees the real key.

### 7. Agent call

```bash
curl -H "Authorization: Bearer pxy_<token>" \
  http://127.0.0.1:8080/openai/v1/chat/completions \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'
```

The proxy:
1. Validates the subtoken (hash lookup + TTL check)
2. Evaluates the OPA policy against request context
3. Resolves the real `OPENAI_API_KEY` from Doppler (TTL-cached in memory)
4. Strips `Authorization` from the inbound request, injects the real credential, and forwards

---

## Security model

### Subtokens

`pxy_*` tokens are 256-bit random strings. Only their SHA-256 hash is stored. A stolen subtoken is bounded by TTL and the OPA policy attached at mint time.

### Encryption at rest

The data-encryption key (DEK) is encrypted by a KEK derived from your passphrase using Argon2id (time=3, memory=64 MB). The DEK ciphertext is stored with XChaCha20-Poly1305 authenticated encryption. The passphrase never persists to disk.

### Credential handling

Upstream API credentials are never written to the keystore. They are resolved live from the configured provider on first use and cached in memory with a short TTL. A proxy restart clears the cache.

### Header stripping

`Authorization`, `Cookie`, and `Proxy-Authorization` headers from the agent request are always removed before forwarding upstream. Credentials are injected fresh from the resolved secret.

### Admin surface

The admin API is exposed only over a Unix domain socket (`$HOME/.proxyd/admin.sock`, mode 0600). Only the OS user who owns the socket can call it — no network exposure.

---

## Known limitations (v1)

- **Subset attenuation is admin-asserted** — there is no formal cryptographic subset proof; the `policy.subset_of` chain relies on the admin correctly scoping policies at mint time.
- **No rate limiting** — the proxy does not enforce per-token or per-upstream request quotas.
- **Single-node only** — no HA, clustering, or shared keystore support.
- **`parseInject` is a stub** — upstream registration via `proxyctl` is not yet wired; use direct admin socket calls (see Quickstart step 4).
- **Config YAML loader exists but is not consumed** — `proxyd` does not yet read its config file on startup; defaults are compiled in.
