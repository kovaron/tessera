# Transparent forward-proxy mode — design

**Date:** 2026-06-03
**Status:** Approved

## Goal

Let users run `tessera exec -- <cmd>` and have all HTTPS traffic from the child process transparently routed through Tessera. The child uses real hostnames (`api.openai.com`) instead of `http://127.0.0.1:8080/u/openai/...`. Tessera intercepts, authn/authz/inject as today, forwards to the real upstream.

## Non-goals (v1)

- HTTP/2 and HTTP/3 in the MITM path.
- WebSocket upgrades through MITM.
- Bypassing cert-pinned apps.
- Per-process ports (single shared listener).
- macOS launchctl / system-wide proxy injection (manual `tessera exec` only).

## Architecture

Two listeners share the same store / authn / authz / inject machinery:

| Listener | Address | Role |
|---|---|---|
| Path-based (existing) | `127.0.0.1:8080` | Agents call `/u/<upstream>/...`. Still supported. |
| Transparent forward-proxy (new) | `127.0.0.1:8443` | HTTP/1.1 forward proxy. Accepts `CONNECT host:443`, MITMs TLS using a leaf cert minted on the fly, applies the existing middleware chain, forwards to the real upstream. |

A child launched via `tessera exec` only ever talks to `127.0.0.1:8443`. The proxy figures out which upstream the request is for by matching the `Host` header against a configured hostname list per upstream.

`--allow-passthrough` is **off** by default: an unknown hostname is denied with `502 + audit unknown_host`, not forwarded transparently.

## Components

### `internal/pki`

Root CA + leaf cert factory.

- **Root** generated once at bootstrap. P-256 ECDSA. 10y validity. PEM exported via `tessera-cli ca export`. PEM + private key AEAD-encrypted with the DEK in a new `keystore_ca` table.
- **Leaf factory** — given a hostname:
  - LRU cache (256 entries, TTL 30 days).
  - On miss, mint a leaf signed by the root with SAN=hostname, 30d validity, EKU=serverAuth.
- **Trust install helper** — `tessera-cli ca install` shells out to `security add-trusted-cert -d -r trustAsRoot -k ~/Library/Keychains/login.keychain-db ~/.tessera/ca.pem`. Requires user password (one-time).

### `internal/proxy/forward.go`

The forward-proxy listener.

- Listens for `CONNECT host:port` requests.
- Reply `200 OK`.
- Wrap the conn with `tls.Server` using a `GetCertificate` callback that calls `pki.LeafFor(clientHelloInfo.ServerName)`.
- After TLS handshake, parse the inner HTTP/1.1 request, run the existing middleware chain (lock → authn → authz → inject), build a reverse-proxy request to the real upstream.
- For plaintext HTTP (rare for these upstreams), handle inline without TLS termination — same chain.

### `internal/upstreams`

- Add `Hostnames []string` to `Upstream`.
- Build a reverse index `hostname → upstream_id` at registry hydration; rebuild on Upsert / Delete.

### `internal/store`

- New column `upstreams.hostnames TEXT` (JSON array, default `[]`). Idempotent migration via `addUpstreamColumns` mirroring the policy-column pattern.
- New table `keystore_ca` (singleton, `id = 1`):
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

### `cmd/tessera-cli/exec.go`

`tessera-cli exec [flags] -- <cmd> [args...]`

Flags:
- `--upstream <id>` (required) — the upstream this exec session is scoped to. Bound to the minted child token.
- `--policy <id>` (required) — Rego policy applied to every request from the child.
- `--ttl <duration>` (default `1h`) — child token lifetime.
- `--label <string>` (default `exec:<pid>`) — audit label.

Behaviour:
1. POST `/v1/tokens` over admin socket with the above. Capture `pxy_…` from response.
2. Build child env: parent env + `HTTPS_PROXY` + `HTTP_PROXY` + CA bundle env vars + `PXY_TOKEN`.
3. Spawn child. Forward signals (`SIGINT`/`SIGTERM`).
4. On child exit, `DELETE /v1/tokens/<id>` to revoke the exec token (cascade-revokes any children minted via attenuation).

### Admin API additions

- `POST /v1/upstreams` body adds `"hostnames": ["api.openai.com", "api.openai.cn"]`.
- `GET /v1/ca` — returns PEM. UI uses for the "Install CA" flow.
- `POST /v1/ca/install` — runs the `security` helper. Returns its stderr on failure.

## Data flow

```
child process                  Tessera                       upstream
─────────────                  ───────                       ────────
HTTPS req to api.openai.com
   │
   │ HTTPS_PROXY env → CONNECT api.openai.com:443 HTTP/1.1
   ├──────────────────────────────►
   │                              200 OK
   │ ◄────────────────────────────
   │ TLS ClientHello (SNI: api.openai.com)
   ├──────────────────────────────►  pki.LeafFor("api.openai.com")
   │ ◄────────────────────────────  TLS handshake completes
   │ POST /v1/chat/completions
   │   Authorization: Bearer $PXY_TOKEN
   ├──────────────────────────────►  authn(PXY_TOKEN) →
   │                                   token.upstream = "openai"
   │                                 hostnames["api.openai.com"] →
   │                                   upstream = "openai" ✓ match
   │                                 authz(policy) → allow
   │                                 strip Authorization
   │                                 secrets.Get(openai.inject) →
   │                                   real OPENAI_API_KEY
   │                                 inject Authorization: Bearer <real>
   │                                                              │
   │                              POST /v1/chat/completions ──────►
   │                                       ◄──────── 200 response
   │ ◄──────────────────────────── 200 response (re-encrypted)
```

## Error handling

| Condition | Response | Audit reason |
|---|---|---|
| Unknown hostname (no upstream mapping) | 502 | `unknown_host` |
| Token's `upstream_id` ≠ resolved upstream | 403 | `upstream_mismatch` |
| Leaf cert mint failure (invalid hostname) | 502 | `leaf_mint_failed` |
| CA not present at startup | Forward listener disabled, daemon keeps serving `:8080` and logs a warning | n/a |
| Lock middleware: DEK not loaded | 503 | (existing) |
| TLS handshake failure (client refused cert) | TCP RST | n/a — pre-MITM |

## Security model

- The MITM CA is a Tessera-issued root, trust-installed by the user with explicit `security add-trusted-cert`. Compromise of this CA is equivalent to compromise of the DEK (both required to mint leaf certs). The CA key is AEAD-encrypted at rest, only unwrapped at runtime alongside the DEK.
- The forward-proxy listener is `127.0.0.1`-only; no network exposure.
- The child receives `PXY_TOKEN` in its environment. Any process inside the child's process tree can read it. Limit child blast radius by combining narrow policy + short TTL.
- Audit log emits one event per request through the forward proxy, same shape as path-based today.
- Cert-pinned upstreams will break (handshake failure visible in child). This is the design — we will not silently bypass.

## Testing

- **Unit**
  - `pki.LeafFor("api.openai.com")` — cert has SAN match, chain verifies against root.
  - `store.upstreams.hostnames` round-trip including idempotent migration on an old DB.
  - `pki.AEADRoundTrip` — CA encrypt/decrypt under DEK.

- **Integration (Go)**
  - Spin up a self-signed fake upstream on `127.0.0.1:N`. Register it with `hostnames: ["fake.test"]` and a stub policy that allows GET. Open a TCP client to `:8443`, perform `CONNECT fake.test:443`, complete TLS using the Tessera CA as trust root, send `GET /`, expect 200 with the injected Authorization on the upstream side.
  - Token-upstream mismatch: token bound to `openai`, request `Host: api.github.com` — expect 403 + audit `upstream_mismatch`.
  - Unknown host: `Host: api.unknown.com`, no mapping — expect 502 + audit `unknown_host`.

- **End-to-end (manual)**
  - `tessera-cli exec --upstream openai --policy chat-only -- python -c "import openai; openai.ChatCompletion.create(model='gpt-4o', messages=[{'role':'user','content':'hi'}])"` — succeeds, audit event recorded, child exit triggers revoke.

## Migration / rollout

No production usage yet → no compatibility shim. Bootstrap a new DB or run the daemon once to apply the new schema migration in place. Existing upstreams default to `hostnames: []` (so they keep working over the path-based listener; the forward listener simply has no mapping for them until you set one).

## Out-of-spec follow-ups

- HTTP/2 ALPN support in the MITM (needed for clients that pin HTTP/2).
- Per-exec ephemeral ports for stronger token-port binding.
- `tessera-cli exec --auto-policy` that synthesises a path-allowlist policy from a `--allow PATH` flag.
- UI screen listing active exec sessions with revoke buttons.
