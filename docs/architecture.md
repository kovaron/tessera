# Architecture

A short overview of how Tessera is put together. For the original design and the task-by-task implementation plan, see `docs/superpowers/specs/` and `docs/superpowers/plans/`.

## High-level flow

```
┌────────────┐    pxy_*    ┌─────────────────────────────────┐    real key    ┌──────────────┐
│  AI Agent  │ ──────────► │             Tessera             │ ─────────────► │ Upstream API │
└────────────┘             │  authn → authz → inject         │                └──────────────┘
                           │   ▲       ▲        ▲                                    │
                           │   │       │        │   secret resolved live             │
                           │   │       │        └───────► 1Password / Doppler /      │
                           │   │       │                  Vault / env                │
                           │   │       │                                             │
                           │   │       └── OPA policy decode + eval                  │
                           │   │                                                     │
                           │   └── SHA-256 hash lookup + parent-chain check          │
                           │                                                         │
                           │                                                         │
                           │            ◄────────────── response ─────────────────── │
                           └─────────────────────────────────┘
```

## Process layout

Two binaries plus a desktop app, all running as the same OS user on one machine.

- **`tessera`** — long-running daemon. Listens on `127.0.0.1:8080` for agent traffic. Listens on `~/.tessera/admin.sock` (mode 0600) for admin commands.
- **`tessera-cli`** — operator CLI for bootstrap, unlock, and CRUD. Talks to the admin socket.
- **Desktop UI** (Tauri) — bundles `tessera-cli` as a sidecar for bootstrap, talks to the admin socket directly for everything else.

## Go package layout

| Package | Role |
|---|---|
| `cmd/tessera` | Daemon entry point. Parses flags, opens the store, starts the admin socket, builds the data plane. |
| `cmd/tessera-cli` | Cobra CLI. Bootstrap, unlock, status, upstream/policy/token commands. |
| `internal/store` | SQLite persistence. Tokens, policies (encrypted), upstreams, keystore (singleton). |
| `internal/crypto` | XChaCha20-Poly1305 AEAD, Argon2id KDF, envelope DEK wrap/unwrap, PassphraseProvider. |
| `internal/authn` | Subtoken generation (`pxy_*`), SHA-256 hashing, parent-chain resolve with depth limit. |
| `internal/authz` | OPA engine adapter, compiled-policy cache keyed by source hash. |
| `internal/secrets` | SecretProvider interface, registry, env / 1Password / Doppler / Vault impls, TTL cache with singleflight. |
| `internal/upstreams` | In-memory upstream registry hydrated from store; injection rule execution (bearer / header / query). |
| `internal/proxy` | Middleware chain (lock → authn → authz → inject), reverse proxy assembly, header sanitizer, audit emit on every outcome. |
| `internal/audit` | Structured JSON event types, multi-writer logger, size-based rotating file writer. |
| `internal/admin` | HTTP handlers on the unix socket: status, unlock/lock, upstreams, policies, tokens, attenuate. |
| `internal/config` | YAML config loader (scaffolded, not yet consumed by the daemon). |

## Where the guards sit

Every data-plane request crosses four checkpoints before a real credential is even resolved:

1. **Lock middleware** — returns 503 if the DEK is not loaded.
2. **Authn middleware** — Bearer header → hash → store lookup → parent-chain walk → token in request context.
3. **Authz middleware** — fetches the encrypted policy, decrypts with the DEK, compiles via OPA (cached), evaluates against `{token, upstream, request}`. Emits an audit deny on rejection.
4. **Reverse proxy Director** — strips inbound `Authorization` / `Cookie` / `Proxy-Authorization`, resolves the upstream secret via the live provider (TTL-cached), injects per the upstream's inject rule, forwards.

Outside the data plane:

- **Admin socket** is 0600. Only the OS user reaches it.
- **Keystore on disk** is SQLite. Policy source is AEAD-encrypted with the DEK. The DEK itself is wrapped under a KEK derived from your passphrase via Argon2id and only unwrapped at runtime.
- **Audit log** at `~/.tessera/audit.log` records every allow and every deny with reason codes. Size-rotated.

## Data flow on the happy path

```
Agent → POST /u/<upstream_id>/<path>
        Authorization: Bearer pxy_xyz...
                │
                ▼
       LockMiddleware (DEK loaded?)
                │
                ▼
       AuthnMiddleware
         hash = sha256(pxy_xyz...)
         token = store.LookupTokenByHash(hash)
         walk parent chain (max depth 16)
                │
                ▼
       AuthzMiddleware
         src = store.GetPolicy(token.policy_id)
         pt  = AEAD.Open(DEK, src)
         compiled = cache.GetOrCompile(token.policy_id, pt)
         compiled.Eval({token, upstream, request})  → allow
                │
                ▼
       Director
         path  = baseURL + path.Clean(rest)
         strip Authorization / Cookie / Proxy-Authorization
         secret = secrets.Cache.Get(upstream.inject.secret_ref)
         apply inject rule  →  Authorization: Bearer <real key>
                │
                ▼
       Upstream API
                │
                ▼ response
       statusWriter captures status code
                │
                ▼
       audit.Emit({decision: "allow", status, latency_ms, …})
```

## What is intentionally out of scope (v1)

- Multi-instance / multi-user. Single OS user, single daemon.
- Network-exposed admin API. Unix socket only.
- Formal cryptographic subset proofs for attenuation. The `policy.subset_of` chain is admin-asserted.
- Rate limiting and quota enforcement.
- Built-in cluster / HA.

See [`CHANGELOG.md`](../CHANGELOG.md) for what has shipped and `docs/superpowers/specs/2026-05-21-auth-proxy-design.md` for the full design rationale.
