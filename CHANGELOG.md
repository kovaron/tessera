# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Rebrand from `proxyd` / `proxyctl` / `ai-secrets-manager` to **Tessera** / **tessera-cli**. Go module path is now `github.com/kovaron/tessera`. Default state directory moved from `~/.proxyd/` to `~/.tessera/`. Tauri app product name and identifier updated.

### Added
- Project logo, README naming explanation, OSS scaffolding (LICENSE, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, CHANGELOG.md, issue + PR templates, examples directory, architecture overview).
- Multiple policies per upstream. Policies now carry a `name` and optional `upstream_id` — a policy with no upstream is global and applies to any. `GET /v1/policies`, `GET/PUT/DELETE /v1/policies/{id}` admin endpoints. UI Policies screen reworked into a list grouped by upstream with a side-drawer editor. Token mint dropdown filters policies by the chosen upstream. Existing policies migrate forward via `ALTER TABLE` with sensible defaults (empty name, null upstream = global).

## [admin-ui-v0.1.0] — 2026-05-24

### Added
- Tauri-based macOS desktop admin app: bootstrap wizard, unlock / lock, upstream / policy / token management, live audit-log tail, Rego editor with OPA cheatsheet.
- Persistent audit log at `~/.tessera/audit.log` with size-based rotation (default 100 MB threshold, keep 5).
- `tessera-cli bootstrap --passphrase-stdin` flag for non-interactive keystore initialisation (used by the desktop wizard).
- `GET /v1/status` now exposes `initialized` so the UI can route uninitialised installs to the bootstrap wizard.
- Audit `deny` events from the authz middleware (was previously silent on rejection).

## [v0.1.1] — 2026-05-24

### Fixed
- DEK is now explicitly zeroed in memory on `lock()` (a second slice copy in `admin.State.dek` was previously left untouched until garbage collection).
- Attenuation rejects `ttl_seconds <= 0` requests — children could otherwise outlive their parent.
- Token and parent expiry checks use `>=` (was `>`, accepting an expired token for up to one extra second).
- `authn.Generate()` error in the attenuate path is now propagated instead of discarded.
- README factual errors: SHA-256 (not BLAKE3), socket path `~/.tessera/admin.sock`, route prefix `/u/<upstream_id>/...`.

### Changed
- `revokeCascade` switched from unbounded recursion to depth-limited iterative BFS (max depth 16, cycle-safe via a `seen` set).
- `PRAGMA foreign_keys = ON` is issued explicitly after `sql.Open` so the in-schema FK constraints actually take effect.
- `singleflight.Do` wraps the upstream call in `context.WithoutCancel` so the first waiter's cancellation no longer poisons co-waiters.
- `GET /healthz` returns HTTP 503 when locked, with body `{"locked": true}`.
- Reverse-proxy ErrorHandler now records the upstream error message in the audit event's `deny_reason`.

## [v0.1.0] — 2026-05-23

### Added
- Initial release. Reverse-proxy daemon, admin unix socket, CLI tool, OPA policy engine, encrypted SQLite store, secret providers for `env://`, `1password://`, `doppler://`, and `vault://`, subtoken hashing with parent-chain attenuation, header sanitization on the data plane, structured JSON audit logger, full end-to-end integration test.
