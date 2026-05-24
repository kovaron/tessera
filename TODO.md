# TODO — remaining post-review items

All Critical + Risk findings from the v0.1.0 final review have been addressed in v0.1.1.
See `git log v0.1.0..v0.1.1` for the fix commits.

## Resolved in v0.1.1

### Critical
- `internal/authn/lookup.go` — expiry boundary `>` → `>=` (token + parent).
- `internal/crypto/keyprovider_pass.go` + `internal/admin/unlock.go` — `lock()` zeroes the DEK slice in memory before swapping the atomic.Value pointer.
- `internal/admin/attenuate.go` — `ttl_seconds <= 0` now rejected with HTTP 400; child can no longer outlive parent.
- `internal/admin/attenuate.go` — `authn.Generate()` error now checked, returns 500.
- `README.md` — corrected: SHA-256 (not BLAKE3); socket path `$HOME/.proxyd/admin.sock`; admin routes `/v1/...`.

### Risk
- `internal/proxy/middleware_authz.go` — deny events now emitted to audit logger with reason codes (`no_token`, `policy_unavailable`, `policy_invalid`, `eval_error`, `policy_denied`).
- `internal/admin/revoke.go` — recursive cascade replaced with iterative BFS, depth limit 16, cycle detection via `seen` map.
- `internal/store/sqlite.go` — `PRAGMA foreign_keys = ON` issued explicitly after `sql.Open` (in addition to URL param). Test `TestForeignKeysEnforced` verifies.
- `internal/secrets/cache.go` — `context.WithoutCancel(ctx)` inside `singleflight.Do` so first-waiter cancellation cannot poison co-waiters.
- `internal/proxy/server.go` — `/healthz` returns 503 + `{"locked":true}` when DEK not loaded.
- `internal/proxy/reverseproxy.go` — `path.Clean` applied to upstream URL; duplicate `Sanitize` is intentional defense-in-depth (commented).
- `internal/admin/attenuate.go` — comment documents that any data-plane bearer may attenuate (0600 socket is the boundary).
- `tests/security/security_test.go` — `TestPathTraversalRejected` rewritten as end-to-end; asserts forwarded path contains no `..`.

## Open

### Question (deferred — call before changing)
- `internal/admin/policies.go:41` — `SubsetOf` reference not validated against store before insert. Dangling references silently break attenuation. May be intentional (caller is admin, schema FK now enforces existence anyway after the foreign_keys pragma fix). Leaving as-is until usage shows it matters.
