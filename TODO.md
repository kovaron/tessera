# TODO — post-v0.1.0 follow-ups

Findings from final code review (commit `fc8726a`, tag `v0.1.0`). All severities are the reviewer's assessment.

## Critical

- **`internal/authn/lookup.go:31,49`** — Token expiry uses `>` not `>=`. A token whose `ExpiresAt == now.Unix()` is accepted for one extra second. Same off-by-one on parent expiry check.
- **`internal/crypto/keyprovider_pass.go:52` + `internal/admin/unlock.go:32`** — `Unlock()` returns the raw DEK to the caller, which the admin handler stores in `atomic.Value`. `Lock()` zeroes the provider's internal copy but NOT the slice in `admin.State.dek`. After `POST /v1/lock` the DEK remains readable in memory until GC. Fix: in `lock()` handler, retrieve the old slice and zero it before storing nil.
- **`internal/admin/attenuate.go:47-50`** — When `body.TTLSeconds == 0`, child token is inserted with `exp = nil` even if parent has finite `ExpiresAt`. Attenuated child outlives parent. Fix: reject `TTLSeconds <= 0` or inherit parent expiry.
- **`internal/admin/attenuate.go:52`** — `plain, hash, _ := authn.Generate()` swallows `crypto/rand` error. On rare failure, an empty-hash token is persisted and `{"secret":""}` returned with 201.
- **`README.md`** — Multiple false claims:
  - L122 says "BLAKE3 hash" — actual code uses SHA-256 (`internal/authn/hash.go:14`).
  - L42 references socket path `/tmp/proxyd.sock` — actual default is `$HOME/.proxyd/admin.sock` (`cmd/proxyd/main.go:26`).
  - L64 example curl uses `/admin/upstreams` — actual route is `/v1/upstreams`.

## Risk (important)

- **`internal/proxy/reverseproxy.go:67-79`** — Audit `log.Emit` runs only after successful upstream forward. Authz denies are silently dropped. Add deny emission in `AuthzMiddleware`.
- **`internal/admin/revoke.go:26-40`** — `revokeCascade` is unbounded recursive. A cycle in the parent graph stack-overflows. Add depth limit or iterative BFS.
- **`internal/store/sqlite.go`** — `PRAGMA foreign_keys = ON` never issued. Token `parent_id` and policy `subset_of` FK constraints are inert. Enable pragma on connection open.
- **`internal/secrets/cache.go:30-43`** — `singleflight.Do` passes outer ctx. First waiter's cancellation poisons all co-waiters. Use `context.WithoutCancel(ctx)` (Go 1.21+).
- **`internal/proxy/server.go:55`** — `/healthz` bypasses lock check; reports healthy when locked. Either return non-200 when locked or document.
- **`internal/proxy/reverseproxy.go:54`** — Duplicate `Sanitize(req.Header)` inside Director and in `InjectMiddleware`. Harmless but obscures stripping responsibility. Consolidate.
- **`internal/admin/attenuate.go:23-24`** — No admin/privilege check on bearer token. Any valid data-plane token can attenuate via admin socket. Acceptable given 0600 socket but document.
- **`tests/security/security_test.go:43-51`** — `TestPathTraversalRejected` asserts wrong thing (id field). The dangerous part is `rest` being appended to upstream BaseURL. Test should verify forwarded URL doesn't contain `..`.

## Question

- **`internal/admin/policies.go:41`** — `SubsetOf` reference is not validated against store before insert. Dangling references silently break attenuation. Intentional?

---

Recommended order: Critical 1-4 → README (Critical 5) → Risk in listed order.
