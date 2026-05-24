# Admin UI — Design

> macOS desktop admin app for `proxyd`. Tauri 2 + React + shadcn/ui + Monaco. Single local instance. Full feature parity with `proxyctl` plus a live audit log viewer.

## Goals

1. Run as a macOS app (no terminal needed for daily ops or first-time setup).
2. Full parity with `proxyctl`: bootstrap, unlock/lock, manage upstreams/policies/tokens (mint, list, revoke, attenuate).
3. Live audit log viewer with filter and detail drawer.
4. Rich Rego policy editor with local OPA WASM compile feedback before save.
5. Inherit `proxyd`'s security model. No new attack surface.

## Non-goals (v1)

- Multi-instance / multi-socket management. Single `$HOME/.proxyd/admin.sock`.
- Remote proxyd over network. Local unix socket only.
- Starting/stopping proxyd from the UI. User runs `proxyd` separately (launchd, brew service, terminal).
- Multi-user. Single OS user only.
- Telemetry, crash reporting, analytics. None.
- iOS / iPad. Future work; rejected today (Q2).

---

## 1. Architecture

```
┌─────────────────────────────────────────────────┐
│  Tauri macOS App  (~/Applications/proxyui.app)  │
│                                                 │
│  ┌──────────────────────────────────────────┐   │
│  │ React + shadcn/ui (webview)              │   │
│  │ - Monaco editor + OPA WASM compile       │   │
│  │ - State: TanStack Query → IPC            │   │
│  └────────────────┬─────────────────────────┘   │
│                   │ tauri::invoke               │
│  ┌────────────────▼─────────────────────────┐   │
│  │ Rust backend                             │   │
│  │ - hyper unix-socket client → admin sock  │   │
│  │ - tokio file watcher → audit.log tail    │   │
│  │ - macOS Keychain (tauri-plugin-keychain) │   │
│  │ - fs::exists check for keystore + sock   │   │
│  │ - bundled proxyctl sidecar for bootstrap │   │
│  └────────────────┬─────────────────────────┘   │
└───────────────────┼─────────────────────────────┘
                    │ AF_UNIX (0600)
                    ▼
    ┌──────────────────────────┐
    │ proxyd                   │
    │ - admin sock /v1/*       │
    │ - audit.log writer (new) │
    └──────────────────────────┘
```

**Boundaries**

- React = view + state. Knows nothing about sockets.
- Rust = OS / IO. Owns the unix-socket HTTP client, audit-file tailer, Keychain access, sidecar invocation.
- IPC via `tauri::invoke` with `specta` / `ts-rs` codegen so TS types are derived from Rust structs at build time.

**No new admin endpoints required.** UI is a client of the existing `/v1/*` routes. Only `proxyd` change is the audit-log file writer (§5).

---

## 2. Screens

Sidebar layout, seven routes.

```
┌──────────────┬────────────────────────────────────┐
│ ● Connected  │                                    │
│ ○ Unlocked   │      [active screen content]       │
│ ──────────── │                                    │
│ Dashboard    │                                    │
│ Upstreams    │                                    │
│ Policies     │                                    │
│ Tokens       │                                    │
│ Audit Log    │                                    │
│ Settings     │                                    │
│ ──────────── │                                    │
│ Lock         │                                    │
└──────────────┴────────────────────────────────────┘
```

### 2.1 Dashboard
- Locked / unlocked badge.
- proxyd reachable badge.
- Counts: upstreams, policies, active tokens, revoked tokens (computed in UI from list responses).
- Last 10 audit events (live).
- Quick actions: "Mint token", "Add upstream".

### 2.2 Upstreams
- Table: id, base_url, inject type.
- Row click → side drawer with edit form.
- Inject rule builder: type dropdown (`bearer` / `header` / `query`) → conditional fields (name + value_template for header, name for query, secret_ref always required).
- "Add" button → same drawer empty.

### 2.3 Policies
- List: id, engine, subset_of, created_at.
- Click → split view. Monaco rego editor left, OPA WASM compile panel right (red/green diagnostics).
- "Save" disabled until compile clean.
- "New" modal: pick `engine` (opa only for v1) and optional `subset_of` from existing policies.

### 2.4 Tokens
- Tree view (parent → children expanded). Columns: label, upstream, expires-in, revoked.
- "Mint" button → modal (label, upstream picker, policy picker, TTL slider).
- "Attenuate" action on a non-revoked parent row → same modal pre-filled with parent id, restricted to subset policies of parent.
- "Revoke" row action → confirm modal listing children that will cascade-revoke.

### 2.5 Audit Log
- Live tail (push from Rust file watcher).
- Sticky filter bar: decision (allow / deny), upstream, token label, free-text search.
- Virtualized row list (react-virtual; up to 5000 rows in memory).
- Row click → JSON detail drawer.

### 2.6 Settings
- Socket path (default `$HOME/.proxyd/admin.sock`).
- Audit log path (default `$HOME/.proxyd/audit.log`).
- Theme (light / dark / system).
- "Store passphrase in Keychain" toggle.
- Danger zone: "Delete keystore and re-bootstrap" (requires typed confirmation).

### 2.7 Modal flows

- **First launch / no keystore:** full-screen bootstrap wizard (§4).
- **Locked:** full-screen unlock prompt (passphrase) → `POST /v1/unlock`.
- **proxyd unreachable:** banner "proxyd not running" with copy-able command. No auto-start.

---

## 3. Data flow + state

### 3.1 Read path
```
React component
  └─ TanStack Query: useUpstreams()
       └─ tauri::invoke("list_upstreams")
            └─ Rust: GET /v1/upstreams via unix socket → JSON → typed struct
                 └─ specta-generated TS type returned to React
```

### 3.2 Write path
Identical, via TanStack mutation hooks. Success invalidates relevant query keys.

### 3.3 Audit tail (push)
```
proxyd → audit.log (append-only JSONL)
  └─ Rust: tokio::fs::File seek-to-end + line reader
       └─ tauri emit("audit:event", parsed) per new line
            └─ React: useEffect listen("audit:event") → ring buffer (≤5000)
```

File rotation handled by Rust by re-opening the path when the watcher reports rename / inode change.

### 3.4 OPA WASM compile (local, no IPC)
```
Monaco onChange → debounce 300ms
  └─ @open-policy-agent/opa-wasm: rego.compile(source)
       └─ result → editor diagnostics + Save enable
```

### 3.5 State buckets
- **TanStack Query cache** — all REST data (upstreams, policies, tokens, status).
- **Zustand store** — app-level (current screen, theme, selected row IDs).
- **React ref** — audit ring buffer (mutable, not reactive; virtualizer subscribes).

### 3.6 Types
`specta` + `ts-rs` derive on Rust structs → emit `bindings.ts` at build time. Frontend imports types; no manual sync.

---

## 4. Bootstrap wizard

The UI owns first-launch. No `proxyctl` interaction required for new users.

### 4.1 Detection on launch (Rust)
```
1. db_exists($HOME/.proxyd/data.db)?  → keystore initialized
2. socket_exists($HOME/.proxyd/admin.sock)? → proxyd running
3. GET /v1/status reachable? → confirm alive
4. status.locked == true? → show unlock screen
```

### 4.2 State machine
```
                ┌─────────────────────┐
                │ App launch          │
                └──────────┬──────────┘
                           ▼
                  ┌────────────────┐
       ┌──────────│ db exists?     │
       │ no       └────┬───────────┘
       ▼               │ yes
  ┌──────────┐         ▼
  │ BOOTSTRAP│   ┌──────────────┐
  │ wizard   │   │ sock alive?  │──no──▶ "Start proxyd" banner
  └────┬─────┘   └──────┬───────┘
       │                │ yes
       │                ▼
       │         ┌────────────────┐
       │         │ status.locked? │──yes──▶ Unlock screen
       │         └──────┬─────────┘
       │                │ no
       │                ▼
       │           Dashboard
       └────────────────┘
       (after bootstrap, fall through to "start proxyd" banner)
```

### 4.3 Wizard screens
1. Welcome — what is about to happen + db path (configurable).
2. Passphrase — input + confirm. Strength meter. Minimum 12 chars.
3. Optional: "Store in Keychain?" toggle. If yes, save under service `com.kovaron.proxyui`, account `passphrase`.
4. "Creating keystore…" spinner — Rust spawns bundled `proxyctl` sidecar.

### 4.4 Sidecar
Ship `proxyctl` as a Tauri sidecar binary. Rust invokes `proxyctl bootstrap --db <path>` with passphrase piped via stdin. Avoids re-implementing Argon2 / AEAD in Rust.

Bundle layout in `tauri.conf.json`:
```
binaries/proxyctl-aarch64-apple-darwin
binaries/proxyctl-x86_64-apple-darwin
```
Built by extending `Makefile` with cross-compile targets.

### 4.5 Post-bootstrap
Show "Now start proxyd" with the exact command + copy button. Once the socket appears (filesystem watch on socket path), UI transitions automatically to the unlock screen.

---

## 5. Backend (proxyd) changes

Minimal, two changes.

### 5.1 Multi-writer audit logger
`internal/audit/logger.go` accepts a variadic `io.Writer` list:
```go
func New(writers ...io.Writer) *Logger {
    w := io.MultiWriter(writers...)
    return &Logger{w: w, enc: json.NewEncoder(w)}
}
```
Backward-compatible — existing single-writer callers keep working.

`cmd/proxyd/main.go`:
```go
auditPath := flag.String("audit-log", os.ExpandEnv("$HOME/.proxyd/audit.log"), "audit log file")
// ...
f, err := os.OpenFile(*auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
if err != nil { log.Fatal(err) }
defer f.Close()
auditLogger := audit.New(os.Stdout, f)
```
Mode 0600. Same trust boundary as the admin socket.

### 5.2 Rotation
New `internal/audit/rotate.go`:
- Wrap the file writer in a struct that checks size on each `Emit`.
- When size > 100 MB → close, rename `audit.log` → `audit.log.1`, open fresh `audit.log`.
- Keep last 5 rotations (`audit.log.1` … `audit.log.5`); delete older.
- Single goroutine-safe via the Logger's existing mutex.

### 5.3 Stats endpoint
Deferred. UI computes counts client-side from list responses for v1. Revisit if list responses get too large.

---

## 6. Security model

UI inherits the proxyd trust model. No new attack surface beyond the existing admin socket.

**Threat boundary:** macOS user account. Whoever owns the user owns proxyd. UI does not weaken or extend this.

1. **Socket access** — UI connects to `$HOME/.proxyd/admin.sock` (0600). Tauri runs as the logged-in user, same access as `proxyctl`. No privilege escalation.
2. **Passphrase handling**
   - Wizard + unlock prompt: input field `type=password`, no echo, no logging.
   - In-memory: Rust holds the passphrase only long enough to POST `/v1/unlock` or to feed `proxyctl bootstrap`. Zeroed via the `zeroize` crate after use.
   - Keychain opt-in: stored under service `com.kovaron.proxyui`, account `passphrase`. Retrieval requires Touch ID / login password (macOS default).
3. **Minted secret display** — modal auto-copies to clipboard. Show timer "clipboard cleared in 60s"; Rust schedules a clipboard clear via `tauri-plugin-clipboard-manager`. Modal masks the secret behind a reveal toggle even after first show.
4. **Audit log file** — `proxyd` opens it 0600. UI reads as the same user. No exposure.
5. **OPA WASM** — local compile only, never sends rego source over the network. Policy bodies stay in memory + admin socket only.
6. **Code-signing + notarization** — release build signed with Developer ID cert + notarized. Prevents tampered binaries.
7. **Update channel** — manual download from GitHub releases for v1. Tauri updater (with signed releases) deferred.
8. **No telemetry** — local-only app. No analytics, no remote logging, no crash reporter.

**Explicit non-goals:**
- Multi-user. Single OS user only.
- Sandboxed renderer talking to remote APIs. UI never connects to internet.
- Hardening against a root attacker. Root reads `~/.proxyd/data.db` directly; UI cannot mitigate.

---

## 7. Testing

### 7.1 Backend (Go)
- `internal/audit/logger_test.go` — extend for multi-writer.
- `internal/audit/rotate_test.go` — new. Synthetic > 100 MB emit → assert rename + new file + cleanup of `.6` and older.

### 7.2 Rust (Tauri backend)
- Unit tests per command (`list_upstreams`, `mint_token`, etc.) with a fake unix socket server (`tokio::net::UnixListener` in test). Assert JSON encode/decode + error mapping.
- Audit tailer: temp file, append lines, assert events emitted in order. Test rotation handling (rename mid-tail).

### 7.3 React
- Vitest + React Testing Library.
- Component tests for forms (inject rule builder, mint modal, attenuate modal).
- Hook tests for the TanStack Query layer with `tauri::invoke` mocked.
- OPA WASM compile hook — known-good rego → no diagnostics; known-bad → diagnostics non-empty.

### 7.4 E2E
- Playwright + `tauri-driver`.
- Headed against real built app + real proxyd binary.
- Single happy path: bootstrap → unlock → add upstream → add policy → mint token → see audit event → revoke → see deny in audit.
- Build tag `e2e` so default `pnpm test` skips it.

### 7.5 Manual QA checklist (`docs/qa/admin-ui.md`)
- macOS Sequoia + macOS Sonoma.
- Light + dark mode.
- Keychain enabled vs disabled.
- proxyd not running → banner.
- proxyd running but locked → unlock screen.
- Audit log file missing → graceful empty state.
- Audit rotation across boundaries.
- Long token labels / Rego policies (perf check on Monaco).

### 7.6 CI (GitHub Actions)
- `go test ./...` (existing).
- `pnpm test` (Vitest).
- `cargo test --manifest-path src-tauri/Cargo.toml`.
- `pnpm tauri build --debug` smoke-build on a macOS runner (no notarization in CI; release workflow separate).

---

## 8. Open questions deferred to implementation

- Exact `tauri-plugin-keychain` API — must verify the crate supports passphrase-protected items or whether to call `security-framework` directly.
- Whether to embed `proxyctl` as sidecar (current plan) or to refactor `internal/store` + `internal/crypto` into a thin shared Go library with both a CLI and a `cgo`-able interface. Sidecar is simpler; keep unless re-introducing CLI churn.
- Whether OPA WASM policy bundle ships with the app (~3 MB) or is loaded at first use. Lean toward bundling for offline use.

## 9. Decisions summary (from brainstorming)

| Q | Choice | Note |
|---|---|---|
| Scope | Full parity + viewer | All admin endpoints + audit tail |
| Instances | Single local | One socket only |
| Audit source | Persisted file tail | proxyd writes audit.log + rotation |
| Bootstrap | UI wizard | proxyctl sidecar invoked from Rust |
| Lifecycle | UI assumes proxyd running | No auto-start; banner with command |
| Rego editor | Monaco + OPA WASM live compile | Save gated on clean compile |
| Token mint | Modal + auto-copy + reveal toggle | Clipboard auto-cleared after 60s |
| Stack | Tauri 2 + React + shadcn/ui + Monaco | Rust shell, specta-typed IPC |
