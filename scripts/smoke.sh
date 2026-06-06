#!/usr/bin/env bash
# End-to-end smoke test for the transparent forward-proxy mode.
#
# Requirements:
#   - `tessera` daemon already running with --forward-addr 127.0.0.1:8443
#   - `tessera-cli unlock` already done (so the CA is generated)
#   - `jq`, `curl` on PATH
#   - HTTPBIN_KEY env var optional (any non-empty string; the proxy injects it)
#
# What it does:
#   1. registers httpbin.org as an upstream (UPSERT — safe to re-run)
#   2. ensures an "allow-all" policy bound to httpbin exists
#   3. mints a short-lived token, hits httpbin via --proxy, verifies the inject
#   4. runs the same call wrapped in `tessera-cli exec`
#   5. negative path: unknown host → 502
#   6. negative path: upstream mismatch → 403
#   7. revokes the smoke-test token at the end
#
# Exit code: 0 on full pass, non-zero on first failure.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/tessera-cli"
SOCK="${TESSERA_SOCK:-$HOME/.tessera/admin.sock}"
CA="${TESSERA_CA:-$HOME/.tessera/ca.pem}"
PROXY="${TESSERA_PROXY:-127.0.0.1:8443}"

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
step()  { printf '\033[36m== %s ==\033[0m\n' "$*"; }

fail() { red "FAIL: $*"; exit 1; }

# ---------- preflight ----------
step "preflight"

[[ -x "$CLI" ]]   || fail "tessera-cli not built. Run: make build"
[[ -S "$SOCK" ]]  || fail "admin socket not found at $SOCK. Is the daemon running?"
command -v jq    >/dev/null || fail "jq is required"
command -v curl  >/dev/null || fail "curl is required"

status=$(curl --unix-socket "$SOCK" -s http://localhost/v1/status)
locked=$(jq -r .locked  <<<"$status")
inited=$(jq -r .initialized <<<"$status")
[[ "$inited" == "true" ]] || fail "daemon not initialized (run: tessera-cli bootstrap)"
[[ "$locked" == "false" ]] || fail "daemon is locked (run: tessera-cli unlock)"

# Ensure CA is exported on disk; the exec test needs it.
if [[ ! -f "$CA" ]]; then
  step "exporting CA to $CA"
  mkdir -p "$(dirname "$CA")"
  "$CLI" ca export > "$CA" || fail "failed to export CA"
fi

# ---------- upstream ----------
step "registering upstream 'httpbin' (idempotent UPSERT)"
curl --unix-socket "$SOCK" -s -X POST http://localhost/v1/upstreams \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "httpbin",
    "base_url": "https://httpbin.org",
    "inject": { "type": "bearer", "secret_ref": "env://HTTPBIN_KEY" },
    "hostnames": ["httpbin.org"]
  }' >/dev/null

# ---------- policy (find-or-create) ----------
step "ensuring 'smoke-allow-all' policy on httpbin"
POL=$(curl --unix-socket "$SOCK" -s http://localhost/v1/policies \
  | jq -r '.[] | select(.name=="smoke-allow-all" and .upstream_id=="httpbin") | .id' \
  | head -n1)

if [[ -z "$POL" ]]; then
  tmp=$(mktemp -t tessera-smoke.rego)
  cat > "$tmp" <<'EOF'
package proxy.authz
default allow := true
EOF
  POL=$("$CLI" policy add --engine opa --file "$tmp" --name smoke-allow-all --upstream httpbin)
  rm -f "$tmp"
  [[ -n "$POL" ]] || fail "policy add did not return an id"
fi
echo "policy id: $POL"

# ---------- mint ----------
step "minting smoke token (120s TTL)"
MINT=$(curl --unix-socket "$SOCK" -s -X POST http://localhost/v1/tokens \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg p "$POL" '{label:"smoke", upstream_id:"httpbin", policy_id:$p, ttl_seconds:120}')")
TOK_ID=$(jq -r .id     <<<"$MINT")
TOK=$(   jq -r .secret <<<"$MINT")
[[ -n "$TOK_ID" && -n "$TOK" ]] || fail "mint did not return id+secret: $MINT"

trap 'curl --unix-socket "$SOCK" -s -X DELETE "http://localhost/v1/tokens/$TOK_ID" >/dev/null || true' EXIT

# ---------- direct forward-proxy call ----------
step "1) direct call via --proxy http://$PROXY"
body=$(curl -sf --proxy "http://$PROXY" --cacert "$CA" \
            -H "Authorization: Bearer $TOK" \
            https://httpbin.org/bearer) \
  || fail "direct call failed"

echo "$body" | jq .
authn=$(jq -r .authenticated <<<"$body")
[[ "$authn" == "true" ]] || fail "expected authenticated=true, got: $body"
green "  PASS — proxy injected real bearer token, httpbin accepted it"

# ---------- exec wrapper ----------
step "2) same call via tessera-cli exec"
out=$("$CLI" exec --upstream httpbin --policy "$POL" --ttl 120 -- \
       curl -sf --cacert "$CA" https://httpbin.org/bearer)
echo "$out" | jq .
authn=$(jq -r .authenticated <<<"$out")
[[ "$authn" == "true" ]] || fail "exec wrapper request rejected: $out"
green "  PASS — exec wrapper minted token, ran child, auto-revoked"

# ---------- negative: unknown host ----------
step "3) unknown host → expect 502"
code=$(curl -s -o /dev/null -w '%{http_code}' \
       --proxy "http://$PROXY" --cacert "$CA" \
       -H "Authorization: Bearer $TOK" \
       https://example.invalid/ || true)
[[ "$code" == "502" ]] || fail "expected 502 for unknown host, got $code"
green "  PASS — unknown host denied"

# ---------- negative: upstream mismatch ----------
step "4) upstream mismatch → expect 403"
# Register a second upstream owning a different hostname.
curl --unix-socket "$SOCK" -s -X POST http://localhost/v1/upstreams \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "ghclone",
    "base_url": "https://httpbin.org",
    "inject": { "type": "bearer", "secret_ref": "env://HTTPBIN_KEY" },
    "hostnames": ["api.example.test"]
  }' >/dev/null

code=$(curl -s -o /dev/null -w '%{http_code}' \
       --proxy "http://$PROXY" --cacert "$CA" \
       --resolve "api.example.test:443:127.0.0.1" \
       -H "Authorization: Bearer $TOK" \
       https://api.example.test/get || true)
[[ "$code" == "403" ]] || fail "expected 403 for upstream mismatch, got $code"
green "  PASS — upstream mismatch denied"

# ---------- done ----------
green
green "ALL SMOKE TESTS PASSED"
green "  audit log: tail -f ~/.tessera/audit.log"
