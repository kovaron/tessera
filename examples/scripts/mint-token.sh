#!/usr/bin/env bash
# Mint a subtoken via the admin socket.
# Usage: ./mint-token.sh <label> <upstream_id> <policy_id> [ttl_seconds]
set -euo pipefail

LABEL="${1:?label required}"
UP="${2:?upstream required}"
POL="${3:?policy required}"
TTL="${4:-3600}"
SOCK="${TESSERA_SOCK:-$HOME/.tessera/admin.sock}"

curl --unix-socket "$SOCK" -s -X POST http://localhost/v1/tokens \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg l "$LABEL" --arg u "$UP" --arg p "$POL" --argjson t "$TTL" \
    '{label: $l, upstream_id: $u, policy_id: $p, ttl_seconds: $t}')"
echo
