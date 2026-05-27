#!/usr/bin/env bash
# Upload a Rego policy via the admin socket.
# Usage: ./add-policy.sh <path-to-rego-file> [name] [upstream_id]
# Prints the new policy id.
set -euo pipefail

FILE="${1:?rego file path required}"
NAME="${2:-}"
UPSTREAM="${3:-}"
SOCK="${TESSERA_SOCK:-$HOME/.tessera/admin.sock}"

JQ_ARGS=(--arg src "$(cat "$FILE")" --arg name "$NAME")
JQ_FILTER='{name: $name, engine: "opa", source: $src}'
if [ -n "$UPSTREAM" ]; then
  JQ_ARGS+=(--arg up "$UPSTREAM")
  JQ_FILTER='{name: $name, upstream_id: $up, engine: "opa", source: $src}'
fi

curl --unix-socket "$SOCK" -s -X POST http://localhost/v1/policies \
  -H "Content-Type: application/json" \
  -d "$(jq -n "${JQ_ARGS[@]}" "$JQ_FILTER")"
echo
