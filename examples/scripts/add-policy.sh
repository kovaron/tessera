#!/usr/bin/env bash
# Upload a Rego policy via the admin socket.
# Usage: ./add-policy.sh <path-to-rego-file>
# Prints the new policy id.
set -euo pipefail

FILE="${1:?rego file path required}"
SOCK="${TESSERA_SOCK:-$HOME/.tessera/admin.sock}"

curl --unix-socket "$SOCK" -s -X POST http://localhost/v1/policies \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg src "$(cat "$FILE")" '{engine: "opa", source: $src}')"
echo
