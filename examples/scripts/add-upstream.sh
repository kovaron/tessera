#!/usr/bin/env bash
# Add an upstream via the admin socket.
# Usage: ./add-upstream.sh <id> <base_url> <secret_ref>
# Example: ./add-upstream.sh github https://api.github.com env://GH_TOKEN
set -euo pipefail

ID="${1:?id required}"
URL="${2:?base url required}"
REF="${3:?secret ref required}"
SOCK="${TESSERA_SOCK:-$HOME/.tessera/admin.sock}"

curl --unix-socket "$SOCK" -s -X POST http://localhost/v1/upstreams \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg id "$ID" --arg url "$URL" --arg ref "$REF" \
    '{id: $id, base_url: $url, inject: {type: "bearer", secret_ref: $ref}}')"
echo
