# Tessera examples

Sample Rego policies and admin-socket helper scripts.

## Policies (`policies/`)

| File | Use case |
|---|---|
| [`read-only.rego`](policies/read-only.rego) | Allow only safe (GET, HEAD) requests. |
| [`github-issues-read.rego`](policies/github-issues-read.rego) | Read-only access to one repo's issues endpoint. |
| [`openai-chat-only.rego`](policies/openai-chat-only.rego) | Restrict an OpenAI token to chat completions only. |

All policies use Rego v1 syntax (`allow if { ... }` not `allow { ... }`).

## Scripts (`scripts/`)

Bash + `jq` helpers that drive the admin unix socket directly. The Tessera daemon must be running and unlocked.

```bash
chmod +x scripts/*.sh

# 1. Add an upstream
./scripts/add-upstream.sh openai https://api.openai.com env://OPENAI_API_KEY

# 2. Add a policy and capture its id
POLICY_ID=$(./scripts/add-policy.sh policies/openai-chat-only.rego | jq -r .id)

# 3. Mint a subtoken bound to that upstream + policy, 1 hour TTL
./scripts/mint-token.sh agent-1 openai "$POLICY_ID" 3600
```

Override the socket path with `TESSERA_SOCK=/path/to/admin.sock`.

## Hitting the data plane

Once you have a subtoken (the `secret` field from `mint-token.sh`):

```bash
SUBTOKEN=pxy_...

curl -H "Authorization: Bearer $SUBTOKEN" \
  http://127.0.0.1:8080/u/openai/v1/chat/completions \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}'
```

Tessera validates the subtoken, evaluates the policy, swaps the bearer for the real `OPENAI_API_KEY` resolved from your secret provider, and forwards.
