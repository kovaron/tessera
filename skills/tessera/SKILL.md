---
name: tessera
description: Use Tessera (a local auth proxy) to call third-party APIs without ever touching the user's real API key. Invoke when the user has Tessera installed and the task needs an outbound call to an API like OpenAI / Anthropic / GitHub / Stripe.
---

# Tessera — outbound API calls without the real key

Tessera is a local-first auth proxy. Instead of reading `OPENAI_API_KEY` from the environment and sending it directly to the upstream, you go through Tessera. It validates a short-lived subtoken, evaluates a Rego policy, swaps in the real credential, and forwards the request. The real key never enters your process.

## When this skill applies

Use Tessera when **all** of the following hold:

1. The user has Tessera installed (`tessera` binary on `PATH` or at `~/projects/.../tessera`).
2. The user has bootstrapped the keystore (`~/.tessera/data.db` exists).
3. The daemon is running and unlocked (check via `tessera-cli status`).
4. The task requires you to call a third-party API on the user's behalf.

If any of these fail, fall back to the user's normal credentials and tell them why.

## Detect availability — first thing you do

```bash
tessera-cli status
# Expect: map[initialized:true locked:false version:dev]
```

If `tessera-cli` is missing → Tessera is not installed; don't use this skill.
If `locked:true` → ask the user to run `tessera-cli unlock` first.
If `initialized:false` → ask the user to run `tessera-cli bootstrap` first.

## Two modes — pick one

### Mode A: Path-based (no setup overhead)

Best when you control the HTTP client and can set a base URL.

1. Mint a token bound to the upstream:
   ```bash
   PXY_TOKEN=$(tessera-cli token mint \
     --label "agent:$(basename $PWD)" \
     --upstream openai \
     --policy <policy-id> \
     --ttl-seconds 3600)
   ```
2. Point your client at the path-based endpoint:
   ```python
   from openai import OpenAI
   client = OpenAI(
       api_key=PXY_TOKEN,
       base_url="http://127.0.0.1:8080/u/openai/v1",
   )
   ```
3. When done (or on error), revoke:
   ```bash
   tessera-cli token revoke <token-id>
   ```

### Mode B: Transparent forward proxy (no code changes)

Best when you can't change the client's base URL (e.g. SDKs that hardcode `api.openai.com`).

Wrap the whole command:

```bash
tessera-cli exec --upstream openai --policy <policy-id> -- python my_script.py
```

`exec` sets `HTTPS_PROXY`, `*_CA_BUNDLE`, and `PXY_TOKEN` on the child, mints a token before, revokes after. No code change inside `my_script.py` is required.

For this to work the user must have installed the Tessera root CA (`tessera-cli ca install` on macOS). If the CA isn't in the trust store, TLS handshakes from the child will fail with "unknown authority".

## Choosing the policy

Always pass `--policy`. Never mint a token without one.

To find an existing policy:

```bash
curl --unix-socket ~/.tessera/admin.sock -s http://localhost/v1/policies | jq '.[] | {id, name, upstream_id}'
```

Pick by `name` + matching `upstream_id` (or `null` for global). If the user hasn't created a suitable policy, **ask** — don't auto-create. Policies encode permissions, and you should not be choosing the scope on the user's behalf.

A policy bound to the wrong upstream will be rejected at mint time. A policy that's too permissive defeats the point of Tessera.

## TTL guidance

Pick the smallest TTL that fits the task:

| Task | Suggested TTL |
|---|---|
| One-shot API call | `60` (1 min) |
| Interactive session | `600` (10 min) |
| Long-running batch | `3600` (1 h) max |

Never request more than 1 hour. If the task takes longer, mint again.

## Error handling

| Symptom | Meaning | What to do |
|---|---|---|
| `connection refused` on `:8080` or `:8443` | Daemon not running | Tell the user to start `tessera` |
| 503 from any admin call | Daemon locked | Tell the user to run `tessera-cli unlock` |
| 403 from data plane | Policy denied the request | Read the audit log: `tail -1 ~/.tessera/audit.log`; report the `deny_reason` |
| 502 `unknown_host` | Hostname not registered to an upstream | Tell the user which hostname was attempted |
| 502 `upstream_mismatch` | Token bound to upstream A, request hit upstream B | Mint a new token bound to the correct upstream |
| `x509: signed by unknown authority` (transparent mode only) | CA not in trust store | Tell the user to run `tessera-cli ca install` |

Don't retry on 403 or 502 — they are policy / config decisions, not transient errors.

## What you must NEVER do

- **Don't read the user's real `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / etc.** If you see one in the env, it means Tessera isn't being used. That defeats the entire point.
- **Don't ask the user for their real key.** Ask them to register an upstream in Tessera instead.
- **Don't write the `pxy_*` token to a file the user didn't ask for.** Tokens are bearer secrets even though short-lived.
- **Don't try to bypass the proxy** by hitting `api.openai.com` directly in transparent mode — the policy is there for a reason.
- **Don't widen a policy** without asking. If you hit a deny, surface it to the user; let them decide whether to broaden the policy.

## Audit log

Every allow and every deny is written to `~/.tessera/audit.log` (JSONL). When something fails or you want to confirm a call landed:

```bash
tail -1 ~/.tessera/audit.log | jq .
```

Fields you care about: `decision` (allow/deny), `deny_reason`, `token_label`, `upstream_id`, `path`, `status`.

## Quick command reference

```bash
# Status & lifecycle
tessera-cli status
tessera-cli unlock
tessera-cli lock

# Upstreams
curl --unix-socket ~/.tessera/admin.sock -s http://localhost/v1/upstreams | jq

# Policies
curl --unix-socket ~/.tessera/admin.sock -s http://localhost/v1/policies | jq

# Tokens
tessera-cli token mint --label X --upstream Y --policy Z --ttl-seconds 600
tessera-cli token list
tessera-cli token revoke <id>

# Transparent mode (one-shot wrap)
tessera-cli ca export > ~/.tessera/ca.pem
tessera-cli ca install                                          # macOS, one-time
tessera-cli exec --upstream Y --policy Z -- <command> [args...]
```

## When to NOT use this skill

- The user's task doesn't involve calling an external API.
- The API in question is on a private network the user trusts (e.g. local Postgres).
- The user explicitly asked you to use a real key (rare; double-check).
- Tessera is not running and the task is time-sensitive — fall back to the user's normal flow and document what you did.
