# Stop Giving AI Agents Your Real API Tokens

*Draft LinkedIn article — ~1100 words, designed for one read-through, no jargon dump.*

---

I have one GitHub token on my laptop.

It can do everything — open repos, close issues, push branches, dismiss reviews, delete tags. GitHub does not let me create a second, narrower token that can only `GET /repos/acme/widgets/issues`. It is read/write on everything, or nothing.

Then I started letting AI agents use that token.

You can see where this is going.

The first time I watched an agent run, it did exactly what I asked. The second time, it tried to "clean up some stale issues" I had not asked it to touch. The third time, I started typing a Slack message to a colleague and stopped mid-sentence, because the honest version of it was: *I gave my agent a key that opens every door in the house, and I am surprised it walked into rooms.*

The agent did nothing malicious. The system was malicious — toward me — by giving me only one tool: a master key.

## The problem is not the agent. It is the credential.

The conversation around AI safety likes to focus on the model: alignment, refusal, prompts. That is fine, but it is not where the leverage is for most people shipping today. The leverage is the credential.

If you give an AI agent a token that can do ten things, you must trust the agent to only do one of them. If you give an AI agent a token that can only do one thing, the trust question collapses. The blast radius is whatever the token allows. Full stop.

So why does almost nobody do this? Because most third-party APIs do not let you mint narrow tokens. They give you one personal access token, sometimes one machine token, occasionally OAuth scopes that are still way too broad. The granularity you want — *this agent, this endpoint, this repository, this method, for 24 hours* — does not exist in their auth model. You can't build the gate at their door. So you build the gate at your door.

That is what I am building. It is called `ai-secrets-manager`, it is in Go, and it is going to be open source.

## How it works, in one paragraph

The proxy is a small HTTP server that sits between your agents and the outside world. Agents do not get the real GitHub / Linear / Stripe / whatever token. They get an opaque random string from the proxy — `pxy_xxxxxxx` — that is bound to a policy: *GET only, on `/repos/acme/widgets/issues*`, expires in 24 hours, agent label `triage-bot`*. When the agent makes a request, the proxy looks up the token, evaluates the policy against the request, strips the agent's bearer token off, fetches the real upstream credential from 1Password (or Doppler, or Vault) at request time, injects it, and forwards. The real token never leaves the proxy host. The agent never sees it. If the agent goes rogue, you `proxyctl token revoke` and it is dead in milliseconds. If the laptop is stolen, the database does not contain the real upstream token — only a reference to a 1Password item, plus a sealed policy blob encrypted under a key that is only in memory while you have the proxy unlocked.

That is the whole pitch. The rest is engineering.

## The interesting design decisions

A few choices worth surfacing, because I think they generalize beyond this project.

**Opaque tokens, not JWTs.** Self-contained signed tokens are seductive: no DB hit, scope in claims, very web-scale. They are also a nightmare for revocation. The whole point of this proxy is that an operator should be able to kill an agent's access in one second — not "wait for the JWT to expire." Opaque random tokens with a DB lookup gives you instant revoke at the cost of a single SQLite read per request. SQLite reads are not the bottleneck in any system that calls a third-party API. Pay the cost; keep control.

**Encryption is app-layer, not at the database file.** I considered SQLCipher — encrypt the whole `.db`. It would have meant a cgo build and a worse open-source distribution story. Instead, the sensitive columns (policy text, plus the wrapped data-encryption key) are sealed with XChaCha20-Poly1305, and the master key is derived from a passphrase via Argon2id. The proxy starts locked. You unlock it with `proxyctl unlock`. While locked, every agent request returns 503. The threat model assumes someone might steal the DB file; it does not assume they will steal your live process memory.

**Pluggable everything.** `SecretProvider` is an interface — 1Password CLI, Doppler CLI, Vault HTTP, env. `KeyProvider` is an interface — passphrase today, cloud KMS when this runs as a service. `Store` is an interface — SQLite today, Postgres later. None of this is over-engineered abstraction theater. Each interface exists because *I know I am going to swap it.* Local-first becomes service-mode by changing one provider, not by rewriting the data model.

**Real policy engine.** The first instinct is "method + path glob." That covers 80% of cases and then collapses the first time you need "only when the JSON body says `state=open`" or "only on weekdays" or "deny if path matches a personally identifiable pattern." I am shipping Open Policy Agent's Rego in-process. Heavier than a glob matcher; orders of magnitude more expressive. I do not want to write a worse OPA.

**Attenuation, with an honest caveat.** A parent token can mint a narrower child token for a sub-agent. The proxy enforces that the child's TTL is at most the parent's remaining TTL, and that the child's policy declares itself a subset of the parent's. The subset claim is *admin-asserted*, not proven. Provable subset is a research problem. I picked usefulness now over correctness later, and I documented exactly where the trust boundary sits.

## Why open source

Because every team running AI agents has the same problem, and the answer should not be "ask your security team if you can have a real solution." The answer should be: clone the repo, run the binary, give your agents real-shaped tokens.

If you have ever felt the small drop in your stomach when you watched an agent run with your personal token — this is for you.

I will share the repo when it is ready to be used in anger. Until then: think about your tokens. Not the agent's behavior. The credential it holds.

That is where the trust really lives.

---

*If this resonates, follow along — I will be posting design notes as the project comes together.*
