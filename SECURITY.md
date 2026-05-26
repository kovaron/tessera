# Security Policy

## Supported Versions

Only the latest tagged release of the `tessera` daemon is actively supported with security fixes.

| Version | Supported |
|---------|-----------|
| Latest tag | Yes |
| Older tags | No — please upgrade |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **kovacs.aron@kovaron.com** with the subject line:

```
[security] tessera <brief description>
```

Please include:

- A minimal reproducer or step-by-step description
- Expected vs actual behavior
- Your assessment of the impact (e.g., credential exposure, privilege escalation, DoS)
- A suggested fix if you have one

### Response SLA

| Severity | Acknowledgement | Fix target |
|----------|-----------------|------------|
| Critical | 7 days (best-effort) | 30 days |
| High | 7 days (best-effort) | 60 days |
| Medium / Low | Best-effort | Next scheduled release |

These are targets, not guarantees. This is a solo-maintained project.

## Out of Scope

The following are **not** treated as security vulnerabilities:

- Attacks that require root access on the user's machine
- OS-level keychain or Secure Enclave bypass
- Physical access to the machine running Tessera
- Theoretical weaknesses without a practical exploit path

## Coordinated Disclosure

Please allow time to produce a fix before public disclosure. Fixed releases will include a CVE identifier if the vulnerability meets the threshold for assignment.

## Testing Guidelines

Please test only against your **own** keystore and credentials. Do not test against systems you do not own or have explicit permission to test.
