# Security Policy

Local AI Firewall is a security tool, so we take reports about its own
weaknesses seriously. This document explains what is in scope, how to report
an issue, and what to expect in return.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, use GitHub's **Private Vulnerability Reporting**:

1. Go to the repository on GitHub.
2. Click the **Security** tab.
3. Click **Report a vulnerability**.

This keeps the report private until a fix is ready. **Do not open a public issue** — public disclosure before a patch is available puts all users at risk.

When reporting, please include:

- a description of the issue and the impact you believe it has,
- the version or commit you tested against,
- step-by-step reproduction instructions, and
- any proof-of-concept code or sample payloads, if applicable.

You will receive an acknowledgement of your report. We aim to respond with an
initial assessment, agree on a disclosure timeline with you, and credit you in
the release notes if you wish (and if the report leads to a fix).

We ask that you give us reasonable time to investigate and ship a fix before
any public disclosure.

## Scope

In scope — issues in this repository that could:

- cause a secret to be sent upstream **unmasked** when it should have been caught,
- expose the in-memory vault contents to the network or to the upstream provider,
- leak the CA private key, or weaken its at-rest protection,
- allow a non-loopback client to reach `/metrics` or `/dashboard`,
- allow the MITM proxy to be abused to intercept traffic it should not, or
- any other flaw that breaks the guarantees described in
  [THREAT_MODEL.md](THREAT_MODEL.md).

Out of scope:

- the **known limitations** already documented in
  [THREAT_MODEL.md](THREAT_MODEL.md) (e.g. the SHA-256 key-derivation trade-off,
  or secrets split across SSE chunk boundaries) — these are acknowledged, and
  hardening them is tracked as ordinary roadmap work rather than as
  vulnerabilities,
- attacks that require an adversary already running code as your user on the
  same machine (this tool does not claim to defend against local malware),
- detection-coverage gaps (a pattern that does not yet exist for some secret
  format) — these are welcome as **feature requests**, not security reports,
  unless the gap silently undermines a documented guarantee.

## Supported versions

Security fixes target the latest stable release. There is no long-term-support
branch yet; please track the latest release.

## Disclosure philosophy

We prefer coordinated disclosure. Once a fix is available, we will publish a
security advisory describing the issue, the affected versions, and the fix,
crediting the reporter unless they prefer to remain anonymous.
