# Threat Model

This document states plainly what Local AI Firewall protects against, what it
does **not** protect against, and the known trade-offs in its current design.
It is deliberately honest about limitations — knowing the edges of a security
tool is part of using it safely.

## What this tool is for

**The core problem:** when you use an AI coding assistant or chat tool, your
prompts are sent to a cloud provider you don't control. Those prompts often
contain secrets you didn't mean to share — an API key pasted into a stack
trace, a database password in a config snippet, a file path that reveals your
username, an email address.

**What the firewall does:** it sits between your AI tool and the provider,
detects secrets in the **request body**, replaces each with a placeholder
before the request leaves your machine, and restores the originals in the
response before your client sees them. For values matched by the configured
patterns, the provider receives placeholders instead of the original values.

## What it protects against

- **Accidental exfiltration of secrets to an AI provider.** The primary goal.
  Detected secrets in the request body are replaced with placeholders before
  the request is forwarded.
- **Leaking the token→secret mapping.** Each request gets an isolated vault that
  lives only in memory, is never persisted, and is wiped after its response.
- **The firewall's own API key leaking.** In explicit proxy mode,
  `FORWARD_API_KEY` is injected upstream and is never logged or written to disk.
- **Accidental plaintext transport to a remote upstream.** Remote upstream URLs
  must use HTTPS. Plain HTTP is accepted only for `localhost` and loopback IPs;
  URL userinfo, query parameters, and fragments are rejected.
- **Internal state leaking to the network.** The `/metrics` and `/dashboard`
  endpoints are bound to loopback (`127.0.0.1`, `::1`). Any non-loopback request
  receives `403 Forbidden`, so vault occupancy and mask counts cannot leak to
  the provider or the wider network.

## What it does NOT protect against

Be clear-eyed about these. The firewall is not a sandbox.

- **Local malware or another user on the machine.** If an attacker is already
  running code as your user, they can read process memory, the vault, and the
  CA key file. This tool assumes the local machine and user account are trusted.
- **Secrets it doesn't have a pattern for.** Detection is pattern-based.
  A secret in a format with no matching pattern will pass through unmasked.
  Coverage is a moving target; treat the pattern list as best-effort, not
  exhaustive.
- **Prompt injection or malicious model output.** The firewall does not inspect
  prompts for injection attacks, nor does it sanitise model responses for
  anything other than restoring its own placeholders.
- **Secrets you send outside the proxied path.** Only traffic that actually goes
  through the firewall is scanned. A tool that bypasses the proxy, or a host the
  MITM proxy is not configured to intercept, is not protected.
- **The auth header itself.** In transparent (MITM) mode the firewall
  deliberately does **not** mask the `x-api-key` / `Authorization` header — that
  credential must reach the provider for authentication to work. Only the
  request body is scanned.

## Trust boundaries

| Boundary | Trusted? | Notes |
|---|---|---|
| Your machine / user account | Trusted | The whole design assumes this. |
| Per-request in-memory vault | Trusted, never persisted | Isolated and wiped after each response. |
| The CA private key on disk | Sensitive | `0600`; encrypt with a passphrase. |
| The upstream AI provider | **Untrusted** | Receives proxied bodies with recognised values masked; detection is best-effort. |
| The network between you and the provider | Untrusted | Standard TLS to the provider. |
| `/metrics`, `/dashboard` | Loopback only | `403` for any non-loopback client. |

## MITM mode specifics

Transparent mode works by terminating TLS locally. On first run the firewall
generates a self-signed ECDSA P-256 CA (`CN=AI Firewall CA`). After you install
it into your system trust store (`ai-firewall install-ca`), the firewall signs
short-lived (24-hour) leaf certificates per host so it can read and mask the
request body before re-encrypting to the real provider.

Implications you should understand:

- **The CA can sign certificates for any host on your machine while installed.**
  That is the whole point of a locally trusted CA, and also why protecting the
  CA private key matters. Remove it with `ai-firewall uninstall-ca` when you're
  done.
- **Only configured AI hosts are intercepted.** CONNECT requests for other
  hosts are rejected. Traffic that does not use the proxy remains outside the
  firewall and is not scanned.

## Known limitations and trade-offs

These are acknowledged design trade-offs, not vulnerabilities. They are tracked
as roadmap work.

- **Passphrase strength still matters.** New encrypted CA keys use a random
  16-byte salt and PBKDF2-HMAC-SHA-256 with 210,000 iterations before
  AES-256-GCM encryption. Versioned KDF metadata is stored in the PEM headers.
  Legacy files derived with a single SHA-256 pass remain readable for upgrade
  compatibility, so installations with legacy keys should rotate them. A weak
  passphrase can still be attacked offline if `ca.key` is exfiltrated.
- **No passphrase means the CA key is stored unencrypted.** If
  `AI_FIREWALL_CA_PASSPHRASE` is unset, the key is written as a plain `0600` PEM
  file and a prominent warning is logged. The cert directory gets an automatic
  `.gitignore` to prevent accidental commits, but you should set a passphrase.
- **Streaming output cannot recall bytes already delivered.** A bounded 64 KiB
  raw look-behind detects supported credential patterns split across network
  reads and suppresses the output that completes a match. Earlier bytes may
  already have been flushed before a later malicious value is recognizable;
  terminating the stream cannot recall those bytes. Request bodies are always
  processed on a complete buffer and are unaffected.
- **Non-streaming responses are bounded, not streamed.** Explicit-proxy and MITM
  paths buffer standard responses for leak inspection and cap them at 64 MiB.
  Oversized bodies are suppressed rather than restored or forwarded.
- **Detection is best-effort and format-specific.** Patterns are tuned to real
  secret formats to limit false positives, which means a malformed or
  truncated-looking secret may not match. Test with realistic values.

## Reporting

If you believe any guarantee above is broken, see
[SECURITY.md](SECURITY.md) for how to report it privately.
