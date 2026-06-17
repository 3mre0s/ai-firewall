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
response before your client sees them. The provider only ever receives
placeholders.

## What it protects against

- **Accidental exfiltration of secrets to an AI provider.** The primary goal.
  Detected secrets in the request body are replaced with placeholders before
  the request is forwarded.
- **Leaking the token→secret mapping.** The vault that maps placeholders back to
  originals lives only in memory. It is never written to disk and is wiped on
  graceful shutdown.
- **The firewall's own API key leaking.** In explicit proxy mode,
  `FORWARD_API_KEY` is injected upstream and is never logged or written to disk.
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
| The in-memory vault | Trusted, never persisted | Wiped on shutdown. |
| The CA private key on disk | Sensitive | `0600`; encrypt with a passphrase. |
| The upstream AI provider | **Untrusted** | Sees only masked request bodies. |
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
- **Only configured AI hosts are intercepted.** Non-AI hosts pass through as a
  blind tunnel without TLS termination, so the firewall never sees their
  contents. This limits exposure but also means traffic to an unrecognised AI
  host is not scanned.

## Known limitations and trade-offs

These are acknowledged design trade-offs, not vulnerabilities. They are tracked
as roadmap work.

- **CA key derivation uses a single SHA-256 hash, not a password-based KDF.**
  When `AI_FIREWALL_CA_PASSPHRASE` is set, the AES-256-GCM key is derived from
  the passphrase with one SHA-256 pass rather than scrypt or Argon2id. If the
  encrypted key file is exfiltrated, this offers limited resistance to offline
  dictionary attacks. Mitigating factors: the file is `0600`, the passphrase is
  never written to disk, and leaf certificates are valid for only 24 hours.
  **Roadmap:** move to Argon2id.
- **No passphrase means the CA key is stored unencrypted.** If
  `AI_FIREWALL_CA_PASSPHRASE` is unset, the key is written as a plain `0600` PEM
  file and a prominent warning is logged. The cert directory gets an automatic
  `.gitignore` to prevent accidental commits, but you should set a passphrase.
- **Secrets split across SSE chunk boundaries may pass through unmasked.** In
  streaming responses each chunk is processed as it arrives. A secret whose
  bytes are split across two chunks may not be detected on the **response** path.
  Request bodies are always processed on a complete buffer and are unaffected.
- **Detection is best-effort and format-specific.** Patterns are tuned to real
  secret formats to limit false positives, which means a malformed or
  truncated-looking secret may not match. Test with realistic values.

## Reporting

If you believe any guarantee above is broken, see
[SECURITY.md](SECURITY.md) for how to report it privately.
