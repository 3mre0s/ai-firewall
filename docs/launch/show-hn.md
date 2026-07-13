# Show HN draft

## Title candidates

1. Show HN: Local AI Firewall – strip secrets from prompts before they reach Claude/GPT
2. Show HN: A local proxy that masks API keys and PII in your AI prompts, no cloud involved
3. Show HN: I built a transparent MITM proxy that redacts secrets from LLM traffic

(Pick #1 — it names the concrete provider examples, which reads better on HN than a generic claim.)

## Post body

Local AI Firewall is a single Go binary that sits between your AI coding tools
(Claude Code, Copilot, Cursor, raw API calls) and the provider. It scans
outgoing requests, replaces anything that looks like a secret — API keys,
passwords, file paths with your username, emails, and a growing list of
validated national ID formats — with a short placeholder
(`[[OAI_KEY_A1B2C3D4]]`), and swaps the placeholders back in the response
before your client sees them.

Two ways to run it:
- Transparent mode: install a local CA once, point your system proxy at it,
  every tool is covered without touching its config.
- Explicit mode: point a tool's base URL at the firewall directly.

Why local-only instead of a hosted gateway: the entire point of redacting
secrets is defeated if the redaction step itself runs on someone else's
server. The token-to-secret mapping lives in an in-memory vault, is never
written to disk, and is wiped on shutdown. The metrics dashboard refuses any
non-loopback request.

It's AGPL-3.0-or-later, single static binary (Linux/macOS/Windows,
amd64/arm64), available via Homebrew/Scoop or as a direct download.

GitHub: https://github.com/3mre0s/ai-firewall

Feedback welcome, especially on pattern coverage (what's still leaking
through) and the MITM trust model.

## First comment (maker comment, post immediately after submitting)

A few decisions worth explaining:

- **Why AGPL and not MIT/Apache**: this is the kind of tool where someone
  could wrap it in a hosted "secure AI gateway" SaaS and undermine the whole
  "your secrets never leave your machine" premise. AGPL means a modified,
  network-deployed version still has to share source.
- **Why MITM instead of just an env-var proxy**: most people don't want to
  reconfigure every tool's base URL one by one. The CA-based transparent mode
  means zero per-tool setup, at the cost of needing to trust a locally
  generated CA — the private key is AES-256-GCM encrypted at rest if you set
  a passphrase, and the cert directory is auto-gitignored.
- **Known limitations**: pattern-based detection means it can both miss
  novel secret formats and occasionally mask things that aren't secrets.
  Full threat model is in THREAT_MODEL.md in the repo.

Happy to answer questions about the masking/vault implementation or the CA
install flow.
