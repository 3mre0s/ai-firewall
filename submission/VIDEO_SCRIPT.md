# Video script — target 2:40

## 0:00–0:20 — Problem

“Coding agents routinely receive stack traces, environment snippets, private paths, and credentials. Anonmyz is a local-first DLP gateway that replaces supported sensitive values before they leave this machine and restores them only in the local response.”

Show the repository and the Apache-2.0 license.

## 0:20–1:05 — Deterministic proof

Run:

```text
anonmyz demo --non-interactive
```

Point to the four detections, generated placeholders, the automatic assertion that original values are absent upstream, the split-SSE restoration check, and the final non-zero-on-failure result. State that the demo contacts no external service and uses the production proxy.

## 1:05–1:40 — Live Codex proof

Show the retained successful terminal record. Highlight:

- `Authentication: chatgpt_subscription`;
- upstream `https://chatgpt.com/backend-api/codex`;
- `status=200`;
- `detections=1` and `prevented=true`;
- `restored=3` and `response_blocked=false`;
- final `VERIFIED` line.

Say: “The payload was an intentionally fake GitHub PAT-shaped value. No real credential or authentication header is retained.”

## 1:40–2:10 — Fail closed and local only

Show the retained fail-closed output or run:

```text
go run ./scripts/verify-codex-fail-closed
```

Point to Codex exiting with an error and zero direct model fallback attempts. Show the loopback test line proving `127.0.0.1:<dynamic>` and not `0.0.0.0`.

## 2:10–2:30 — Explainability

Show the dashboard/audit evidence: secret type, placeholder, request ID, prevention, latency, upstream status, and restoration. Emphasize that raw values, bodies, hashes, OAuth bearer tokens, ChatGPT account IDs, and cookies are absent.

## 2:30–2:40 — Close

Show `go test ./...` passing and the Windows/Linux/macOS binaries with `checksums.txt`.

“Anonmyz turns the security claim into two executable proofs: deterministic local DLP and protected live Codex traffic.”

## Recording safety

- Use a clean terminal and large font.
- Never reveal `codex login status` details beyond the authentication mode.
- Never show environment variables, browser storage, cookies, or request headers.
- Use only the documented fake test value; mask it in retained audit exports.
- Keep the final upload under three minutes.
