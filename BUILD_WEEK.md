# Anonmyz — OpenAI Build Week Submission

## Problem

Coding agents routinely receive stack traces, environment snippets, repository context, credentials, and private local paths. A developer can accidentally include sensitive values in a prompt long before a cloud provider's controls can help. Most DLP gateways add another cloud processor, require a broad deployment, or do not restore redacted context locally for an agent workflow.

## Solution

Anonmyz is a local-first AI security and DLP gateway. It detects supported sensitive-value formats in a complete request body, replaces them with request-scoped placeholders, forwards only the sanitized body, and restores placeholders from the model response on the developer's machine. It is a single Go binary with no Anonmyz service, account, telemetry, database, or runtime dependency.

The Build Week experience centers on one deterministic command:

```bash
anonmyz demo --non-interactive
```

It requires no API key, starts a local mock model and the real proxy on dynamic ports, sends four unmistakably fake values through the production pipeline, proves originals are absent upstream and placeholders are present, splits a placeholder across SSE network writes, verifies local restoration, cleans up both listeners, and fails closed with a non-zero exit code.

## Target users

- Developers using Codex or OpenAI-compatible coding agents.
- Security and platform teams evaluating local controls for AI-assisted development.
- Teams that cannot add another hosted data processor to their prompt path.
- Open-source maintainers who want a judgeable, auditable, single-binary safety layer.

## What existed before the submission period

The repository already contained:

- Go secret patterns, masking engine, in-memory vault, and response unmasking;
- explicit OpenAI-compatible/Anthropic/Gemini proxy support and optional allow-listed MITM mode;
- provider adapters, metrics, a localhost dashboard, tests, IDE integrations, packaging, and release automation;
- request-scoped vault isolation and fail-closed behavior when the vault is full.

That foundation is preserved. Existing `ai-firewall` commands, environment variables, adapters, MITM flow, VS Code/JetBrains integrations, package manifests, and compatibility release archives continue to work.

## Meaningful features added during the submission period

1. Production-path, key-free `anonmyz demo` with upstream assertions, real SSE, dynamic ports, clean shutdown, and CI exit codes.
2. `anonmyz codex` Safe Session with Codex detection, temporary one-run provider overrides, dynamic loopback proxy, argument forwarding, signal/exit-code handling, dry run, and credential diagnostics.
3. Explainable `/audit` metadata integrated into the existing dashboard: detected type, placeholder, prevention result, local request ID, timestamp, processing latency, status, and stream restoration.
4. A bounded 200-request, memory-only audit ring that never stores bodies, raw values, or secret hashes.
5. Streaming restoration for a placeholder split at every byte boundary, including between the opening brackets.
6. A production fix preventing a specific token placeholder from being wrapped again by a later generic assignment pattern.
7. Tests for the full demo, upstream proof, every placeholder boundary, concurrent requests, malformed streams, cancellation, dynamic/occupied ports, CLI exit codes, retention, logs/audit secrecy, and existing proxy behavior.
8. Judge documentation, dual-name build/release path, Devpost copy, and timed demo script.
9. A fail-closed Codex transport probe that kills the real loopback Anonmyz proxy during an in-flight request, traps direct egress, and requires Codex to exit with an error and zero direct model fallback attempts.

## Technical implementation

The request path remains one coherent pipeline:

```text
client POST
  -> full-body pattern scan
  -> request-scoped vault stores placeholder -> original
  -> sanitized request forwarded by the selected provider adapter
  -> standard or bounded-buffer SSE response processing
  -> known placeholders restored locally
  -> vault reset
```

`demo` runs `proxy.Server` and `proxy.StreamProcessor`; it does not call a demo-only redactor. The mock upstream captures exactly what the production proxy sends and echoes its received placeholders. The demo process compares captured bytes against the four original fake values and exits non-zero if any is present.

Safe Session was designed against the installed `codex-cli 0.137.0` help, the current official Codex manual, and the official Codex source. Codex supports temporary `-c` overrides, `openai_base_url`, custom `model_providers`, `wire_api = "responses"`, provider `env_key`, and both ChatGPT and API-key authentication. Anonmyz uses those supported surfaces and never writes the user's global config or reads stored credentials.

Codex receives a temporary custom Responses provider whose base URL is the local proxy. An exported `OPENAI_API_KEY` is referenced through `env_key`; a stored Codex API-key or ChatGPT login is preserved through `requires_openai_auth`. Codex continues to manage its own authentication, while Anonmyz passes the required authorization and ChatGPT account headers through and masks only request bodies. The protected provider has WebSocket support disabled, and request compression is disabled for the child session, so traffic stays on the inspected HTTP path.

Current-CLI revalidation used `codex-cli 0.145.0-alpha.27`. Safe Session now applies a temporary `features.apps=false` override to the protected child, rejects forwarded attempts to re-enable Apps, and leaves the user's global configuration and `CODEX_HOME` unchanged. The fail-closed probe requires a literal loopback model URL and fails on any request reaching its external-egress trap; no OpenAI or `chatgpt.com` hostname is allowlisted.

## Privacy and threat model

Anonmyz protects against accidental disclosure of values matching its configured patterns in request bodies that actually traverse the proxy. It is not a sandbox, malware defense, semantic classifier, or guarantee that every possible secret format will be recognized.

- Raw values live only in the request-scoped in-memory vault and are reset after the exchange.
- Audit data is local, bounded, and metadata-only.
- Listeners bind to `127.0.0.1`; `/metrics`, `/audit`, and `/dashboard` reject non-loopback callers.
- Request bodies are fully buffered and limited to 32 MiB before masking.
- Vault exhaustion blocks the request instead of forwarding partially masked data.
- Compressed request and upstream bodies are rejected because scanning them as plaintext would be unsafe.
- SSE buffering is bounded. A raw secret detected in an upstream chunk is suppressed and terminates the stream, but bytes already flushed before a later malicious chunk cannot be recalled.
- Provider authentication headers necessarily reach the configured provider; body DLP does not redact the credential used to authenticate that request.
- Traffic that bypasses the configured explicit or MITM proxy is not protected.

## How Codex and GPT-5.6 accelerated development

Codex with GPT-5.6 inspected the repository structure, dirty worktree, architecture, tests, integrations, and git history; verified the installed Codex CLI and current official configuration manual; implemented scoped changes; ran the demo and verification matrix; and reviewed the security-sensitive diff. Its fast feedback surfaced the nested-placeholder edge case and the single-opening-bracket streaming boundary during end-to-end and exhaustive tests.

## Key human product and engineering decisions

- Keep the product local-first and single-binary instead of adding a hosted control plane or new runtime.
- Reuse the production proxy in the demo so the central claim is executable evidence.
- Make visible prevention proof—not a generic dashboard—the core two-minute story.
- Keep audit metadata useful but exclude raw values and even hashes, which can enable guessing attacks.
- Preserve the old binary name and integrations while presenting the new Anonmyz product name.
- Support Codex routing through temporary documented configuration without reading or rewriting credentials.
- Use only an unmistakably fake secret-shaped value in the live ChatGPT-subscription smoke test, retain metadata-only evidence, and separately prove that proxy loss cannot trigger direct model fallback.

## Exact judge testing steps

From a clone with Go 1.22+:

```bash
go build -trimpath -o anonmyz .
./anonmyz demo --non-interactive
./anonmyz demo --non-interactive
./anonmyz codex --dry-run -- --no-alt-screen
go test ./...
go run ./scripts/verify-codex-fail-closed
```

Windows PowerShell:

```powershell
go build -trimpath -o anonmyz.exe .
.\anonmyz.exe demo --non-interactive
.\anonmyz.exe demo --non-interactive
.\anonmyz.exe codex --dry-run -- --no-alt-screen
go test ./...
go run .\scripts\verify-codex-fail-closed
```

The second demo run verifies clean listener shutdown. Dry run is informative without credentials; it prints a blocked credential action if needed and never launches Codex or edits global config.

Optional live test with your existing ChatGPT login:

```bash
codex login
./anonmyz codex --dry-run -- --no-alt-screen
./anonmyz codex -- --no-alt-screen
```

Optional API-key alternative:

```bash
export OPENAI_API_KEY="value-from-your-secret-manager"
./anonmyz codex --dry-run -- --no-alt-screen
./anonmyz codex -- --no-alt-screen
```

Open the dynamic dashboard URL printed by Safe Session and send a prompt containing only a clearly fake pattern. Exit Codex to verify that the proxy stops and the child exit code is preserved.

The retained live test used ChatGPT subscription authentication and a fake GitHub PAT-shaped value. It completed with upstream `200`, one prevented detection, safe local restoration, and no response block. The raw fake value and authentication headers are excluded from retained audit evidence.

## Known limitations

- Detection is pattern-based and best-effort; unknown formats and semantically sensitive prose can pass through.
- Codex Safe Session supports ChatGPT and API-key authentication. The ChatGPT path was exercised with a real subscription session and an intentionally fake secret-shaped payload; no real secret was used.
- Only request bodies are masked. Required provider authentication headers pass through.
- The proxy must actually be configured; bypass traffic is invisible to Anonmyz.
- The audit ring is process-local and disappears on exit by design.
- Optional MITM mode expands the local trust boundary by installing a CA; demo and Safe Session do not use or install it.
- Windows arm64 is not in the current release matrix.

## Suggested 2.5-minute demo sequence

**0:00–0:20 — Problem.** Show a coding-agent request containing the four fake categories. Explain that accidental context can leave the machine before a developer notices.

**0:20–0:55 — One command.** Run `anonmyz demo --non-interactive`. Point to `[DETECTED]`, safe placeholder IDs, the upstream absence assertion, split-stream restoration, and final count.

**0:55–1:20 — Evidence, not animation.** Explain that two real loopback servers ran and the mock asserted on bytes received through `proxy.Server`. Run the command a second time to show deterministic cleanup.

**1:20–1:50 — Codex workflow.** Run `anonmyz codex --dry-run -- --no-alt-screen`. Highlight the detected executable, dynamic local URL, unchanged global config, credential state, and honest live-credential validation boundary.

**1:50–2:10 — Live proof.** Show the retained successful Codex terminal/audit evidence: subscription authentication, `status=200`, one prevented GitHub PAT-shaped test value, safe restoration, and `response_blocked=false`.

**2:10–2:25 — Fail closed.** Show the fail-closed probe ending with Codex error, zero direct model fallback attempts, and a listener bound to `127.0.0.1` rather than `0.0.0.0`.

**2:25–2:40 — Close.** Show `go test ./...` passing. Summarize: a single local binary, two executable proofs, no Anonmyz cloud processor, and compatibility with the project's existing integrations.

## Proposed English Devpost description

**Anonmyz — keep coding-agent secrets on your machine**

Anonmyz is a local-first AI security and DLP gateway for coding agents. It detects supported API keys, tokens, passwords, private paths, and PII in request bodies, replaces them with request-scoped placeholders, forwards only sanitized context to the configured model provider, and restores known placeholders locally in standard or streaming responses.

The submission's centerpiece is `anonmyz demo`: a deterministic, no-key proof that starts a real Anonmyz proxy and local mock model, sends four clearly fake sensitive values through the production pipeline, programmatically proves the originals never reached the mock upstream, proves placeholders did, splits a placeholder across streamed network writes, verifies local restoration, and fails non-zero if any security invariant breaks.

`anonmyz codex` creates a protected Codex session for ChatGPT or API-key authentication using temporary documented Codex configuration overrides, without modifying global configuration or reading stored credentials. A bounded local audit trace explains what was detected, which placeholder replaced it, whether the original was prevented, request identity, processing latency, and stream restoration status—without retaining raw values, bodies, or hashes.

Anonmyz remains a single Go binary with no hosted gateway, account, telemetry, database, or new runtime. It builds on the repository's pre-existing masking, provider, proxy, MITM, metrics, IDE, and packaging architecture while adding a coherent judge-testable Codex security product.

## English video narration script

**[0:00]** Coding agents are powerful, but the context we give them can contain credentials, private paths, and passwords that we never intended to send to a cloud model. Anonmyz is a local-first DLP gateway that replaces supported sensitive values before they leave this machine and restores them only in the local response.

**[0:18]** The fastest way to verify that claim is one command. This demo needs no API key and contacts no external service.

**[0:27]** Anonmyz has detected four clearly fake values: a GitHub token, an OpenAI-shaped API key, an inline password, and a private-looking path. These placeholder IDs are safe to show.

**[0:42]** This is not a scripted animation or a second redactor. The command started the production proxy and a mock model on dynamic loopback ports. The mock inspected the exact bytes it received. The demo fails if any original arrives upstream or if placeholders are absent.

**[0:58]** The mock also split a placeholder between streamed network writes. Anonmyz's bounded rolling buffer reassembled and restored it locally. The exhaustive test suite repeats that split at every byte boundary, including between the opening brackets.

**[1:16]** Running the demo again proves both temporary servers released their ports cleanly.

**[1:25]** For a live Codex workflow, `anonmyz codex` detects the CLI, preserves the existing ChatGPT or API-key authentication, starts the proxy, and launches Codex with temporary documented provider overrides. Arguments after the separator go directly to Codex. The user's global configuration is never edited, and Codex's exit code and termination are preserved.

**[1:48]** Here is the retained live proof. Codex used an existing ChatGPT subscription while the prompt contained only a fake GitHub PAT-shaped value. The local audit reports upstream status two hundred, one prevented detection, safe restoration, and no response block. Authentication headers and raw values are never retained.

**[2:08]** Now I terminate Anonmyz during an in-flight Codex model request. Codex retries only the configured loopback URL, then exits with an error. The egress trap observes zero direct model fallback attempts. The gateway is bound to `127.0.0.1`, not all network interfaces.

**[2:30]** Anonmyz stays a zero-dependency Go binary and preserves the project's existing providers, explicit proxy, optional MITM mode, IDE integrations, and legacy binary name. The result is a security claim a judge can test—not just trust.

## Recording commands

Use a clean terminal with a large readable font. Do not place a real credential in the demo prompt or terminal history.

```bash
go build -trimpath -ldflags="-s -w -X main.version=build-week" -o anonmyz .
./anonmyz help
./anonmyz demo --non-interactive
./anonmyz demo --non-interactive
./anonmyz codex --dry-run -- --no-alt-screen
go run ./scripts/verify-codex-fail-closed
go test ./... -count=1
```

PowerShell:

```powershell
go build -trimpath -ldflags "-s -w -X main.version=build-week" -o anonmyz.exe .
.\anonmyz.exe help
.\anonmyz.exe demo --non-interactive
.\anonmyz.exe demo --non-interactive
.\anonmyz.exe codex --dry-run -- --no-alt-screen
go run .\scripts\verify-codex-fail-closed
go test ./... -count=1
```

For a live dashboard shot, use your existing Codex ChatGPT login or a dedicated revocable API key, never display credentials, run `anonmyz codex`, and open the printed loopback dashboard URL. Put only clearly fake secret-shaped data in the smoke-test prompt.
