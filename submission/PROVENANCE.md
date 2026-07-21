# Submission-period provenance

## Existing before OpenAI Build Week

- Go pattern registry and masking engine.
- Request-scoped in-memory vault and restoration.
- OpenAI-compatible, Anthropic, and Gemini provider adapters.
- Explicit proxy and optional allow-listed MITM mode.
- Metrics dashboard, IDE integrations, packaging, release automation, and baseline tests.
- Vault-capacity fail-closed behavior.

## Added or materially completed during OpenAI Build Week

- Deterministic, API-key-free `anonmyz demo` using the production proxy and a byte-inspecting local mock upstream.
- `anonmyz codex` Safe Session with ChatGPT-subscription and optional API-key authentication, temporary provider overrides, HTTP-only inspected transport, signal/exit handling, and metadata-only session evidence.
- Bounded local `/audit` trail and dashboard privacy trace without raw values or hashes.
- Exhaustive streaming placeholder restoration, including a split between opening brackets.
- Request-scoped response leak detection that avoids unrelated path/PII false positives while remaining fail-closed for credentials.
- Live ChatGPT-subscription verification using only a fake GitHub PAT-shaped payload.
- Automated proxy-loss proof showing Codex error termination and zero direct model fallback attempts.
- Current-CLI Safe Session hardening that disables Apps only for the protected child and makes any trapped non-loopback egress a verification failure without hostname allowlists.
- Loopback-only and authentication-metadata non-retention regression tests.
- Cross-platform Anonmyz builds, checksums, judge guide, Devpost copy, video script, and sanitized evidence package.

## Human and Codex contributions

Human decisions established the product scope, local-only trust boundary, safe live-test constraints, retention policy, and submission story. Codex inspected the repository and history, checked current Codex behavior against the installed CLI and official manual/source, implemented scoped changes, ran the verification matrix, and prepared judge-facing artifacts. Final submission, video recording/upload, and `/feedback` submission remain human-controlled external actions.
