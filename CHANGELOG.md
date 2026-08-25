# Changelog

All notable changes to Local AI Firewall will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-25

### Security

- Require HTTPS for remote `UPSTREAM_URL` targets; allow plaintext HTTP only for loopback development services and reject URL userinfo, query parameters, and fragments.
- Block Safe Session arguments that attempt to change the protected model-provider route, the `anonmyz` provider definition, Apps, or request-compression features.
- Stop IDE extensions from auto-executing workspace/project-root binaries that would receive the provider credential; VS Code accepts `binaryPath` only from global user settings.
- Derive new encrypted MITM CA keys with salted PBKDF2-HMAC-SHA-256 (210,000 iterations) before AES-256-GCM encryption while retaining legacy-key read compatibility.
- Detect supported raw credentials split across streaming network reads with a bounded 64 KiB inspection look-behind.
- Cap non-streaming upstream response bodies at 64 MiB in explicit-proxy and MITM paths.
- Delay explicit-proxy standard response headers until DLP inspection completes so blocked responses return an unambiguous `502 Bad Gateway` instead of an upstream success status with an empty body.
- Reject malformed integer and boolean environment values instead of silently falling back; validate listener conflicts, vault capacity, and log levels at startup.

### Added

- Add checksum-verifying, one-command installers for Linux, macOS, and Windows that install without administrator access.
- Add an approximately 60-second demo recording captured from the deterministic production-path demo command.
- Rewrite the README opening around the user problem, local trust boundary, one-command install, and independently verifiable demo.
- Add `anonmyz doctor` and `anonmyz --check-config` for credential-safe configuration validation without starting listeners.
- Add a shared transport-independent `dlp.Engine` for explicit-proxy and MITM request scopes, standard responses, and streaming restoration.
- Add request-correlated JSON security events for request, upstream, restoration, and blocking decisions.
- Add VS Code binary-trust and health-check unit tests and run them in CI.
- Add a testable VS Code child-process lifecycle with start/stop, stale-child, spawn-error, and shutdown coverage.
- Add JetBrains binary resolver tests and a Java 17/Gradle CI job.
- Add real CONNECT/TLS interception, stream, response-limit, trust-store, certificate-cache, and HTTP-framing tests for MITM mode.
- Add masker/body-size, secret-count, and stream-chunk benchmarks with a CI benchmark report artifact.
- Add `govulncheck` and npm audit release gates; run Go CI jobs on patched Go 1.26.6.
- Upgrade the VSIX packaging toolchain to `@vscode/vsce` 3.9.2 and patched transitive dependencies after the audit gate detected high-severity development dependency advisories.

### Changed

- Replace MITM's `goto` keep-alive flow with a per-request function and deterministic scope/body cleanup.
- Replace process-global metrics with injected per-server recorders; remove the vault package's metrics DTO dependency.
- Keep only the DLP look-behind required by the active request scope and use a bounded credential-shape tail, reducing the 64-byte stream benchmark from about 8.9 s to 134 ms and allocation from about 38 MB to 0.85 MB for a 64 KiB payload.
- Skip regex replacement buffers when a pattern is absent; a safe 32 MiB body now allocates about 56 KiB instead of 1.07 GiB, guarded by a backing-storage and allocation-budget test.
- Add a single-pass character-feature prefilter before regex evaluation, reducing the 32 MiB safe-body benchmark from about 14.4 s to 1.32 s and allocation to about 21 KiB without changing detector semantics.
- Pin Docker builder/runtime images to patched immutable digests and pin GoReleaser/golangci-lint tool versions.
- Publish race coverage, benchmark and VSIX CI artefacts; generate per-archive SPDX SBOMs, checksums and GitHub/Sigstore release provenance.
- Add Dependabot maintenance for Go modules, the VS Code npm lockfile and GitHub Actions.

## [0.1.0] - 2026-06-17

### Added

#### Core Firewall
- **Transparent reverse proxy** for AI providers: Anthropic, OpenAI, Gemini, Azure OpenAI, Groq, Together AI, Perplexity, Mistral, Cohere, DeepSeek, xAI, Ollama, LM Studio, generic OpenAI-compatible catch-all (14 adapters)
- **28 sensitive pattern detectors**:
  - GitHub PAT v1 (`ghp_...`), OAuth App token (`gho_...`), Actions token (`ghs_...`)
  - GitLab Personal Access Token (`glpat-...`)
  - AWS Access Key ID (`AKIA...`) and Secret Access Key
  - Anthropic API key, OpenAI API key, Google API key, Stripe key, Slack token
  - HTTP Bearer tokens, standalone JWTs, PEM private key blocks
  - Inline secret assignments (`password=...`, `api_key: "..."`) and shell `export` secrets
  - Unix and Windows filesystem paths (leak username)
  - Email addresses, credit card numbers, IBANs (international + Turkish)
  - National IDs with checksum validation: Turkish TC Kimlik, Brazilian CPF (mod-11), Spanish DNI (mod-23), Indian Aadhaar (Verhoeff), Italian Codice Fiscale
  - Turkish phone numbers
- **MITM transparent proxy mode** (`MITM_ENABLED=true`): intercepts TLS connections to AI providers without requiring client reconfiguration; one-command CA install/uninstall (`ai-firewall install-ca` / `uninstall-ca`)
- **CA private key encryption** (`AI_FIREWALL_CA_PASSPHRASE`): AES-256-GCM at rest; warning logged on startup when passphrase is absent
- **Vault-full request blocking**: requests that would leak secrets due to a full vault are rejected with 507 Insufficient Storage
- **SSE streaming support** with chunk-safe label reassembly
- **Thread-safe vault** (`sync.RWMutex`) with atomic metrics counters
- **Provider auto-detection** from `UPSTREAM_URL` or manual override via `PROVIDER_HINT`
- **HTTP header allow-list** (explicit forward policy)
- **JSON metrics endpoint** (`/metrics`) with Prometheus-compatible structure
- **`/dashboard` endpoint**: real-time HTML metrics dashboard (loopback-only)
- **Graceful shutdown** with vault wipe on SIGINT/SIGTERM

#### IDE Extensions

**VS Code / Cursor Extension** (`extensions/vscode/`) — Stable:
- First-run wizard with "Set API Key & Start" notification
- SecretStorage integration (API key never written to disk)
- Status bar `$(shield) Firewall` icon with click-to-toggle
- 6 command palette commands: Start, Stop, Restart, Set API Key, Open Metrics, Copy Agent Env
- 7-layer cross-platform binary discovery (config → env var → workspace → bundle → OS dirs → PATH → browse dialog)
- Health check polling with visual status updates; auto-start on VS Code launch

**JetBrains Plugin** (`extensions/jetbrains/`) — Beta:
- Tools menu integration: Start, Stop, Restart, Copy Agent Env, Open Metrics
- Process management with environment variable propagation
- Same 7-layer binary discovery as VS Code; notification balloons for status

#### Infrastructure & Tooling
- `.github/workflows/release.yml` — 5-platform automated builds (linux-amd64, linux-arm64, darwin-amd64, darwin-arm64, windows-amd64) + VSIX package, with `checksums.txt`
- `.github/workflows/ci.yml` — CI pipeline with `go test ./...` and `go vet ./...`
- `scripts/build-all.{ps1,sh}` — local cross-compilation scripts
- `scripts/update-packaging.sh` — fills Homebrew formula and Scoop manifest with real checksums from a published release
- `scripts/e2e-live.{ps1,sh}` — manual smoke test against real Anthropic/OpenAI endpoints (never runs in CI)
- `packaging/homebrew/ai-firewall.rb` — Homebrew tap formula
- `packaging/scoop/ai-firewall.json` — Scoop bucket manifest

#### Documentation
- `SECURITY.md` — vulnerability disclosure policy
- `THREAT_MODEL.md` — trust boundaries and threat matrix

### Configuration

Environment variable-only; no config file needed.

| Variable | Default | Description |
|---|---|---|
| `FORWARD_API_KEY` | *(required)* | Real key forwarded upstream. Set to `"none"` for passthrough. |
| `UPSTREAM_URL` | `https://api.anthropic.com` | Upstream provider base URL. |
| `FIREWALL_PORT` | `8080` | TCP port for the API proxy. |
| `PROVIDER_HINT` | *(auto-detect)* | Force a specific provider adapter. |
| `VAULT_SIZE_LIMIT` | `1000` | Max token→secret entries in memory; 507 on overflow. |
| `MASK_PATHS` | `true` | Detect and mask filesystem paths. |
| `MASK_EMAILS` | `true` | Detect and mask email addresses. |
| `LOG_LEVEL` | `info` | `silent` \| `info` \| `debug`. |
| `MITM_ENABLED` | `false` | Start transparent MITM proxy. |
| `MITM_PORT` | `8082` | TCP port for the MITM proxy. |
| `MITM_CERT_DIR` | `~/.ai-firewall` | CA cert/key directory. |
| `AI_FIREWALL_CA_PASSPHRASE` | *(unset)* | AES-256-GCM passphrase for the CA private key. |

### Performance
- Pre-compiled regex patterns (zero allocation per match after startup)
- O(1) vault lookups via hash maps; lock-free metrics counters (atomic primitives)
- Stream processing (clean SSE chunk): **~28 µs/op · 4 allocs/op** (`BenchmarkStreamProcessing`)
- Request masking (body with PAT + email): **~33 µs/op · 101 allocs/op** (`BenchmarkMasking`)
- Typical memory footprint < 10 MB under local workload

### Security
- API keys never logged or written to disk
- Header allow-list — only explicitly safe headers forwarded upstream
- Vault wiped on graceful shutdown; size limit prevents unbounded memory growth
- Label format validated (`[[PREFIX_8HEXDIGITS]]`)
- SSE chunk-safe processing (labels can span multiple network packets)
- License: **AGPL-3.0-or-later**

### Known Limitations
- GitHub PAT pattern requires exactly 36 chars after `ghp_` (strict validation avoids false positives)
- Vault-full rejects the request with 507; the upstream never receives unmasked secrets
- Streaming response masking is chunk-by-chunk — a secret split across a chunk boundary may pass through on the response path
- HTTP-only (HTTPS termination should be handled upstream in production)
- Single-instance design (no cluster mode or shared vault)

---

[Unreleased]: https://github.com/3mre0s/ai-firewall/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/3mre0s/ai-firewall/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/3mre0s/ai-firewall/releases/tag/v0.1.0
