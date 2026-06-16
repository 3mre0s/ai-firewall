# Changelog

All notable changes to Local AI Firewall will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-06-14

### Added
- **MITM transparent proxy mode** (`MITM_ENABLED=true`): intercepts TLS connections to AI providers without requiring client reconfiguration. One-command CA installation (`ai-firewall install-ca` / `uninstall-ca`).
- **15 additional detection patterns** (total 28): Turkish TC Kimlik, Brazilian CPF, Spanish DNI, Indian Aadhaar, Italian Codice Fiscale (all checksum-validated), Turkish phone numbers and IBAN, international IBAN, standalone JWTs, Stripe keys, Google API keys, Slack tokens, and more.
- **Multi-platform CI/CD release pipeline** (`.github/workflows/release.yml`): automated builds for linux-amd64, linux-arm64, darwin-amd64, darwin-arm64, windows-amd64 with `checksums.txt`.
- **CA private key encryption** (`AI_FIREWALL_CA_PASSPHRASE`): AES-256-GCM at rest; unencrypted-key warning on startup when passphrase is absent.
- **Vault-full request blocking**: requests that would leak secrets due to a full vault are now rejected with 507 Insufficient Storage instead of forwarding unmasked data.
- **`/dashboard` endpoint**: real-time HTML metrics dashboard (loopback-only).

### Changed
- **License: AGPL-3.0-or-later** (replacing the previous MIT license).
- `FORWARD_API_KEY=none` passthrough mode documented and supported for subscription-based auth (Claude Code Pro/Max).

## [0.2.0] - 2026-06-10

### Added
- **VS Code Extension**: `src/extension.js` is fully implemented and stable for use.
- **Documentation**: Updated `README.md` to reflect the stable release status of the VS Code extension.

## [0.1.0] - 2026-06-10

### Added

#### Core Firewall
- **Transparent reverse proxy** for AI providers (Anthropic, OpenAI, Gemini, Groq, Together, Mistral, Perplexity, Cohere, DeepSeek, xAI, Ollama, LM Studio, Antigravity, Generic)
- **13 sensitive pattern detectors**:
  - GitHub Personal Access Token v1 (`ghp_...`)
  - GitHub OAuth App Token (`gho_...`)
  - GitHub Actions Token (`ghs_...`)
  - GitLab Personal Access Token (`glpat-...`)
  - AWS Access Key ID (`AKIA...`)
  - AWS Secret Access Key
  - HTTP Bearer tokens
  - PEM private key blocks
  - Inline secret assignments (`password=...`, `api_key: "..."`)
  - Shell exports (`export DB_PASS=...`)
  - Unix absolute paths (`/home/...`, `/var/...`)
  - Windows absolute paths (`C:\Users\...`)
  - Email addresses (PII)
- **SSE streaming support** with chunk-safe label reassembly
- **Thread-safe vault** (sync.RWMutex) with atomic metrics counters
- **Provider auto-detection** from UPSTREAM_URL or manual override via PROVIDER_HINT
- **HTTP header allow-list** for security (explicit forward policy)
- **JSON metrics endpoint** (`/metrics`) with Prometheus-compatible structure
- **Graceful shutdown** with vault wipe on SIGINT/SIGTERM

#### IDE Extensions

**VS Code / Cursor Extension** (`extensions/vscode/`):
- First-run wizard with "Set API Key & Start" notification
- SecretStorage integration for secure API key storage (never written to disk)
- Status bar with `$(shield) Firewall` icon and click-to-toggle
- 6 command palette commands:
  - Start, Stop, Restart
  - Set API Key
  - Open Metrics
  - Copy Agent Env (generates provider-aware export snippets)
- Cross-platform binary discovery (7-layer fallback chain):
  - Explicit `localAiFirewall.binaryPath` config
  - `AI_FIREWALL_BINARY` environment variable
  - Workspace root folders
  - Extension bundle directory
  - OS-standard install locations (Windows: `%LOCALAPPDATA%\local-ai-firewall`, macOS: `~/Library/Application Support/local-ai-firewall`, Linux: `~/.local/bin`)
  - PATH lookup
  - Interactive "Browse for binary" dialog
- Health check polling with visual status updates
- Auto-start on VS Code launch (configurable)
- Output channel for firewall logs

**JetBrains Plugin** (`extensions/jetbrains/`):
- Tools menu integration with 5 actions:
  - Start, Stop, Restart
  - Copy Agent Env
  - Open Metrics
- Process management with environment variable propagation
- Same 7-layer binary discovery as VS Code
- Notification balloons for status updates

#### Beta Infrastructure
- `.github/workflows/release.yml` — 4-platform automated builds (linux-amd64, darwin-amd64, darwin-arm64, windows-amd64) with SHA256 checksums
- `scripts/build-all.{ps1,sh}` — local cross-compilation scripts
- `scripts/e2e-live.{ps1,sh}` — manual smoke test against real Anthropic/OpenAI endpoints (never runs in CI)
- `scripts/e2e-headless.ps1` + `scripts/mock-upstream/` — 6-step automated headless test with mock upstream (no real API key required)
- `BETA.md` — 6-step onboarding guide with placeholders for Discord/feedback URLs
- `.github/ISSUE_TEMPLATE/beta-{access,feedback}.yml` — GitHub issue forms for beta program
- VSIX packaging support (`npm run package` in `extensions/vscode`)

#### Documentation
- `ARCHITECTURE.md` — component diagrams and data flow
- `DEPLOYMENT.md` — Docker/Kubernetes sidecar patterns
- `SECURITY.md` — vulnerability disclosure policy
- `THREAT_MODEL.md` — trust boundaries and threat matrix

### Configuration
- Environment variable-only configuration (no config file required)
- Required: `FORWARD_API_KEY` (never logged, never written to disk)
- Optional: `UPSTREAM_URL`, `PROVIDER_HINT`, `FIREWALL_PORT`, `VAULT_SIZE_LIMIT`, `MASK_PATHS`, `MASK_EMAILS`, `LOG_LEVEL`

### Testing
- Full unit test coverage across all packages (`go test ./...`)
- 6-step headless E2E test with mock upstream (VSIX install verification, SecretStorage code path validation, health check, agent connection, masking round-trip, metrics validation)
- Pattern validation tests (mask/unmask round-trip, vault-full behavior, SSE split-chunk reassembly)
- Cross-platform build verification (all 4 target platforms compile successfully)

### Security
- API keys never logged or written to disk
- Header allow-list (only safe headers forwarded upstream)
- Vault automatic wipe on process shutdown
- Vault size limit (default 1000 entries) to prevent unbounded memory growth
- Label format validation (`[[PREFIX_8HEXDIGITS]]`)
- SSE chunk-safe processing (labels can span multiple network packets)

### Performance
- Pre-compiled regex patterns (zero allocation per match)
- O(1) vault lookups via hash maps
- Lock-free metrics counters (atomic primitives)
- Typical memory footprint <10 MB under local workload

### Known Limitations
- GitHub PAT pattern requires exactly 36 characters after `ghp_` prefix (strict validation avoids false positives)
- Vault-full events reject the request with 507 Insufficient Storage; the upstream never receives unmasked secrets (monitor `vault_evictions_total` metric)
- HTTP-only (HTTPS termination should be handled by reverse proxy in production)
- Single-instance design (no cluster mode or shared vault)

## [0.0.0] - 2026-06-06

### Added
- Initial project scaffold
- Core masking/unmasking engine
- Vault implementation
- Pattern registry
- Provider abstraction

---

[Unreleased]: https://github.com/3mre0s/ai_firewall/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/3mre0s/ai_firewall/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/3mre0s/ai_firewall/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/3mre0s/ai_firewall/releases/tag/v0.1.0
