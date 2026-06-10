# 🔥 Local AI Firewall

[![Go](https://img.shields.io/badge/go-1.22-blue)](#)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](#-running-tests)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Security](https://img.shields.io/badge/security-zero--trust-red)](SECURITY.md)

A transparent, zero-trust **reverse proxy** that sits between your IDE / application and any AI API. It **masks** sensitive data before it ever reaches the cloud and **unmasks** the response on the way back — all without modifying a single line of your application code.

## 📚 Documentation Index

To support enterprise compliance and technical reviews, the following resources are available:
- **[SECURITY.md](SECURITY.md)**: Security Support Policy and vulnerability disclosure reporting guide.
- **[THREAT_MODEL.md](THREAT_MODEL.md)**: Trust boundaries, in-scope threat matrix, and out-of-scope security mitigations.
- **[ARCHITECTURE.md](ARCHITECTURE.md)**: Component diagrams, sequence flow charts, and SSE streaming processor design.
- **[DEPLOYMENT.md](DEPLOYMENT.md)**: Dockerfile configurations, Kubernetes sidecar architecture, and health checks.

```
Your App  →  [AI Firewall :8080]  →  Anthropic / OpenAI / Gemini / Groq / …
                    ↑
        Masks secrets BEFORE forwarding
        Unmasks labels AFTER receiving
```

---

## ✨ Features

| Feature | Detail |
|---|---|
| **Multi-provider** | Anthropic, OpenAI, Gemini, Groq, Together, Mistral, Perplexity, DeepSeek, xAI/Grok, Cohere, Azure OpenAI, Ollama, LM Studio, Antigravity |
| **Pattern coverage** | GitHub/GitLab tokens, AWS keys, Bearer tokens, PEM private keys, passwords, API keys, env-var secrets, Unix/Windows paths, e-mail addresses |
| **Streaming** | SSE chunk-safe unmasking — labels split across network packets are correctly reassembled |
| **Observability** | `/metrics` JSON endpoint — vault fill %, masked item counts, error rates, uptime |
| **Zero config** | Single binary + env vars. No config files, no databases. |
| **Thread-safe** | sync.RWMutex vault + atomic counters — safe under concurrent load |

---

## 📦 Installation

### Option 1: Download Pre-built Binary (Recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/localai/firewall/releases/latest):

| Platform | Binary | Installation |
|---|---|---|
| **Windows x64** | `ai-firewall-windows-amd64.exe` | Rename to `ai-firewall.exe`, place in `%LOCALAPPDATA%\local-ai-firewall\` |
| **macOS Apple Silicon** | `ai-firewall-darwin-arm64` | Rename to `ai-firewall`, place in `~/Library/Application Support/local-ai-firewall/` or `/opt/homebrew/bin` |
| **macOS Intel** | `ai-firewall-darwin-amd64` | Rename to `ai-firewall`, place in `~/Library/Application Support/local-ai-firewall/` or `/usr/local/bin` |
| **Linux x64** | `ai-firewall-linux-amd64` | Rename to `ai-firewall`, place in `~/.local/bin/` or `/usr/local/bin` |

**Verify the checksum** (recommended):
```bash
sha256sum ai-firewall-linux-amd64
# Compare with checksums.txt from the same release
```

**macOS/Linux: Make executable:**
```bash
chmod +x ~/.local/bin/ai-firewall
```

### Option 2: Build from Source

**Prerequisites:**
- [Go 1.22+](https://go.dev/dl/)

**Build:**
```bash
git clone https://github.com/localai/firewall
cd firewall
go build -o ai-firewall .
```

---

## 🚀 Quick Start

### 1. Prerequisites

- An API key for your AI provider (Anthropic, OpenAI, Gemini, Groq, etc.)
- The `ai-firewall` binary (from Installation above)

### 2. Build (skip if you downloaded pre-built binary)

```bash
git clone https://github.com/localai/firewall
cd firewall
go build -o ai-firewall .
```

### 3. Configure

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
# Edit .env with your editor
```

### 4. Run

```bash
# Load env vars and start the proxy
# On Linux/macOS:
export $(cat .env | xargs) && ./ai-firewall

# On Windows PowerShell:
Get-Content .env | ForEach-Object { $k,$v = $_ -split '=',2; [System.Environment]::SetEnvironmentVariable($k,$v) }
.\ai-firewall.exe
```

The firewall starts on `http://localhost:8080` (or your configured port).

### 5. Point your client at the firewall

```bash
# Before (direct to Anthropic):
ANTHROPIC_BASE_URL=https://api.anthropic.com

# After (through the firewall):
ANTHROPIC_BASE_URL=http://localhost:8080
```

The firewall injects your real `FORWARD_API_KEY` — your client sends **any** placeholder or no key at all.

---

## ⚙️ Configuration Reference

All settings are read from **environment variables**. No `.env` file format is enforced; any mechanism that sets env vars works (Docker `--env`, Kubernetes secrets, direnv, etc.).

| Variable | Default | Description |
|---|---|---|
| `FORWARD_API_KEY` | *(required)* | Real API key forwarded to the upstream provider. Never logged. |
| `UPSTREAM_URL` | `https://api.anthropic.com` | Base URL of the upstream AI provider. |
| `PROVIDER_HINT` | *(auto-detect)* | Force a specific provider. Leave empty for URL-based auto-detection. See [Providers](#-supported-providers). |
| `FIREWALL_PORT` | `8080` | Local TCP port the proxy listens on. |
| `VAULT_SIZE_LIMIT` | `1000` | Max masked values held in memory per process lifetime. |
| `MASK_PATHS` | `true` | Detect and mask Unix/Windows file-system paths. |
| `MASK_EMAILS` | `true` | Detect and mask e-mail addresses (PII). |
| `LOG_LEVEL` | `info` | Verbosity: `silent` \| `info` \| `debug` |

---

## 📄 .env.example

```dotenv
# ─── Required ───────────────────────────────────────────────────────────────
# Your real API key. This is NEVER sent to your client or logged anywhere.
FORWARD_API_KEY=sk-ant-api03-REPLACE_WITH_YOUR_KEY

# ─── Upstream target ────────────────────────────────────────────────────────
# Anthropic (default)
UPSTREAM_URL=https://api.anthropic.com

# OpenAI — uncomment to switch:
# UPSTREAM_URL=https://api.openai.com
# FORWARD_API_KEY=sk-REPLACE_WITH_OPENAI_KEY

# Google Gemini — uncomment to switch:
# UPSTREAM_URL=https://generativelanguage.googleapis.com
# FORWARD_API_KEY=AIza-REPLACE_WITH_GEMINI_KEY

# Groq — uncomment to switch:
# UPSTREAM_URL=https://api.groq.com
# FORWARD_API_KEY=gsk_REPLACE_WITH_GROQ_KEY

# Ollama (local, no auth needed):
# UPSTREAM_URL=http://localhost:11434
# FORWARD_API_KEY=none

# ─── Provider hint (optional) ────────────────────────────────────────────────
# Leave empty for auto-detection from UPSTREAM_URL.
# Set explicitly if auto-detect is wrong (rare).
# Values: anthropic | openai | gemini | groq | together | mistral |
#         perplexity | cohere | deepseek | xai | azure | ollama |
#         lmstudio | antigravity | generic
PROVIDER_HINT=

# ─── Proxy settings ─────────────────────────────────────────────────────────
FIREWALL_PORT=8080
VAULT_SIZE_LIMIT=1000

# ─── Data categories to mask ────────────────────────────────────────────────
MASK_PATHS=true
MASK_EMAILS=true

# ─── Logging ────────────────────────────────────────────────────────────────
# silent | info | debug
LOG_LEVEL=info
```

**Client-side setup** — point your AI SDK at the firewall:

```bash
# Anthropic SDK (Python/Node/etc.)
ANTHROPIC_BASE_URL=http://localhost:8080
ANTHROPIC_API_KEY=any-placeholder   # the firewall replaces this

# OpenAI SDK
OPENAI_BASE_URL=http://localhost:8080
OPENAI_API_KEY=any-placeholder
```

---

## IDE Extensions

Developer-agent users can run the firewall as a one-click local sidecar from their IDE.

| IDE | Location | Status |
|---|---|---|
| VS Code / Cursor-compatible | `extensions/vscode` | Stable release: start, stop, restart, metrics, copy env, SecretStorage API key |
| JetBrains IDEs | `extensions/jetbrains` | Private beta scaffold: Tools menu actions, process manager, metrics, copy env |

Both extensions auto-discover the `ai-firewall` binary in:

- the current workspace / project root,
- the OS-standard install dir (`%LOCALAPPDATA%\local-ai-firewall`, `~/Library/Application Support/local-ai-firewall`, `~/.local/bin`, `/usr/local/bin`, `/opt/homebrew/bin`),
- anything on `PATH`.

Override with `localAiFirewall.binaryPath` (VS Code) or `AI_FIREWALL_BINARY` (JetBrains).

### VS Code

```bash
go build -o ai-firewall .
code extensions/vscode
```

Press `F5`, then run:

- `Local AI Firewall: Set API Key`
- `Local AI Firewall: Start`
- `Local AI Firewall: Copy Agent Env`

Or install the packaged VSIX directly (no Marketplace needed):

```bash
cd extensions/vscode && npm install && npm run package
code --install-extension local-ai-firewall.vsix
```

### JetBrains

```bash
go build -o ai-firewall .
cd extensions/jetbrains
./gradlew runIde
```

Set `FORWARD_API_KEY` before launching the IDE, or set `AI_FIREWALL_BINARY` if the binary is not in one of the auto-discovered locations.

---

## 🧪 Private Beta

Pre-release builds for Windows, macOS (Apple Silicon + Intel), and Linux are published to GitHub Releases. See **[BETA.md](BETA.md)** for the full onboarding flow: requesting an invite, installing the binary in the OS-standard path, installing the VSIX or JetBrains plugin, and submitting feedback.

Live smoke test against a real provider (manual, not run in CI to avoid leaking keys):

```bash
# macOS / Linux
FORWARD_API_KEY=sk-... scripts/e2e-live.sh anthropic
FORWARD_API_KEY=sk-... scripts/e2e-live.sh openai

# Windows
$env:FORWARD_API_KEY = "sk-..."; pwsh scripts/e2e-live.ps1 anthropic
```

---

## 📡 Supported Providers

| `PROVIDER_HINT` | Auto-detected from URL | Notes |
|---|---|---|
| `anthropic` | `anthropic.com` | x-api-key + anthropic-version headers |
| `openai` | `api.openai.com` | Authorization: Bearer + org header |
| `gemini` | `generativelanguage.googleapis.com`, `aiplatform.googleapis.com` | x-goog-api-key or OAuth2 Bearer |
| `azure` | `openai.azure.com` | api-key header (Azure-specific) |
| `groq` | `api.groq.com` | OpenAI-compatible, ultra-fast |
| `together` | `together.xyz`, `together.ai` | OpenAI-compatible open-source models |
| `perplexity` | `perplexity.ai` | Web-search augmented LLM |
| `mistral` | `mistral.ai` | OpenAI-compatible |
| `cohere` | `cohere.com`, `cohere.ai` | OpenAI-compatible v2 endpoint |
| `deepseek` | `deepseek.com` | OpenAI-compatible |
| `xai` | `api.x.ai` | Grok models |
| `antigravity` | `antigravity` | Antigravity inference API |
| `ollama` | `:11434`, `ollama` | Local; auth optional |
| `lmstudio` | `:1234`, `lmstudio` | Local; Content-Type only |
| `generic` | *(catch-all)* | Any OpenAI-compatible endpoint not listed above |

---

## 📊 Metrics Endpoint

`GET http://localhost:8080/metrics`

Returns JSON (no authentication required — restrict access at the network level):
Bind the process to `127.0.0.1` when possible, or enforce a host firewall / security-group rule so only trusted operators can reach it.

```json
{
  "uptime_seconds": 3600.4,
  "requests_total": 142,
  "stream_requests": 38,
  "masked_items_total": 89,
  "masked_requests_total": 61,
  "unmasked_items_total": 89,
  "mask_rate_pct": "42.96%",
  "upstream_errors_total": 2,
  "vault_evictions_total": 0,
  "vault_current": 47,
  "vault_limit": 1000,
  "vault_fill_pct": "4.70%",
  "vault_unmask_hits_total": 95
}
```

### Prometheus Integration

Use the [Prometheus textfile collector](https://github.com/prometheus/node_exporter#textfile-collector) or a simple scrape job with JSON parsing:

```yaml
# prometheus.yml scrape config
scrape_configs:
  - job_name: 'ai_firewall'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    # Use json_exporter or a custom relabeling rule to parse JSON
```

Key metrics to alert on:

| Metric | Alert condition |
|---|---|
| `vault_fill_pct` | > 80% — vault approaching limit |
| `upstream_errors_total` | Increasing rate — upstream API issues |
| `vault_evictions_total` | > 0 — secrets leaking due to full vault |
| `mask_rate_pct` | Sudden drop — pattern coverage regression |

---

## 🛡️ Pattern Coverage

The following patterns are detected and masked automatically:

| Category | Pattern | Example |
|---|---|---|
| TOKEN | GitHub PAT v1 | `ghp_XXXXXXXX...` |
| TOKEN | GitHub OAuth App token | `gho_XXXXXXXX...` |
| TOKEN | GitHub Actions token | `ghs_XXXXXXXX...` |
| TOKEN | GitLab PAT | `glpat-XXXXXXXX` |
| TOKEN | HTTP Bearer token | `Authorization: Bearer <token>` |
| KEY | AWS Access Key ID | `AKIAIOSFODNN7...` |
| KEY | AWS Secret Access Key | `aws_secret_key=...` |
| KEY | PEM private key block | `-----BEGIN PRIVATE KEY-----` |
| SECRET | Inline secret assignment | `password=...`, `api_key: "..."` |
| SECRET | Shell export | `export DB_PASS=...` |
| PATH | Unix absolute path | `/home/alice/.ssh/id_rsa` |
| PATH | Windows absolute path | `C:\Users\alice\Documents\...` |
| PII | E-mail address | `alice@example.com` |

---

## 🛡️ Why Not Traditional DLP?

Traditional Data Loss Prevention (DLP) systems scan outgoing network traffic and block requests if a secret is found. This breaks application workflows, disrupts developers, and requires complex exception management.

**Local AI Firewall** takes a different approach:
- **Preserves Workflows**: It does not block or reject queries.
- **Transparent Substitution**: Secrets are seamlessly replaced with unique, random labels (e.g. `[[EMAIL_A1B2C3D4]]`).
- **Lossless Reconstruction**: Returned answers containing the labels are reconstructed with their original values on the fly.
- **No Developer Impact**: The user experience remains uninterrupted, and the upstream AI provider receives safe, anonymized prompts.

---

## ⚡ Performance

Designed with high-efficiency Go constructs for sub-millisecond latencies:

- **Regex Pre-compilation**: Pattern detection uses pre-compiled regular expressions initialized at startup, resulting in zero allocation per request match.
- **Constant Time Lookups**: Vault mappings are resolved in $O(1)$ time complexity using hash maps.
- **Lock-free Counters**: Metrics are collected using CPU-level atomic primitives (`sync/atomic`), avoiding locks on common paths.
- **Low Memory Footprint**: Typically runs under `< 10 MB` RSS under active local workloads.

### Benchmark Guidelines (MacBook Pro M3)
- **Masking 2 KB prompt**: ~35 µs
- **Masking 20 KB prompt**: ~210 µs

---

## 🔬 Running Tests

```bash
go test ./masker/... -v -count=1
go test ./...        -v
go vet ./...
```

Test coverage includes:

- ✅ `Mask()` output does not contain the original sensitive value (10 patterns)
- ✅ `Unmask(Mask(x)) == x` round-trip for every pattern type
- ✅ Vault-full: masking skipped, original value preserved (not silently dropped)
- ✅ SSE split-chunk: label split across two network packets → correctly reassembled
- ✅ Multi-split streaming with three labels at arbitrary chunk boundaries
- ✅ `ByType` breakdown matches `MaskedCount`
- ✅ Label format `[[PREFIX_8HEXDIGITS]]` validation
- ✅ Edge cases: empty input, plain text with no secrets, unknown vault labels

---

## 🏗️ Architecture

```
github.com/localai/firewall/
├── main.go                 — startup, signal handling, HTTP mux
├── config/config.go        — env var loading, LoadForTest()
├── vault/vault.go          — thread-safe label→value store
├── patterns/patterns.go    — compiled regex registry
├── masker/
│   ├── masker.go           — Mask() / Unmask() engine
│   └── masker_test.go      — unit tests (table-driven)
├── providers/
│   ├── provider.go         — Provider interface + Detect() + DetectByHint()
│   ├── anthropic.go        — x-api-key + anthropic-version
│   ├── gemini.go           — x-goog-api-key / OAuth2 Bearer
│   └── openai_compat.go    — OpenAI, Azure, Groq, Together, Mistral,
│                             Perplexity, Cohere, DeepSeek, xAI, Ollama,
│                             LM Studio, Antigravity, Generic
├── proxy/
│   ├── handler.go          — 5-step pipeline (mask→forward→unmask)
│   └── stream.go           — SSE chunk-safe streamProcessor
└── metrics/metrics.go      — atomic counters + /metrics JSON handler
```

---

## 🤝 Contributing

1. Fork & clone
2. `go test ./...` must pass with no failures
3. `go vet ./...` must report no issues
4. Add a `SensitivePattern` entry in `patterns/patterns.go` for new detection rules
5. Add a new provider by implementing `Provider` interface (or embedding `openAICompatProvider`) in `providers/`

---

## 📜 License

MIT — see [LICENSE](LICENSE).
