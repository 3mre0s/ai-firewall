# Local AI Firewall

Prevent Claude Code, Cursor, and AI coding agents from accidentally sending
API keys, `.env` values, credentials, file paths, and personal data to LLM
providers.

Local AI Firewall runs entirely on your machine. It replaces detected secrets
with typed placeholders before the request leaves your computer and restores
them locally in the response.

- Local-only
- No account
- No hosted gateway
- Telemetry disabled by default
- Secret mappings kept only in memory
- Open source

[![Go](https://img.shields.io/badge/go-1.22+-blue)](#build-from-source)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![CI](https://github.com/3mre0s/ai-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/3mre0s/ai-firewall/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/3mre0s/ai-firewall)](https://github.com/3mre0s/ai-firewall/releases/latest)
[![GitHub stars](https://img.shields.io/github/stars/3mre0s/ai-firewall)](https://github.com/3mre0s/ai-firewall/stargazers)
[![Go Report Card](https://goreportcard.com/badge/github.com/3mre0s/ai-firewall)](https://goreportcard.com/report/github.com/3mre0s/ai-firewall)

![Local AI Firewall demo](docs/demo.gif)

## Try it safely

```bash
ai-firewall demo
```

This runs entirely offline with bundled synthetic credentials and the same
masking engine used by the proxy. It does not require an API key, start the
proxy, install a certificate, change environment variables, or send a network
request. Placeholder mappings exist only in memory until the command exits.

Never paste a real API key, credential, customer record, or private repository
content into a test.

## Quickstart

Explicit proxy mode is the default first experience. It requires no local CA
and does not intercept unrelated HTTPS traffic.

### 1. Install

Download the archive for your platform from the [latest release](../../releases/latest). Linux amd64 example:

```bash
curl -LO https://github.com/3mre0s/ai-firewall/releases/latest/download/ai-firewall-linux-amd64.tar.gz
curl -LO https://github.com/3mre0s/ai-firewall/releases/latest/download/checksums.txt
sha256sum --check checksums.txt --ignore-missing
tar -xzf ai-firewall-linux-amd64.tar.gz
install -m 0755 ai-firewall "$HOME/.local/bin/ai-firewall"
```

> **macOS not:** İlk çalıştırmada Gatekeeper "cannot be opened because the developer cannot be verified"
> uyarısı gösterebilir (binary code-signed/notarized değil). Şu komutla quarantine flag'ini kaldırabilirsiniz:
>
> ```bash
> xattr -d com.apple.quarantine ai-firewall
> ```
>
> Alternatif: System Settings → Privacy & Security → "Open Anyway"

Windows users should download `ai-firewall-windows-amd64.zip`, verify its SHA-256 value against `checksums.txt`, and place `ai-firewall.exe` on `PATH`.

### 2. Start the firewall

Claude Code Pro/Max subscription users can preserve the client's own
authorization header:

```bash
export FORWARD_API_KEY=none
ai-firewall
```

If you use an Anthropic API key, load it into your shell and pass it through
the firewall without putting the value in this command:

```bash
export FORWARD_API_KEY="$ANTHROPIC_API_KEY"
ai-firewall
```

The API proxy listens on `http://localhost:8080` by default.

### 3. Start Claude Code through the proxy

In a second terminal:

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
claude
```

See the focused [Claude Code setup guide](docs/claude-code.md) for verification,
cleanup, and troubleshooting.

## Supported tools

- **Claude Code:** explicit proxy mode; subscription-token passthrough is supported.
- **Cursor and VS Code:** use the included [VS Code extension](extensions/vscode/README.md).
- **Aider:** see the [Aider integration guide](extensions/aider/README.md).
- **Cline:** see the [Cline integration guide](extensions/cline/README.md).
- **Open WebUI:** see the [Open WebUI integration guide](extensions/open-webui/README.md).
- **Other clients:** point an Anthropic or OpenAI-compatible base URL at the local proxy.

## Cursor and VS Code

The extension can start and stop the firewall, store the provider key in the
editor's secret storage, and copy proxy environment variables for an agent
terminal.

```bash
cd extensions/vscode
npm install
npm run package
code --install-extension local-ai-firewall.vsix
```

Then run these commands from the Command Palette:

1. `Local AI Firewall: Set API Key`
2. `Local AI Firewall: Start`
3. `Local AI Firewall: Copy Agent Env`

See the [extension README](extensions/vscode/README.md) for binary discovery and
development setup.

## How it works

1. Your AI tool sends a request to the local proxy.
2. The firewall scans the complete request body for supported patterns.
3. Each detected value is replaced with a typed placeholder such as
   `[[OAI_KEY_A1B2C3D4E5F60718293A4B5C6D7E8F90]]`.
4. The placeholder-to-secret mapping stays in an in-memory vault.
5. The sanitized request is forwarded to the configured provider.
6. Placeholders in buffered or SSE responses are restored locally before the
   response reaches the client.

The provider receives the sanitized request body. Authentication headers still
reach the provider: explicit mode either injects `FORWARD_API_KEY` or preserves
the client's header when `FORWARD_API_KEY=none`.

## What it detects

The current registry covers:

- API keys and tokens for common developer services
- Password and secret assignments, including shell exports
- Unix and Windows file paths
- Email addresses, credit card numbers, and IBANs
- Checksum-validated national identifiers documented in the source

Detection is pattern-based and deliberately not presented as exhaustive. See
[`patterns/patterns.go`](patterns/patterns.go) for the source of truth.

## Why trust it?

- It runs locally and requires no project account.
- Telemetry is disabled by default and requires explicit opt-in in an official
  release binary.
- Prompt contents are not sent to a project-owned cloud service.
- Placeholder mappings remain in process memory and are cleared on graceful
  shutdown.
- The source can be inspected and [built locally](#build-from-source).
- Every release includes `checksums.txt` covering all platform archives and the VS Code extension.
- Transparent MITM mode is optional and disabled by default.
- The trust boundaries and known trade-offs are documented in
  [THREAT_MODEL.md](THREAT_MODEL.md).

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability. These
properties reduce accidental disclosure risk; they do not guarantee that every
secret will be detected.

## Limitations

- This is not a sandbox and does not defend against prompt injection or
  malicious model output.
- It does not protect a compromised local machine or another process running as
  your user; such a process may read memory or local credentials.
- Detection is pattern-based and may produce false negatives.
- Legitimate content can match a pattern and produce false positives.
- Unsupported, encoded, malformed, or truncated credential formats may not be
  detected.
- Only traffic routed through the firewall is scanned.
- Transparent MITM mode installs a local CA and therefore changes the local
  trust model; protect its private key and uninstall it when no longer needed.
- New secrets in streaming responses may be missed when their bytes cross SSE
  chunk boundaries. Requests are scanned as complete bodies, and restoration of
  known placeholders uses a rolling buffer.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the complete threat model.

## Advanced: transparent MITM mode

Transparent mode is optional. It terminates TLS locally for configured AI hosts
and requires trusting a locally generated CA.

```bash
export AI_FIREWALL_CA_PASSPHRASE="choose-a-strong-local-passphrase"
ai-firewall install-ca
export FORWARD_API_KEY=none
export MITM_ENABLED=true
ai-firewall
```

Point the application or system HTTP proxy at `http://localhost:8082`. In this
mode request bodies are scanned, while the client's authentication header is
forwarded unchanged.

Remove the CA when finished:

```bash
ai-firewall uninstall-ca
```

If `AI_FIREWALL_CA_PASSPHRASE` is unset, the private key is stored as an
unencrypted `0600` PEM file. Review the MITM-specific risks in
[THREAT_MODEL.md](THREAT_MODEL.md) before enabling this mode.

## Configuration

All settings are environment variables; no configuration file is required.

| Variable | Default | Description |
|---|---|---|
| `FORWARD_API_KEY` | required | Provider key injected upstream. Use `none` to preserve client authentication headers. |
| `UPSTREAM_URL` | `https://api.anthropic.com` | Upstream provider base URL. |
| `FIREWALL_PORT` | `8080` | Explicit API proxy port. |
| `PROVIDER_HINT` | auto-detect | Optional provider adapter override. |
| `VAULT_SIZE_LIMIT` | `200` | Maximum in-memory placeholder mappings. |
| `MASK_PATHS` | `true` | Mask supported Unix and Windows paths. |
| `MASK_EMAILS` | `true` | Mask email addresses. |
| `LOG_LEVEL` | `info` | `silent`, `info`, or `debug`. |
| `MITM_ENABLED` | `false` | Enable the optional transparent proxy. |
| `MITM_PORT` | `8082` | Transparent proxy port. |
| `MITM_CERT_DIR` | `~/.ai-firewall` | Local CA certificate and key directory. |
| `AI_FIREWALL_CA_PASSPHRASE` | unset | Encrypt the persisted CA private key. |
| `ANALYTICS_OPT_IN` | `false` | Opt in to minimal release telemetry. |

Supported commands:

```text
ai-firewall                Start the proxy server.
ai-firewall demo           Run the offline synthetic masking demo.
ai-firewall install-ca     Install the local MITM CA.
ai-firewall uninstall-ca   Remove the local MITM CA.
ai-firewall version        Print the build version.
ai-firewall help           Show usage.
```

## Security

The firewall is designed to reduce accidental disclosure to an LLM provider,
not to replace endpoint security, secret scanning in CI, or provider-side data
controls.

- Read the [threat model](THREAT_MODEL.md).
- Report vulnerabilities using [SECURITY.md](SECURITY.md).
- Keep provider credentials in your normal secret-management workflow.
- Use only synthetic values in bug reports and tests.
- The local `/metrics` and `/dashboard` endpoints reject non-loopback clients.

Telemetry sends nothing unless `ANALYTICS_OPT_IN=true` and the binary is an
official release containing the telemetry build key. Self-built binaries do not
send telemetry. Prompt contents, secrets, paths, and environment values are not
telemetry fields.

## Development

### Build from source

```bash
git clone https://github.com/3mre0s/ai-firewall.git
cd ai-firewall
go build -trimpath -ldflags "-s -w" -o ai-firewall .
```

On Windows, use `-o ai-firewall.exe`.

### Run checks

```bash
go test ./...
go vet ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [ARCHITECTURE.md](ARCHITECTURE.md), and
[DEPLOYMENT.md](DEPLOYMENT.md) for contributor and deployment details.

## License

Local AI Firewall is licensed under the
[GNU Affero General Public License v3.0 or later](LICENSE). See [NOTICE](NOTICE)
for additional notices.

Commercial licensing inquiries should be sent privately through the
maintainer's GitHub profile rather than opened as a public issue.
