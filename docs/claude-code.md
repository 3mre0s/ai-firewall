# Claude Code setup

Local AI Firewall reduces the chance that Claude Code sends detected API keys,
credentials, `.env` values, file paths, or personal data in a request body. It
runs locally, masks supported values before forwarding, and restores its
placeholders in the response.

> Never paste a real secret, token, customer record, or private repository
> content into a test. Use synthetic values only.

## Prerequisites

- Go 1.22 or later, unless you downloaded a release binary
- Claude Code installed and authenticated
- A free local port `8080`, or a different `FIREWALL_PORT`

## Install

```bash
git clone https://github.com/3mre0s/ai-firewall.git
cd ai-firewall
go build -trimpath -ldflags "-s -w" -o ai-firewall .
./ai-firewall version
```

On Windows, build with `-o ai-firewall.exe` and run
`./ai-firewall.exe version`.

## Happy path: subscription authentication

Claude Code Pro/Max can keep using its own subscription token. Start the
firewall in one terminal:

```bash
export FORWARD_API_KEY=none
ai-firewall
```

Then start Claude Code in a second terminal:

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
claude
```

With `FORWARD_API_KEY=none`, the firewall does not inject an API key. The
client's existing `Authorization` header passes through unchanged.

## Anthropic API key authentication

If Claude Code is using an Anthropic API key, load that key through your normal
secret manager or shell setup, then let the firewall inject it upstream:

```bash
export FORWARD_API_KEY="$ANTHROPIC_API_KEY"
ai-firewall
```

In the Claude Code terminal:

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
claude
```

Do not put a real key directly into documentation, screenshots, shell history,
or issue reports.

## Synthetic test

Use a new disposable conversation and send only fake values:

```text
Repeat these values exactly:
OPENAI_API_KEY=sk-test-not-a-real-key-000000
EMAIL=developer@example.com
FILE=/Users/example/project/.env
```

This connected test reaches your configured provider, but the values are
synthetic. To see masking without starting Claude Code, loading configuration,
or contacting any provider, run:

```bash
ai-firewall demo
```

The offline demo uses bundled fake values and discards its in-memory vault when
the command exits.

## Verify masking

Start the firewall with the default `LOG_LEVEL=info`. During the synthetic
request, its terminal should report masking activity without printing the
original values. The response should contain the original synthetic text after
local placeholder restoration.

You can also open `http://localhost:8080/dashboard` locally and confirm that
mask counters increased. The dashboard is loopback-only.

Do not treat one successful test as proof that every secret format is covered.
Detection is pattern-based.

## Stop and undo

Stop Claude Code, then press `Ctrl+C` in the firewall terminal. A graceful
shutdown clears the in-memory vault.

Undo the environment changes in each shell where you set them:

```bash
unset ANTHROPIC_BASE_URL
unset FORWARD_API_KEY
```

If you also changed optional settings, unset those variables as well:

```bash
unset UPSTREAM_URL FIREWALL_PORT PROVIDER_HINT
```

PowerShell equivalents:

```powershell
Remove-Item Env:ANTHROPIC_BASE_URL -ErrorAction SilentlyContinue
Remove-Item Env:FORWARD_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:UPSTREAM_URL -ErrorAction SilentlyContinue
Remove-Item Env:FIREWALL_PORT -ErrorAction SilentlyContinue
Remove-Item Env:PROVIDER_HINT -ErrorAction SilentlyContinue
```

Explicit proxy mode does not install a CA, so there is no trust-store change to
undo.

## Troubleshooting

### `FORWARD_API_KEY is required but not set`

Set `FORWARD_API_KEY=none` for Claude subscription-token passthrough, or set it
from your existing `ANTHROPIC_API_KEY` environment variable.

### Claude Code still connects directly

Set `ANTHROPIC_BASE_URL` in the same terminal that launches `claude`. Confirm it
is exactly `http://localhost:8080` unless you changed `FIREWALL_PORT`.

### Port 8080 is already in use

Choose another port in both terminals:

```bash
export FIREWALL_PORT=8181
export FORWARD_API_KEY=none
ai-firewall
```

```bash
export ANTHROPIC_BASE_URL=http://localhost:8181
claude
```

### Authentication fails

- Subscription users: confirm Claude Code is already authenticated and
  `FORWARD_API_KEY=none`.
- API-key users: confirm `ANTHROPIC_API_KEY` exists in the firewall terminal
  before assigning it to `FORWARD_API_KEY`.
- Do not set `UPSTREAM_URL` unless you intentionally use another endpoint.

### A value was missed or masked incorrectly

Read the [limitations](../README.md#limitations). Report only a synthetic value
with the same format using the repository's issue forms. Never include the
original value or private surrounding context.

## Optional transparent mode

Transparent MITM mode is not required for Claude Code and changes the local
trust model by installing a CA. Review the
[advanced README section](../README.md#advanced-transparent-mitm-mode) and
[threat model](../THREAT_MODEL.md) before using it.
