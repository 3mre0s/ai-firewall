# AI Firewall — Cline Integration

A setup guide for [Cline](https://github.com/cline/cline) (VS Code AI coding
agent) that routes every chat request through the **existing AI Firewall
proxy** — the same `masker` / `vault` / `StreamProcessor` pipeline that the
proxy-passthrough path for Continue (`config.yaml.example`) and all other
OpenAI-compatible clients use. No adapter code, no custom plugin — Cline just
speaks OpenAI to the proxy's Base URL, and the engine does everything.

```
Cline → POST /v1/chat/completions → AI Firewall proxy :8080 → Mask() → upstream LLM → StreamProcessor.Unmask() → Cline
```

---

## Why this works with zero code

Unlike Open WebUI (which has Filter hooks) or Continue (which offers a
`config.ts` CustomLLM), Cline has **no plugin or hook system**. Its only
integration point is the **"OpenAI Compatible" API Provider** setting: a
Base URL, an API Key, and a Model ID.

That is exactly what the AI Firewall proxy already supports. The proxy is
**schema-agnostic** — it never parses the `{model, messages, stream, …}`
JSON body. It treats the entire request body as an opaque string for masking,
forwards it to the upstream provider, and stream-unmasks the response
token-by-token via `StreamProcessor` (safe-cutpoint incremental unmask +
raw-secret leak fail-fast). The proxy's catch-all route (`mux.Handle("/",
firewallSrv)` in `main.go`) accepts any POST path, including
`/v1/chat/completions`.

This is the **same mechanism** Continue's zero-code proxy path already uses
(`apiBase: http://localhost:8080/v1` in `config.yaml.example`), and Cline
connects identically.

### Comparison with the other integrations

| Concern              | Open WebUI              | Continue (`config.ts`)    | Continue (proxy)       | **Cline (this guide)** |
| -------------------- | ----------------------- | ------------------------- | ---------------------- | ---------------------- |
| Host extension point | Filter (`filter.py`)    | `config.ts` (CustomLLM)  | `config.yaml` apiBase  | VS Code settings GUI   |
| Adapter code         | `filter.py` + `main.go` | `config.ts`              | none                   | **none**               |
| Engine path          | `/v1/check` adapter     | `/v1/check` adapter       | proxy catch-all `/`    | proxy catch-all `/`    |
| Streaming            | buffered (outlet)       | buffered (outlet)         | ✅ incremental (SSE)    | ✅ incremental (SSE)    |

---

## Contents

| File        | Purpose                                             |
| ----------- | --------------------------------------------------- |
| `README.md` | This file — setup guide and verification steps.     |

No code files are needed. Configuration is entered directly in Cline's
VS Code settings UI.

---

## 1. Prerequisites

### 1.1 AI Firewall proxy running

Start the proxy pointed at your upstream provider. See the
[root README](../../README.md) and [ARCHITECTURE.md](../../ARCHITECTURE.md)
for full details.

**Example — OpenAI upstream:**

```bash
UPSTREAM_URL=https://api.openai.com \
FORWARD_API_KEY=sk-your-real-openai-key \
FIREWALL_PORT=8080 \
./ai-firewall
```

**Example — Anthropic upstream (via OpenAI-compatible routing):**

```bash
UPSTREAM_URL=https://api.anthropic.com \
FORWARD_API_KEY=sk-ant-api03-your-key \
PROVIDER_HINT=anthropic \
FIREWALL_PORT=8080 \
./ai-firewall
```

**Example — local Ollama:**

```bash
UPSTREAM_URL=http://localhost:11434 \
FORWARD_API_KEY=none \
FIREWALL_PORT=8080 \
./ai-firewall
```

Verify the proxy is running:

```bash
curl http://localhost:8080/health
# → {"status":"ok"}
```

### 1.2 Cline extension installed

Install [Cline](https://marketplace.visualstudio.com/items?itemName=saoudrizwan.claude-dev)
from the VS Code Marketplace if you haven't already.

---

## 2. Configure Cline

1. Open the Cline panel in VS Code.
2. Click the **gear (⚙️) icon** to open Cline's settings.
3. Set the **API Provider** to **"OpenAI Compatible"**.
4. Fill in the three required fields:

| Cline field   | Value                                | Notes                                                                 |
| ------------- | ------------------------------------ | --------------------------------------------------------------------- |
| **Base URL**  | `http://localhost:8080/v1`           | `8080` is the default `FIREWALL_PORT` — adjust if you changed it.     |
| **API Key**   | `cline-firewall-placeholder`         | Any non-empty string. The proxy replaces it with `FORWARD_API_KEY`.   |
| **Model ID**  | `gpt-4o`                            | Use whatever model your upstream supports (e.g. `claude-sonnet-4-20250514`, `llama3`). |

5. Click **Save** or close the settings panel.

That's it. Every request Cline makes will now flow through the firewall.

> **Port note:** the default `FIREWALL_PORT` is `8080` (see `.env.example`
> and `config/config.go`). If you changed it, update the Base URL
> accordingly — e.g. `http://localhost:9090/v1` for `FIREWALL_PORT=9090`.

> **API Key note:** the value you enter in Cline's API Key field does not
> matter (it can be any non-empty string). The proxy strips it and injects
> the real upstream key from `FORWARD_API_KEY`. If `FORWARD_API_KEY=none`
> (passthrough mode, e.g. for Ollama), Cline's own key flows through
> unchanged — enter `none` or any placeholder.

---

## 3. Verified behaviour

This integration was live-verified end-to-end with the test suite in
`proxy/cline_integration_test.go`. The tests simulate the exact request/response
shapes Cline's "OpenAI Compatible" provider sends, against a mock upstream.
All 5 tests pass (`go test ./proxy/ -run TestClineE2E -v`):

### 3.1 Non-streaming — multi-secret masking & round-trip restore

**Test:** `TestClineE2E_NonStreaming_MultiSecret`

Sends an OpenAI-schema request containing an email (`alice@secretcorp.com`)
and an AWS key (`AKIAIOSFODNN7EXAMPLE`) to `POST /v1/chat/completions`.
The mock upstream echoes the masked body in an OpenAI chat completion response.

**Result (PASS):**

```
✅ PASS — non-streaming multi-secret round-trip
   upstream saw (masked):  ...[[EMAIL_...]]...[[AWS_...]]...
   client received (restored): alice@secretcorp.com and AKIAIOSFODNN7EXAMPLE present
   vault entries: 2
```

- Upstream never received the raw email or AWS key — only vault labels.
- Client response contained both original secrets, fully restored.
- No vault labels leaked to the client.

### 3.2 SSE streaming — mask request, incremental unmask response

**Test:** `TestClineE2E_Streaming_MaskAndRestore`

Sends a streaming request (`"stream": true`) with an email and AWS key.
The mock upstream returns OpenAI-format SSE delta chunks containing the
vault labels. `StreamProcessor` unmasks them incrementally.

**Result (PASS):**

```
✅ PASS — streaming multi-secret round-trip (SSE delta format)
   upstream saw masked labels, client received restored secrets
   SSE framing preserved with [DONE] sentinel
```

- Upstream received masked request body.
- Client received restored secrets in SSE delta chunks.
- `Content-Type: text/event-stream` preserved, `[DONE]` sentinel intact.

### 3.3 SSE streaming — leak detection (fail-fast)

**Test:** `TestClineE2E_Streaming_LeakDetection`

The mock upstream injects a raw secret (`sk-proj-LEAKED_KEY_NEVER_MASKED_123456`)
that was **never routed through the masking pipeline** — simulating the LLM
"hallucinating" a real API key.

**Result (PASS):**

```
🚨 secret detected in stream output — terminating
✅ PASS — streaming leak detection (fail-fast)
   raw secret not delivered to client: confirmed
   stream terminated before secret chunk
```

- The fail-fast mechanism detected the raw secret and terminated the stream.
- The leaked key never reached the client.

### 3.4 GET /v1/models passthrough

**Test:** `TestClineE2E_GetModels`

Sends `GET /v1/models` — now forwarded to the upstream instead of returning 405.

**Result (PASS):**

```
✅ PASS — GET /v1/models forwarded to upstream (was 405 before fix)
   returned 214 bytes of model list JSON
```

### 3.5 Other GET paths still return 405

**Test:** `TestClineE2E_GetOtherPath_Still405`

Confirms that `GET /v1/chat/completions` (and any other non-models GET) is
still rejected with 405 — the models passthrough is scoped, not a blanket
GET allow.

**Result (PASS):**

```
✅ PASS — GET to non-models path correctly returns 405
```

### Running verification yourself

```bash
go test ./proxy/ -run TestClineE2E -v -count=1
```

---

## 4. Known limitations

- **`GET /v1/models` is forwarded to upstream** — the proxy passes
  `GET /v1/models` through to the upstream provider so clients can discover
  available models.  If the upstream does not support this endpoint (e.g.
  Anthropic), its error response will propagate as-is.  All other GET requests
  remain rejected with 405.

- **Anthropic-native endpoints** — if `UPSTREAM_URL` points to Anthropic
  (`https://api.anthropic.com`), the upstream expects requests at
  `/v1/messages` with Anthropic's schema, not `/v1/chat/completions` with
  OpenAI's schema. Cline sends OpenAI-format requests, so you need an
  OpenAI-compatible upstream (OpenAI, Groq, Together, Ollama, etc.) or an
  OpenAI-to-Anthropic translation proxy in front. The firewall itself is
  agnostic — it forwards whatever Cline sends — but Anthropic's API will
  reject an OpenAI-shaped request body.

- **Single vault process** — vault state is in-process and does not sync
  across replicas. See the Open WebUI README's per-user isolation notes for
  capacity planning.

- **Masking-only** — the engine is a masking firewall, not a content-category
  blocker. It masks secrets and PII (API keys, tokens, PEM keys, e-mail, file
  paths, etc.) and blocks only on vault-full or raw-secret leak in model
  output. There is no prompt-injection detection.

---

## Troubleshooting

| Symptom                              | Likely cause / fix                                                                      |
| ------------------------------------ | --------------------------------------------------------------------------------------- |
| Cline shows "connection refused"     | Proxy not running. Start it with the commands in §1.1.                                  |
| Cline shows "401 Unauthorized"       | Upstream rejected the API key. Check that `FORWARD_API_KEY` is a valid key for your provider. |
| Response contains `[[EMAIL_…]]` labels | Vault label not unmasked — likely the proxy was restarted mid-conversation (vault cleared). Start a new chat. |
| `FORWARD_API_KEY is required`        | Set `FORWARD_API_KEY` when starting the proxy (or `none` for passthrough mode).          |
| Upstream returns "invalid request"   | Schema mismatch — Cline sends OpenAI format; make sure `UPSTREAM_URL` points to an OpenAI-compatible API (see §4). |
| Firewall log shows no masking        | The message didn't contain a recognised secret pattern. Try an email or API key pattern. |
