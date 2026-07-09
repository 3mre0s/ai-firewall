# AI Firewall — Continue Integration

A [Continue](https://continue.dev) adapter that routes every chat prompt (and,
best-effort, every completion) through the **existing AI Firewall engine** — the
same `masker` / `vault` / `patterns` packages the proxy and the Open WebUI
filter use. No detection, masking, or vault logic is duplicated; this extension
is a thin adapter in front of the real engine.

```
Continue → config.ts (CustomLLM) → POST /v1/check → masker.{Mask,Unmask,Detect} → engine
```

This is the **second official AI Firewall integration**. It was designed to the
same architectural philosophy as the first (Open WebUI Filter): the engine is
untouched, the integration is only an adapter, and every decision is delegated
over HTTP to the same `/v1/check` endpoint.

---

## 1. Architecture proposal

### 1.1 What "hooks" exist in Continue

Continue does **not** expose a separately-named "hooks" API for intercepting an
LLM request before it is sent and its response after it returns. Its
programmatic extension point is **`config.ts`**, which must export a
`modifyConfig(config)` function
([docs](https://docs.continue.dev/customize/deep-dives/configuration)).

The surface that runs *immediately before* an LLM request and streams the
response back is a **CustomLLM** pushed onto `config.models`. From Continue's
`core/index.d.ts`:

```ts
streamChat?: (
  messages: ChatMessage[],
  signal: AbortSignal,
  options: CompletionOptions,
  fetch: (input, init?) => Promise<Response>,
) => AsyncGenerator<ChatMessage | string>;

streamCompletion?: (
  prompt: string,
  signal: AbortSignal,
  options: CompletionOptions,
  fetch,
) => AsyncGenerator<string>;
```

This **is** the pre/post-LLM hook we need:

- **top of `streamChat`** = the pre-LLM hook → we `Mask()` the messages;
- **the `yield` boundary** = the post-LLM hook → we `Detect()` + `Unmask()` the
  reply.

Full streaming is possible because the return type is an `AsyncGenerator`.

### 1.2 Mapping to the desired flow

```
Continue
   │
   ▼  streamChat(messages, signal, options, fetch)     ← PRE-LLM HOOK
 ┌──────────────────────────────────────────────────┐
 │ 1. mask    POST /v1/check {direction:"inlet"}     │  engine.Mask()
 │ 2. LLM     masked request → upstream model        │
 │ 3. restore POST /v1/check {direction:"outlet"}    │  engine.Detect()+Unmask()
 └──────────────────────────────────────────────────┘
   │  yield restored reply                             ← POST-LLM HOOK
   ▼
Continue
```

Every box except the two hooks is the **existing engine**, reached through the
**existing** `POST /v1/check` adapter (`extensions/open-webui/main.go`). Nothing
in Go changes for this integration.

### 1.3 Comparison with the Open WebUI integration

| Concern              | Open WebUI (1st)                         | Continue (2nd)                              |
| -------------------- | ---------------------------------------- | ------------------------------------------- |
| Host extension point | Filter Function (`filter.py`)            | `config.ts` → `CustomLLM`                   |
| Pre-LLM hook         | `inlet(body, __user__)`                  | top of `streamChat` / `streamCompletion`    |
| Post-LLM hook        | `outlet(body, __user__)`                 | the `yield` boundary of the generator       |
| Engine call          | `POST /v1/check` (inlet / outlet)        | **same** `POST /v1/check` (inlet / outlet)  |
| Mask / Unmask / Detect | in the Go engine, never in the adapter | in the Go engine, never in the adapter      |
| Vault                | per-user, keyed by `user`                | per-user, keyed by `user` (defaults to one) |
| Restore granularity  | complete message (outlet)                | complete message (outlet) — identical       |
| Blocks on            | vault-full / raw leak                    | vault-full / raw leak — identical           |

The two integrations are the **same shape**: a host-specific glue layer
(`filter.py` / `config.ts`) that calls the identical engine endpoint. The Go
adapter binary is shared — run one, point both at it.

### 1.4 Streaming — the one stage that needs care

`streamChat` supports streaming, but the engine's **restore** step
(`Unmask` + leak `Detect`) is exposed over `/v1/check` as a **unary**
request/response. That is a deliberate match to the reference integration:
Open WebUI's `outlet()` **also** restores on the complete assistant message,
not per token. So `config.ts` buffers the reply and restores it once — behaviour
identical to the first integration.

**Why the adapter cannot do incremental restore by itself:** unmasking a stream
token-by-token requires splitting on safe boundaries so a vault label like
`[[EMAIL_6968…]]` is never cut across two chunks. That "safe cutpoint" logic is
**engine logic** and already exists as `proxy.StreamProcessor` /
`proxy.SafeCutpoint`. Re-implementing it in TypeScript would duplicate masking
logic — which this integration forbids.

**Smallest adapter layer to get true incremental streaming:** don't add one.
Route the upstream through the AI Firewall **proxy**, which already does
incremental unmask + leak fail-fast with `StreamProcessor`. Continue speaks
OpenAI to a custom `apiBase`, so this needs **zero code** — see
[`config.yaml.example`](./config.yaml.example). Two supported modes:

| Mode                    | File                  | Streaming            | Adapter logic |
| ----------------------- | --------------------- | -------------------- | ------------- |
| **Proxy passthrough**   | `config.yaml.example` | ✅ incremental        | none (apiBase)|
| **CustomLLM (`/v1/check`)** | `config.ts`        | buffered (full reply)| glue only     |

Both reuse the same engine. Proxy passthrough is recommended when you want
token-by-token streaming; the `config.ts` CustomLLM is the faithful mirror of
the Open WebUI filter and is the right choice when you want the explicit adapter
object, per-user vault selection via the `user` field, or an upstream Continue
cannot point at directly.

---

## 2. Contents

| File                  | Purpose                                                             |
| --------------------- | ------------------------------------------------------------------ |
| `config.ts`           | The Continue adapter (CustomLLM: mask → LLM → detect + restore).    |
| `config.yaml.example` | Zero-code proxy-passthrough path (full incremental streaming).      |
| `README.md`           | This file.                                                         |

---

## 3. Setup — CustomLLM adapter (`config.ts`)

### 3.1 Run the engine adapter

The `config.ts` adapter talks to the **same** `/v1/check` Go adapter the Open
WebUI integration uses. Run it once (the shared config loader requires
`FORWARD_API_KEY`, though this adapter never forwards upstream — set it to
`none`):

```bash
cd extensions/open-webui
FORWARD_API_KEY=none go run .
# → AI Firewall /v1/check adapter listening on :8080
```

### 3.2 Install `config.ts`

Copy `config.ts` to your Continue config directory:

- macOS / Linux: `~/.continue/config.ts`
- Windows: `%USERPROFILE%\.continue\config.ts`

If you already have a `config.ts`, merge its `modifyConfig` body (call
`config.models.push(...)` with the CustomLLM from this file).

### 3.3 Configure via environment variables

The adapter reads these from the environment (all optional, safe defaults):

| Env var                    | Default                     | Meaning                                                         |
| -------------------------- | --------------------------- | -------------------------------------------------------------- |
| `AI_FIREWALL_CHECK_URL`    | `http://localhost:8080`     | Base URL of the `/v1/check` Go adapter.                        |
| `AI_FIREWALL_UPSTREAM_URL` | `https://api.openai.com/v1` | OpenAI-compatible upstream the **masked** request is sent to.  |
| `AI_FIREWALL_UPSTREAM_KEY` | `$OPENAI_API_KEY`           | Bearer key for the upstream LLM.                               |
| `AI_FIREWALL_MODEL`        | `gpt-4o`                    | Default model id.                                             |
| `AI_FIREWALL_TITLE`        | `AI Firewall (Guarded)`     | Title in Continue's model picker.                             |
| `AI_FIREWALL_USER`         | `continue-local`            | Stable id selecting this caller's isolated vault.            |
| `AI_FIREWALL_TIMEOUT_MS`   | `5000`                      | Max wait for the firewall to answer.                          |
| `AI_FIREWALL_FAIL_OPEN`    | `false`                     | `false` = block if firewall down (safe); `true` = send unmasked. |

Restart Continue (or reload the window) after editing `config.ts`. Pick the
model titled **AI Firewall (Guarded)** in Continue's model dropdown.

> **`FAIL_OPEN`** — `false` (default, fail CLOSED): if the engine is unreachable,
> the request is blocked; no traffic bypasses the firewall. `true` (fail OPEN):
> if the engine is down the request is sent **unmasked**.

---

## 4. Setup — proxy passthrough (streaming, zero code)

See [`config.yaml.example`](./config.yaml.example). Start the proxy pointed at
your real provider, then point Continue's `apiBase` at the proxy. The engine
masks the request and stream-unmasks the response with full incremental
streaming — no `config.ts` needed.

---

## 5. What kind of firewall this is

The engine is a **masking** firewall, not a content-category blocker. Its native
action is **mask & allow**: sensitive values (API keys, tokens, PEM keys,
passwords, PII such as e-mail / IBAN / national IDs, file paths) are replaced
with vault placeholders like `[[EMAIL_6968…]]` before the model ever sees them.

It **blocks** in exactly these cases (identical to the Open WebUI integration):

| Reason code                 | When                                                                        |
| --------------------------- | --------------------------------------------------------------------------- |
| `masking_failed_vault_full` | A secret was detected but the vault was full, so it could not be masked (fail-closed). |
| `secret_leak_in_output`     | The model's reply contains a **raw** secret that never went through masking. |
| `missing_user_identifier`   | The request omitted `user` (this adapter always sends one).                  |
| `vault_capacity_exceeded`   | `VAULT_MAX_USERS` isolated vaults already exist (fail-closed).               |

There is **no prompt-injection detector** in this engine, so this adapter does
not invent one.

---

## 6. Known limitations

- **Buffered restore in `config.ts` mode** — the reply is restored on completion,
  not per token (same as Open WebUI's `outlet`). Use proxy passthrough for
  incremental streaming.
- **OpenAI-compatible upstream** — `config.ts` builds an OpenAI
  `/chat/completions` request. For non-OpenAI providers, point
  `AI_FIREWALL_UPSTREAM_URL` at an OpenAI-compatible gateway, or use proxy
  passthrough with the firewall's provider adapters.
- **Single vault process** — vault state is in-process; run one adapter instance
  (see the Open WebUI README's per-user isolation notes).
