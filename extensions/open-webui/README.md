# AI Firewall — Open WebUI Filter

An [Open WebUI](https://docs.openwebui.com/) **Filter Function** that routes
every chat prompt (and, best-effort, every model reply) through the **existing
AI Firewall engine** — the same `masker` / `vault` / `patterns` packages the
proxy uses. No detection or masking logic is duplicated; this extension is a
thin HTTP adapter in front of the real engine.

```
Open WebUI → filter.py → POST /v1/check → masker.{Mask,Unmask,Detect} → JSON
```

## Architecture

This directory is a thin adapter that puts the existing AI Firewall engine
behind an Open WebUI Filter Function. The Python filter (`filter.py`) calls
`POST /v1/check`; the Go handler (`main.go`) unmarshals that request, calls the
engine's existing public API (`Mask` / `Unmask` / `Detect`), and marshals the
verdict back. It has no detection, masking, or restoration logic of its own —
all of that lives in the core `masker`, `vault`, `patterns`, and `config`
packages and is shared unchanged with the proxy. If you are reviewing what this
integration does to the engine, the answer is: nothing; it only routes traffic
to it. See [How it works](#how-it-works) for the request paths.

The one substantive design decision is per-user vault isolation. The engine was
originally built around a single process-wide vault, which in a multi-user
Open WebUI deployment means one user's masked value could be restored into
another user's response if a placeholder label crossed sessions (e.g. via shared
RAG context). The adapter gives each caller — keyed by the `user` field the
filter sends — its own `masker`+`vault` pair, with idle eviction
(`VAULT_IDLE_TTL`) and a registry cap (`VAULT_MAX_USERS`); both a missing `user`
and an exceeded cap fail closed. See
[Per-user vault isolation](#per-user-vault-isolation).

The tunable that matters for capacity planning is the product
`VAULT_MAX_USERS × VAULT_SIZE_LIMIT`, which sets the memory ceiling: each user's
vault pre-allocates a map sized to `VAULT_SIZE_LIMIT`, so per-user cost is driven
by that limit, not by how much a user actually masks. The engine does not
deduplicate a value across separate requests, so a long session grows the vault
by total masking operations, not distinct secrets. The defaults
(`VAULT_MAX_USERS=10000`, `VAULT_SIZE_LIMIT=200`) come from load-test
measurements (~105 MB heap at 10k users), not estimates; raising
`VAULT_SIZE_LIMIT` buys per-session headroom at a linear memory cost. See
[Load Testing](#load-testing).

### Known limitations

- **Single-instance only** — vault state is in-process and does not sync across
  replicas; use sticky sessions if running multiple instances.
- **Registry mutex** — the per-user registry is guarded by one mutex; contention
  is acceptable at ~10k users (per load testing) but may need sharding at much
  higher concurrency.
- **Masking-only** — there is no prompt-injection or content-policy detection;
  requests are blocked only on vault-full (fail-closed) or a raw secret leaked in
  model output.
- **`-race` not verified here** — the race detector needs cgo, which is
  unavailable on this Windows box; run it on Linux CI to confirm the registry is
  race-free.

## Per-user vault isolation

Each Open WebUI user gets their **own** masker + vault pair, keyed by the `user`
field the filter sends in every `/v1/check` request. One user's masked values
can therefore never be restored in another user's context — even if the exact
placeholder label string is replayed across users (e.g. via shared RAG
context), the other user's vault simply does not contain it, so nothing is
restored. This isolation lives entirely in the adapter; the core engine
packages are unchanged.

- **Missing `user`:** the adapter **rejects** the request with HTTP 400 and
  `reason: "missing_user_identifier"` rather than pooling secrets into a shared
  bucket. `filter.py` always sends a `user` (it falls back to `"anonymous"` for
  unauthenticated sessions, so those share one bucket), so this only affects
  direct/raw callers that omit the field.
- **Memory bounds:** idle vaults are evicted after `VAULT_IDLE_TTL`, and the
  number of concurrent user vaults is capped at `VAULT_MAX_USERS`. Exceeding the
  cap fails **closed** (`reason: "vault_capacity_exceeded"`) — without a vault we
  cannot mask, and passing traffic through unmasked would defeat the firewall.

> **Known limitation (not fixed here):** isolation and vault state are
> **per-process**. If AI Firewall is run as multiple replicas/instances behind a
> load balancer, vault state does **not** sync across them — a value masked by
> instance A cannot be restored by instance B. Run a single adapter instance, or
> pin each user to one instance (sticky sessions), until cross-instance vault
> sharing is added.

## What kind of firewall this is

The engine is a **masking** firewall, not a content-category blocker. Its native
action is **mask & allow**: sensitive values (API keys, tokens, PEM keys,
passwords, PII such as e-mail / IBAN / national IDs, file paths) are replaced
with vault placeholders like `[[EMAIL_6968…]]` before the model ever sees them.

It **blocks** in exactly two cases:

| Reason code                 | When                                                                  |
| --------------------------- | --------------------------------------------------------------------- |
| `masking_failed_vault_full` | A secret was detected but the vault was full, so it could not be masked (fail-closed — same as the proxy's HTTP 507). |
| `secret_leak_in_output`     | The model's reply contains a **raw** secret that never went through masking (defence-in-depth, same as the proxy's streaming fail-fast). |
| `missing_user_identifier`   | The request omitted the `user` field, so the caller's isolated vault cannot be selected (returned with HTTP 400). |
| `vault_capacity_exceeded`   | A new user could not be admitted because `VAULT_MAX_USERS` isolated vaults already exist (fail-closed). |

There is **no prompt-injection detector** in this engine, so this adapter does
not invent one.

## Contents

| File           | Purpose                                                                |
| -------------- | ---------------------------------------------------------------------- |
| `filter.py`    | The Open WebUI Filter Function (inlet/outlet adapter).                 |
| `main.go`      | Thin HTTP adapter exposing the real engine at `POST /v1/check`.        |
| `main_test.go` | Tests for the adapter (allowed / masked / blocked / restore).          |

---

## 1. Run the Go firewall adapter

The adapter reuses the engine's canonical config loader, so it honours the same
environment variables as the rest of the firewall (`MASK_EMAILS`, `MASK_PATHS`,
`VAULT_SIZE_LIMIT`, `FIREWALL_PORT`, `LOG_LEVEL`, …), plus two adapter-only
knobs for per-user isolation:

| Env var           | Default | Meaning                                                                 |
| ----------------- | ------- | ----------------------------------------------------------------------- |
| `VAULT_IDLE_TTL`  | `30m`   | Idle duration after which a user's vault is evicted (Go duration, e.g. `45m`, `2h`). |
| `VAULT_MAX_USERS` | `10000` | Max concurrent per-user vaults; new users past this fail closed.        |

> The shared config loader requires `FORWARD_API_KEY`. This adapter never
> forwards anything upstream, so set it to `none`.

```bash
cd extensions/open-webui
FORWARD_API_KEY=none go run .
# → AI Firewall /v1/check adapter listening on :8080 (mask_emails=true mask_paths=true vault_limit=1000)
```

Override the port or toggles as needed:

```bash
FIREWALL_PORT=8091 MASK_EMAILS=true VAULT_SIZE_LIMIT=5000 FORWARD_API_KEY=none go run .
```

Quick sanity check:

```bash
curl -s http://localhost:8080/v1/check \
  -H 'Content-Type: application/json' \
  -d '{"content":"mail me at alice@example.com","direction":"inlet"}'
# → {"allowed":true,"masked_content":"mail me at [[EMAIL_…]]","matches":[{"type":"pii","rule":"E-mail Address …","count":1}]}
```

---

## 2. Load `filter.py` into Open WebUI

1. Open Open WebUI and sign in as an **admin**.
2. Go to **Admin Panel → Functions**.
3. Click **`+` (Add Function)**.
4. Give it a name (e.g. *AI Firewall Guard*), then paste the entire contents of
   `filter.py` into the editor. (The `title`, `author`, and `version` come from
   the docstring at the top of the file.)
5. Click **Save**, then toggle the function **On**.

> **Requirement:** Open WebUI `0.3.9` or newer.

---

## 3. Configure the Valves (Admin Panel)

After saving the function, click its **valve/gear icon**:

| Valve             | Default                 | Meaning                                                                        |
| ----------------- | ----------------------- | ------------------------------------------------------------------------------ |
| `GO_FIREWALL_URL` | `http://localhost:8080` | Base URL of the Go adapter (must match `FIREWALL_PORT`).                        |
| `TIMEOUT_SECONDS` | `5`                     | Max time to wait for the engine to answer.                                     |
| `FAIL_OPEN`       | `false`                 | What to do if the engine is unreachable (see below).                           |
| `priority`        | `0`                     | Filter order; lower runs first. `0` makes this run before other filters.       |

### `FAIL_OPEN`

- **`false` (default, fail CLOSED):** if the engine can't be reached, the request
  is **blocked**. Safer — no traffic bypasses the firewall.
- **`true` (fail OPEN):** if the engine is down, the request is **allowed**
  through unmodified (no masking possible during the outage).

> **Docker note:** if Open WebUI runs in a container and the adapter runs on your
> host, use `http://host.docker.internal:8080` (Docker Desktop) or the adapter
> container's service name — `localhost` inside the container is not your host.

---

## 4. Enable it everywhere (`is_global`)

To enforce the firewall across **every** model: **Admin Panel → Functions**,
find the function, and toggle **Global** on. Open WebUI then applies it to all
chats automatically.

---

## How it works

- **`inlet(body, __user__)`** runs **before** the model. It sends the latest user
  message with `direction: "inlet"`, and if the engine returns `masked_content`,
  it **substitutes the masked text** into the message so the model never sees the
  raw secrets. It raises (blocking the chat) only on `allowed:false`.
- **`outlet(body, __user__)`** runs **after** the model with `direction:"outlet"`.
  The engine (a) blocks if the reply contains a raw unmasked secret, and (b)
  returns `restored_content` — the reply with any vault labels the model echoed
  back replaced by their **original** values — which the filter substitutes so
  the user sees real data. ⚠️ `outlet` fires reliably for chats through the Open
  WebUI frontend but may **not** trigger for direct/raw OpenAI-compatible API
  calls or some streaming paths; rely on `inlet` for enforcement.

### Why restoration lives in Go

Restoration (`Unmask`) **must** run inside the engine: the label→original map is
held in the engine's in-memory **vault** and is never exposed to Python. The
filter only substitutes the `restored_content` string the engine returns. This
requires the **same adapter process** (one shared vault) to serve both the inlet
mask and the outlet restore for a conversation — which it does, as a single
long-lived service.

### The `/v1/check` contract

Request:

```json
{ "content": "the message text", "user": "user-id", "direction": "inlet" }
```

`direction` is `"inlet"` (default) or `"outlet"`.

Response — allowed (inlet):

```json
{
  "allowed": true,
  "masked_content": "mail me at [[EMAIL_…]]",
  "matches": [ { "type": "pii", "rule": "E-mail Address …", "count": 1 } ]
}
```

Response — allowed (outlet, restored):

```json
{ "allowed": true, "restored_content": "mail me at alice@example.com", "matches": [] }
```

Response — blocked:

```json
{ "allowed": false, "reason": "secret_leak_in_output", "matches": [ … ] }
```

- `reason` is always a machine-readable snake_case code, never a sentence.
- `matches` is always present (`[]` when nothing was found); it reports the
  category and rule name, never the sensitive value itself.
- `masked_content` / `restored_content` are only present when the text changed.

---

## Testing

```bash
go test ./extensions/open-webui/...   # adapter: allowed / masked / blocked / restore
go test ./...                         # full suite — the engine refactor is additive
```

---

## Load Testing

`load_test.go` measures the memory and latency behaviour of the per-user vault
registry. It hosts the **real** `/v1/check` handler behind an in-process
`httptest.Server` (real HTTP over loopback), so it exercises the production code
path as a black box while still being able to read the adapter's Go heap and
inject a clock for the eviction scenario. It is **skipped by default** so the
normal suite stays fast, and it asserts only correctness (capacity fail-closed,
eviction count) — never memory/latency thresholds.

```bash
# Full measurement run (steady, concurrent, capacity, idle-eviction):
AIFW_LOADTEST=1 go test ./extensions/open-webui/ -run TestLoadVaultRegistry -v -timeout 20m

# With the race detector (needs a C compiler — cgo; e.g. gcc/mingw or Linux CI):
CGO_ENABLED=1 AIFW_LOADTEST=1 go test ./extensions/open-webui/ -run TestLoadVaultRegistry -race -timeout 30m
```

**Memory methodology:** the reported numbers are the **Go heap**
(`runtime.MemStats.HeapAlloc`, sampled after a forced GC), which is the live
object set — **not** OS RSS. Real RSS is higher (heap spans, fragmentation, the
GC letting the heap grow to ~2× the live set between collections, goroutine
stacks). OS RSS is captured via `/proc/self/status` on Linux only; on other
platforms the test notes it is unsupported and reports Go-heap numbers.

**Key finding:** per-user memory is dominated by the vault's pre-sized map
(`vault.New` allocates `make(map, VAULT_SIZE_LIMIT)`), so it scales with
`VAULT_SIZE_LIMIT`, *not* with how much a user actually masks. The worst-case
registry footprint is roughly:

```
heap ≈ VAULT_MAX_USERS × per_user(VAULT_SIZE_LIMIT)
```

`VAULT_SIZE_LIMIT` now bounds **per-user** secret capacity (each user has their
own vault — it is no longer a single global cap); a user who masks more distinct
values than this within a session will see `masking_failed_vault_full` and
should raise the limit — tune it per deployment size (higher for heavy sessions,
lower for tiny VMs). Because the vault does not deduplicate a value across
separate requests, a long conversation grows the vault by masked-values-per-
message, so the default was chosen to leave headroom before that limit is hit.

Measured empty-vault per-user cost: ~7 KB at `VAULT_SIZE_LIMIT=100`, ~10 KB at
`200` (the default), ~57 KB at `1000`, ~217 KB at `5000`. At the defaults
(`VAULT_MAX_USERS=10000`, `VAULT_SIZE_LIMIT=200`) the measured peak with a
realistic one-email-one-token payload per user is:

| Scenario (10000 users) | Total   | Avg    | p95     | p99     | Heap Δ   | Per-user |
| ---------------------- | ------- | ------ | ------- | ------- | -------- | -------- |
| a) steady (sequential) | ~2.5 s  | ~240µs | ~1.0 ms | ~1.5 ms | ~105 MB  | ~10.7 KB |
| b) concurrent (100 wk) | ~0.62 s | ~6.2ms | ~10 ms  | ~15 ms  | ~108 MB  | ~11.0 KB |

Idle eviction reclaims essentially all of it (~104 MB, `size 10000→1`). Size the
two knobs together against the target VM's RAM. (Lowering `VAULT_SIZE_LIMIT` to
`100` would nearly halve the footprint to ~70 MB but roughly halves per-user
secret headroom.)

---

## Troubleshooting

| Symptom                             | Likely cause / fix                                                                    |
| ----------------------------------- | ------------------------------------------------------------------------------------- |
| `FORWARD_API_KEY is required`       | Set `FORWARD_API_KEY=none` — the shared loader requires it though the adapter ignores it. |
| Every request is blocked            | Engine unreachable + `FAIL_OPEN=false`. Check `GO_FIREWALL_URL` and that the adapter runs. |
| User sees `[[EMAIL_…]]` labels      | `outlet` didn't fire (direct API call / streaming). Expected — restoration is best-effort. |
| `masking_failed_vault_full` blocks  | Vault at capacity. Raise `VAULT_SIZE_LIMIT` or restart the adapter to clear the vault.   |
| `localhost` fails from a container  | Use `host.docker.internal` or the service name (see Docker note above).                |
