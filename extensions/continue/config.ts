// ===========================================================================
// AI Firewall — Continue adapter (config.ts)
// ===========================================================================
//
// This is a *thin* Continue adapter. It contains NO detection, masking, or
// vault logic of its own. Every decision is delegated to the existing Go
// AI Firewall engine over HTTP — the exact same `POST /v1/check` endpoint the
// Open WebUI Filter (`extensions/open-webui/filter.py`) uses:
//
//     Continue --(POST /v1/check)--> Go AI Firewall --> masker.{Mask,Unmask,Detect}
//
// Continue's programmatic extension point is `config.ts`, which must export a
// `modifyConfig(config)` function. Continue has no separately-named "hooks"
// system; the surface that runs immediately before an LLM request and streams
// the response back is a **CustomLLM** pushed onto `config.models`. Its
// `streamChat` / `streamCompletion` async generators are exactly the pre-LLM
// and post-LLM hook we need:
//
//     Continue
//        │
//        ▼  streamChat(messages, signal, options, fetch)   ← PRE-LLM HOOK
//     ┌──────────────────────────────────────────────┐
//     │ 1. mask   → POST /v1/check {direction:"inlet"}│  engine.Mask()
//     │ 2. call the real upstream LLM (masked)        │
//     │ 3. restore→ POST /v1/check {direction:"outlet"}│ engine.Detect()+Unmask()
//     └──────────────────────────────────────────────┘
//        │  yield restored chunks                          ← POST-LLM HOOK
//        ▼
//     Continue
//
// The engine is a *masking* firewall: its native action is "mask & allow". It
// only blocks (fail-closed) when a detected value cannot be masked (vault full)
// or when the model's reply leaks a raw, unmasked secret — identical to the
// Open WebUI integration. There is no prompt-injection detector, so this
// adapter does not invent one.
//
// -------------------------------------------------------------------------
// Streaming note (read this):
//   `/v1/check` is a UNARY request/response endpoint, so this adapter restores
//   the reply on the COMPLETE assistant message — exactly like the Open WebUI
//   `outlet()` hook, which also runs on the full message, not per token. For
//   TRUE incremental streaming restore (unmasking token-by-token as they
//   arrive), route the upstream through the AI Firewall *proxy* instead: its
//   `StreamProcessor` already does safe-cutpoint incremental unmasking + leak
//   fail-fast. See `config.yaml.example` and the README ("Streaming"). Both
//   paths reuse the same engine; neither duplicates masking logic here.
// ===========================================================================

// These types mirror Continue's `core/index.d.ts`. They are declared locally
// so the file type-checks even when Continue's types are not on the path;
// Continue passes real values at runtime.
type ChatMessageRole = "user" | "assistant" | "system" | "tool" | "thinking";
interface ChatMessage {
  role: ChatMessageRole;
  content: any; // string | multimodal parts — see contentToText/replaceText
  [k: string]: any;
}
interface CompletionOptions {
  model: string;
  temperature?: number;
  topP?: number;
  maxTokens?: number;
  stop?: string[];
  [k: string]: any;
}
type FetchFn = (input: any, init?: any) => Promise<any>;
interface Config {
  models: any[];
  [k: string]: any;
}

// ---------------------------------------------------------------------------
// Settings — read from environment variables (Continue evaluates config.ts in
// the extension host, so process.env is available). Every knob has a safe
// default so a bare install works against a local firewall on :8080.
// ---------------------------------------------------------------------------
interface Settings {
  /** Base URL of the Go AI Firewall /v1/check adapter (no trailing slash). */
  firewallUrl: string;
  /** OpenAI-compatible upstream the masked request is sent to. */
  upstreamUrl: string;
  /** Bearer key for the upstream LLM. */
  upstreamKey: string;
  /** Default model id used when Continue does not specify one. */
  model: string;
  /** Title shown in Continue's model picker. */
  title: string;
  /** Stable identifier that selects this caller's isolated vault. */
  user: string;
  /** How long to wait for the firewall to answer, in milliseconds. */
  timeoutMs: number;
  /**
   * Behaviour when the firewall is unreachable.
   *   false = fail CLOSED (block the request, safer default)
   *   true  = fail OPEN  (send the request UNMASKED)
   */
  failOpen: boolean;
}

function loadSettings(): Settings {
  const env = (typeof process !== "undefined" && process.env) || ({} as any);
  const trimSlash = (s: string) => s.replace(/\/+$/, "");
  return {
    firewallUrl: trimSlash(env.AI_FIREWALL_CHECK_URL || "http://localhost:8080"),
    upstreamUrl: trimSlash(env.AI_FIREWALL_UPSTREAM_URL || "https://api.openai.com/v1"),
    upstreamKey: env.AI_FIREWALL_UPSTREAM_KEY || env.OPENAI_API_KEY || "",
    model: env.AI_FIREWALL_MODEL || "gpt-4o",
    title: env.AI_FIREWALL_TITLE || "AI Firewall (Guarded)",
    user: env.AI_FIREWALL_USER || "continue-local",
    timeoutMs: Number(env.AI_FIREWALL_TIMEOUT_MS || 5000),
    failOpen: /^(1|true|yes)$/i.test(env.AI_FIREWALL_FAIL_OPEN || ""),
  };
}

// ---------------------------------------------------------------------------
// Engine contract — mirrors extensions/open-webui/main.go
// ---------------------------------------------------------------------------
interface CheckResponse {
  allowed: boolean;
  reason?: string;
  masked_content?: string;
  restored_content?: string;
  matches?: Array<{ type: string; rule: string; count?: number }>;
}

/**
 * Thrown when the engine blocks content. `reason` is the engine's
 * machine-readable snake_case code (e.g. "masking_failed_vault_full",
 * "secret_leak_in_output"), surfaced verbatim so Continue can display it.
 */
class FirewallBlocked extends Error {
  reason: string;
  constructor(reason: string) {
    super(`Blocked by AI Firewall: ${reason}`);
    this.name = "FirewallBlocked";
    this.reason = reason;
  }
}

// ---------------------------------------------------------------------------
// Content helpers — a Continue message's `content` is a string OR a list of
// multimodal parts. Only plain-string text is substituted; multimodal parts
// are left untouched (parallel to filter.py's `_set_last_message`), which keeps
// the adapter thin and lossless.
// ---------------------------------------------------------------------------
function contentToText(content: any): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .filter((p) => p && p.type === "text" && typeof p.text === "string")
      .map((p) => p.text)
      .join(" ");
  }
  return "";
}

function replaceText(message: ChatMessage, newText: string): ChatMessage {
  // Only substitute when the original content was a plain string. Multimodal
  // content keeps its parts; the block decision still applied to its text.
  if (typeof message.content === "string") {
    return { ...message, content: newText };
  }
  return message;
}

// ---------------------------------------------------------------------------
// The one call into the engine. Mirrors filter.py `_call`.
// ---------------------------------------------------------------------------
async function check(
  fetchFn: FetchFn,
  cfg: Settings,
  content: string,
  direction: "inlet" | "outlet",
): Promise<CheckResponse | null> {
  // Nothing to check — allow, nothing to substitute.
  if (!content) return null;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);
  let data: CheckResponse;
  try {
    const resp = await fetchFn(`${cfg.firewallUrl}/v1/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, user: cfg.user, direction }),
      signal: controller.signal,
    });
    if (!resp.ok) throw new Error(`firewall HTTP ${resp.status}`);
    data = (await resp.json()) as CheckResponse;
  } catch (exc: any) {
    // Timeouts, connection errors, non-2xx, invalid JSON — treat uniformly.
    if (cfg.failOpen) {
      console.warn(`[AI Firewall] ${direction}: unreachable, failing OPEN: ${exc?.message ?? exc}`);
      return null; // allow, no substitution possible
    }
    throw new Error(
      "AI Firewall is unreachable and FAIL_OPEN is disabled, so the request was blocked for safety.",
    );
  } finally {
    clearTimeout(timer);
  }

  // Engine contract: { allowed, reason?, masked_content?, restored_content? }.
  if (!data.allowed) {
    throw new FirewallBlocked(data.reason || "content_blocked");
  }
  return data;
}

// ---------------------------------------------------------------------------
// PRE-LLM: mask every message before it reaches the model. Delegates entirely
// to the engine's Mask via /v1/check inlet. Raises FirewallBlocked when a
// prompt cannot be masked (e.g. vault full → fail-closed).
// ---------------------------------------------------------------------------
async function maskMessages(
  fetchFn: FetchFn,
  cfg: Settings,
  messages: ChatMessage[],
): Promise<ChatMessage[]> {
  const out: ChatMessage[] = [];
  for (const msg of messages) {
    const text = contentToText(msg.content);
    const data = await check(fetchFn, cfg, text, "inlet");
    // Engine only returns masked_content when it actually changed the text.
    if (data && data.masked_content) {
      out.push(replaceText(msg, data.masked_content));
    } else {
      out.push(msg);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// POST-LLM: restore + leak-check the model's complete reply. Delegates to the
// engine's Detect (leak defence) + Unmask (restoration) via /v1/check outlet.
// Restoration MUST run in the engine: the label→original map lives in the
// engine's in-memory vault and is never exposed here.
// ---------------------------------------------------------------------------
async function restoreReply(
  fetchFn: FetchFn,
  cfg: Settings,
  reply: string,
): Promise<string> {
  const data = await check(fetchFn, cfg, reply, "outlet");
  if (data && data.restored_content) return data.restored_content;
  return reply;
}

// ---------------------------------------------------------------------------
// Upstream LLM call — an OpenAI-compatible /chat/completions request. This is
// the "LLM" box in the flow. It carries the MASKED messages; the raw secrets
// never leave the machine unmasked. We buffer the full reply, then restore it
// in one outlet call (see the streaming note at the top of this file).
// ---------------------------------------------------------------------------
async function callUpstream(
  fetchFn: FetchFn,
  cfg: Settings,
  signal: AbortSignal,
  messages: ChatMessage[],
  options: CompletionOptions,
): Promise<string> {
  const body: Record<string, any> = {
    model: options.model || cfg.model,
    messages: messages.map((m) => ({ role: m.role, content: m.content })),
    stream: false,
  };
  if (options.temperature != null) body.temperature = options.temperature;
  if (options.topP != null) body.top_p = options.topP;
  if (options.maxTokens != null) body.max_tokens = options.maxTokens;
  if (options.stop != null) body.stop = options.stop;

  const resp = await fetchFn(`${cfg.upstreamUrl}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(cfg.upstreamKey ? { Authorization: `Bearer ${cfg.upstreamKey}` } : {}),
    },
    body: JSON.stringify(body),
    signal,
  });
  if (!resp.ok) {
    const detail = await resp.text().catch(() => "");
    throw new Error(`upstream LLM HTTP ${resp.status}: ${detail.slice(0, 300)}`);
  }
  const json = await resp.json();
  return json?.choices?.[0]?.message?.content ?? "";
}

// ---------------------------------------------------------------------------
// modifyConfig — Continue's required entry point. We register one CustomLLM
// whose streamChat/streamCompletion generators are the pre/post-LLM hooks.
// ---------------------------------------------------------------------------
export function modifyConfig(config: Config): Config {
  const cfg = loadSettings();

  config.models.push({
    options: { title: cfg.title, model: cfg.model },

    // streamChat — PRE-LLM hook (mask) → LLM → POST-LLM hook (detect + restore).
    streamChat: async function* (
      messages: ChatMessage[],
      signal: AbortSignal,
      options: CompletionOptions,
      fetchFn: FetchFn,
    ): AsyncGenerator<ChatMessage | string> {
      // 1. PRE-LLM: mask. Engine.Mask() via /v1/check inlet. Throws if blocked.
      const masked = await maskMessages(fetchFn, cfg, messages);

      // 2. LLM: send masked messages upstream.
      const rawReply = await callUpstream(fetchFn, cfg, signal, masked, options);

      // 3. POST-LLM: detect leaks + restore. Engine via /v1/check outlet.
      //    Throws FirewallBlocked("secret_leak_in_output") on a raw leak.
      const restored = await restoreReply(fetchFn, cfg, rawReply);

      // Yield the fully-restored assistant message (unary restore — see note).
      yield { role: "assistant", content: restored };
    },

    // streamCompletion — the same pipeline for non-chat (autocomplete-style)
    // prompts. Provided so a single guarded model works for both surfaces.
    streamCompletion: async function* (
      prompt: string,
      signal: AbortSignal,
      options: CompletionOptions,
      fetchFn: FetchFn,
    ): AsyncGenerator<string> {
      const [masked] = await maskMessages(fetchFn, cfg, [
        { role: "user", content: prompt },
      ]);
      const rawReply = await callUpstream(fetchFn, cfg, signal, [masked], options);
      const restored = await restoreReply(fetchFn, cfg, rawReply);
      yield restored;
    },
  });

  return config;
}
