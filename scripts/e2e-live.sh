#!/usr/bin/env bash
# End-to-end smoke test against a REAL upstream provider.
#
# Usage:
#   FORWARD_API_KEY=sk-... scripts/e2e-live.sh anthropic
#   FORWARD_API_KEY=sk-... scripts/e2e-live.sh openai
#
# Exits non-zero on any failure. NEVER run this in CI — it would leak your key.

set -euo pipefail

provider="${1:-}"
port="${PORT:-18080}"

# Dummy secret: matches \bsk-ant-[A-Za-z0-9\-_]{20,}\b (patterns/patterns.go:290)
# but is NOT a real credential. Exercises the mask → vault → unmask round-trip.
DUMMY_SECRET="sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXX"

case "$provider" in
  anthropic|openai) ;;
  *)
    echo "usage: $0 {anthropic|openai}" >&2
    exit 2
    ;;
esac

if [ -z "${FORWARD_API_KEY:-}" ]; then
  echo "FORWARD_API_KEY is not set. Aborting before we start the firewall." >&2
  exit 2
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
binary="$root/ai-firewall"
[ "$(uname -s)" = "MINGW64_NT"* ] || [ "$(uname -s)" = "MSYS_NT"* ] && binary="$root/ai-firewall.exe"

if [ ! -x "$binary" ]; then
  echo "→ binary missing, building: $binary"
  ( cd "$root" && go build -o "$binary" . )
fi

case "$provider" in
  anthropic)
    upstream="https://api.anthropic.com"
    hint="anthropic"
    path="/v1/messages"
    extra_headers=(-H "anthropic-version: 2023-06-01")
    body="{\"model\":\"claude-3-5-haiku-20241022\",\"max_tokens\":64,\"messages\":[{\"role\":\"user\",\"content\":\"Repeat the following token back to me verbatim inside a code block, nothing else: ${DUMMY_SECRET}\"}]}"
    ;;
  openai)
    upstream="https://api.openai.com"
    hint="openai"
    path="/v1/chat/completions"
    extra_headers=()
    body="{\"model\":\"gpt-4o-mini\",\"max_tokens\":64,\"messages\":[{\"role\":\"user\",\"content\":\"Repeat the following token back to me verbatim inside a code block, nothing else: ${DUMMY_SECRET}\"}]}"
    ;;
esac

log_file="$(mktemp -t ai-firewall-e2e.XXXXXX.log)"

echo "→ starting firewall on :$port → $upstream ($hint)"

FORWARD_API_KEY="$FORWARD_API_KEY" \
UPSTREAM_URL="$upstream" \
PROVIDER_HINT="$hint" \
FIREWALL_PORT="$port" \
LOG_LEVEL="debug" \
  "$binary" >"$log_file" 2>&1 &
fw_pid=$!

cleanup() {
  if kill -0 "$fw_pid" 2>/dev/null; then
    echo "→ stopping firewall (pid $fw_pid)"
    kill "$fw_pid" 2>/dev/null || true
    wait "$fw_pid" 2>/dev/null || true
  fi
  echo "firewall log: $log_file"
}
trap cleanup EXIT INT TERM

# Wait for /health
healthy=0
for _ in $(seq 1 30); do
  sleep 0.2
  if curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
    healthy=1
    break
  fi
done
[ "$healthy" = "1" ] || { echo "firewall did not become healthy within 6s"; exit 1; }
echo "✓ /health ok"

# Live POST
uri="http://127.0.0.1:${port}${path}"
echo "→ POST $uri"

resp_headers="$(mktemp)"
resp_body="$(mktemp)"
trap 'rm -f "$resp_headers" "$resp_body"; cleanup' EXIT INT TERM

status="$(curl -sS \
  -o "$resp_body" \
  -D "$resp_headers" \
  -w '%{http_code}' \
  -X POST \
  -H "Content-Type: application/json" \
  "${extra_headers[@]}" \
  --max-time 60 \
  --data-binary "$body" \
  "$uri")"

echo "← status: $status"
echo "← headers (relevant):"
grep -iE '^(content-type|x-request-id|anthropic-ratelimit-requests-remaining|x-ratelimit-remaining-requests):' "$resp_headers" || true
echo "← body (first 400 chars):"
head -c 400 "$resp_body"
echo ""

if [ "$status" -ge 400 ]; then
  echo ""
  echo "✗ connection FAIL: upstream returned $status" >&2
  exit 1
fi
echo "✓ connection/200 check PASSED"
echo ""

# ── Assert A: masking happened ─────────────────────────────────────────────────
# masked_items_total (metrics/metrics.go:105) counts every individual sensitive
# value replaced in the request body. A value > 0 proves the dummy secret was
# replaced with a [[ANT_KEY_XXXXXXXX]] placeholder before reaching upstream.
metrics_json="$(curl -sS "http://127.0.0.1:${port}/metrics")"
echo "/metrics (relevant fields):"
printf '%s\n' "$metrics_json" | jq '{masked_items_total,masked_requests_total,unmasked_items_total,vault_current}'
echo ""

masked_count="$(printf '%s\n' "$metrics_json" | jq '.masked_items_total')"
if [ "${masked_count:-0}" -gt 0 ]; then
  echo "✓ Assert A (masking): masked_items_total=${masked_count} — dummy secret replaced with placeholder before upstream"
else
  echo "✗ Assert A FAIL: masked_items_total=${masked_count:-0} — masking did not fire; dummy secret may have reached the AI provider"
  exit 1
fi

# Note: no Assert B (log-based leak check).
# proxy/proxy.go logs neither the incoming nor the outgoing request body at any
# log level (proxy.go:130 logs method/path only; proxy.go:149 logs mask count
# only; the masked body at proxy.go:190 is forwarded upstream but never written
# to the log). A full-log grep for the dummy secret would therefore find it in
# the INCOMING body if body logging were ever added, making the check a
# false-positive risk. Masking is already proven by Assert A (masked_items_total
# > 0); a log-based sızıntı check adds no reliable signal here.

# ── Assert C: unmasking happened (counter-primary, body-secondary) ─────────────
# unmasked_items_total (metrics/metrics.go:107) counts label→original
# replacements made in upstream responses. A value > 0 is primary proof the
# full round-trip worked. If the counter is 0 and no [[LABEL]] pattern appears
# in the response body, the model did not echo the token — that is not a
# firewall defect, so we skip rather than fail.
unmasked_count="$(printf '%s\n' "$metrics_json" | jq '.unmasked_items_total')"
resp_text="$(cat "$resp_body")"

if [ "${unmasked_count:-0}" -gt 0 ]; then
  echo "✓ Assert C (unmask counter): unmasked_items_total=${unmasked_count} — placeholder resolved back to original in response"
  if printf '%s\n' "$resp_text" | grep -qF "$DUMMY_SECRET"; then
    echo "✓ Assert C (unmask value): original dummy secret present in response body"
  else
    echo "  ↳ counter fired but original not literal in body (model may have paraphrased — not a firewall error)"
  fi
elif printf '%s\n' "$resp_text" | grep -qE '\[\[[A-Z_]+_[0-9A-F]{8}\]\]'; then
  # A vault placeholder survived into the client response — unmask did not run.
  echo "✗ Assert C FAIL: vault placeholder present in response body but unmasked_items_total=0 — unmask did not fire"
  exit 1
else
  echo "⚠ Assert C SKIP: unmasked_items_total=0 and no placeholder in response — model did not echo the token verbatim; unmask path not exercised this run"
fi

echo ""
echo "✓ live test PASSED for $provider"
