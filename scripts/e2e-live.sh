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
    body='{"model":"claude-3-5-haiku-20241022","max_tokens":32,"messages":[{"role":"user","content":"Reply with exactly: ok"}]}'
    ;;
  openai)
    upstream="https://api.openai.com"
    hint="openai"
    path="/v1/chat/completions"
    extra_headers=()
    body='{"model":"gpt-4o-mini","max_tokens":32,"messages":[{"role":"user","content":"Reply with exactly: ok"}]}'
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

echo ""
echo "/metrics:"
curl -sS "http://127.0.0.1:${port}/metrics"
echo ""

if [ "$status" -ge 400 ]; then
  echo ""
  echo "upstream returned $status. Check headers above — this is exactly the kind of header bug task #4 is meant to catch." >&2
  exit 1
fi

echo ""
echo "✓ live test PASSED for $provider"
