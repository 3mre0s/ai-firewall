#!/usr/bin/env bash
# Demo script — run via: bash docs/_demo.sh
# Shows the mask-on-the-way-out / restore-on-the-way-back pipeline.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PAT="ghp_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
EMAIL="alice@acme-corp.com"
UPSTREAM_PORT="29999"
FIREWALL_PORT="28080"
UPSTREAM_LOG="/tmp/ai-fw-upstream-$$.log"
FW_LOG="/tmp/ai-fw-$$.log"

cleanup() {
  [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null || true
  [ -n "${FW_PID:-}" ]   && kill "$FW_PID"   2>/dev/null || true
  rm -f "$ROOT/ai-firewall" "$UPSTREAM_LOG" "$FW_LOG"
}
trap cleanup EXIT

# ── 1. Build binary ───────────────────────────────────────────────────────
printf '\033[1;33m$ \033[0mgo build -o ai-firewall .\n'
(cd "$ROOT" && go build -o ai-firewall . 2>&1)
printf '\033[1;32m  built ✓\033[0m\n\n'

# ── 2. Start mock upstream ────────────────────────────────────────────────
printf '\033[1;33m$ \033[0mgo run scripts/mock-upstream --port %s &\n' "$UPSTREAM_PORT"
go run "$ROOT/scripts/mock-upstream/main.go" --port "$UPSTREAM_PORT" \
  > "$UPSTREAM_LOG" 2>&1 &
MOCK_PID=$!

# Wait until mock is ready (health check /ping)
for i in $(seq 1 30); do
  curl -sf "http://localhost:$UPSTREAM_PORT/ping" >/dev/null 2>&1 && break
  sleep 0.3
done

# ── 3. Start firewall ─────────────────────────────────────────────────────
printf '\033[1;33m$ \033[0mFORWARD_API_KEY=sk-demo UPSTREAM_URL=http://localhost:%s ./ai-firewall &\n' "$UPSTREAM_PORT"
FORWARD_API_KEY=sk-demo \
  UPSTREAM_URL="http://localhost:$UPSTREAM_PORT" \
  FIREWALL_PORT="$FIREWALL_PORT" \
  LOG_LEVEL=silent \
  "$ROOT/ai-firewall" > "$FW_LOG" 2>&1 &
FW_PID=$!

# Wait until firewall is ready (/metrics = localhost-only 200)
for i in $(seq 1 30); do
  curl -sf "http://localhost:$FIREWALL_PORT/metrics" >/dev/null 2>&1 && break
  sleep 0.3
done

# ── 4. Show the prompt ────────────────────────────────────────────────────
printf '\n\033[1;36m── prompt contains real secrets ─────────────────────────────────────\033[0m\n'
printf "  PAT   : \033[1;31m%s\033[0m\n" "$PAT"
printf "  email : \033[1;31m%s\033[0m\n\n" "$EMAIL"
sleep 0.4

# ── 5. Send request through firewall ─────────────────────────────────────
printf '\033[1;33m$ \033[0mcurl -s localhost:%s/v1/messages ...\n\n' "$FIREWALL_PORT"
PAYLOAD=$(printf '{"model":"claude-3-haiku","messages":[{"role":"user","content":"PAT: %s  user: %s"}]}' "$PAT" "$EMAIL")
RESPONSE=$(curl -sf "localhost:$FIREWALL_PORT/v1/messages" \
  -H "Content-Type: application/json" \
  -H "x-api-key: sk-demo" \
  -d "$PAYLOAD" 2>&1) || RESPONSE="(request failed)"
printf '%s\n' "$RESPONSE" | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin), indent=2))" 2>/dev/null \
  || printf '%s\n' "$RESPONSE"

# ── 6. What the provider received (masked) ───────────────────────────────
printf '\n\033[1;36m── what the AI provider actually received ────────────────────────────\033[0m\n'
BODY_LINE=$(grep "BODY" "$UPSTREAM_LOG" 2>/dev/null | tail -1 | sed 's/.*BODY //')
if [ -n "$BODY_LINE" ]; then
  printf '%s\n' "$BODY_LINE" | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin), indent=2))" 2>/dev/null \
    || printf '%s\n' "$BODY_LINE"
else
  printf '  (upstream log: %s)\n' "$(cat "$UPSTREAM_LOG" 2>/dev/null | head -3)"
fi

printf '\n\033[1;32m  secrets → vault tokens before leaving your machine ✓\033[0m\n\n'
sleep 0.5
# cleanup via trap
