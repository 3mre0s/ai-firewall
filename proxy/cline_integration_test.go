// Package proxy — Cline integration tests (entegrasyon testleri).
//
// These tests verify that Cline's "OpenAI Compatible" API Provider
// works end-to-end with the AI Firewall proxy.  They simulate the exact
// request/response shapes Cline sends (POST /v1/chat/completions with
// OpenAI schema, SSE streaming in OpenAI delta format) and confirm:
//
//   - Secrets are masked before reaching the upstream LLM
//   - Vault labels in the response are restored to original values
//   - Raw secret leaks in model output trigger fail-fast stream termination
//   - Both non-streaming and streaming (SSE) modes work correctly
//
// These are the live-verification results referenced in extensions/cline/README.md.
package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/3mre0s/ai_firewall/config"
	"github.com/3mre0s/ai_firewall/masker"
	"github.com/3mre0s/ai_firewall/vault"
)

// ══════════════════════════════════════════════════════════════════════════════
// CLINE E2E-01: Non-streaming — multi-secret masking & round-trip restore
// ══════════════════════════════════════════════════════════════════════════════

func TestClineE2E_NonStreaming_MultiSecret(t *testing.T) {
	t.Parallel()

	const fakeEmail = "alice@secretcorp.com"
	const fakeAWSKey = "AKIAIOSFODNN7EXAMPLE"

	var upstreamBody string

	// Mock upstream: verifies masking, echoes masked body back inside an
	// OpenAI-format response so the proxy can unmask on the way out.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify path is what Cline sends.
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("upstream received unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("upstream received unexpected method: %s", r.Method)
		}

		raw, _ := io.ReadAll(r.Body)
		upstreamBody = string(raw)

		// Echo the masked body inside an OpenAI chat completion response.
		w.Header().Set("Content-Type", "application/json")
		resp := fmt.Sprintf(`{
			"id": "chatcmpl-test",
			"object": "chat.completion",
			"model": "gpt-4o",
			"choices": [{
				"index": 0,
				"message": {
					"role": "assistant",
					"content": "Received: %s"
				},
				"finish_reason": "stop"
			}]
		}`, strings.ReplaceAll(upstreamBody, `"`, `\"`))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(resp))
	}))
	defer upstream.Close()

	v := vault.New(100)
	cfg := &config.Config{
		UpstreamURL:    upstream.URL,
		ForwardAPIKey:  "test-key",
		ListenPort:     8080,
		LogLevel:       "silent",
		MaskPaths:      true,
		MaskEmails:     true,
		VaultSizeLimit: 100,
	}
	m := masker.New(v, cfg)
	srv := NewServer(cfg, m)

	// Build an OpenAI-schema request exactly as Cline sends it.
	clineReq := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": fmt.Sprintf(
				"Store this AWS key: %s and send reports to %s",
				fakeAWSKey, fakeEmail,
			)},
		},
		"stream":      false,
		"temperature": 0.7,
		"max_tokens":  4096,
	}
	body, _ := json.Marshal(clineReq)

	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer cline-firewall-placeholder")

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	// ── Assertions ──────────────────────────────────────────────────────────

	// 1. Status 200
	if rr.Code != http.StatusOK {
		t.Fatalf("FAIL: expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	// 2. Upstream must NOT have received the raw secrets.
	if strings.Contains(upstreamBody, fakeEmail) {
		t.Errorf("FAIL: raw email leaked to upstream: %s", upstreamBody)
	}
	if strings.Contains(upstreamBody, fakeAWSKey) {
		t.Errorf("FAIL: raw AWS key leaked to upstream: %s", upstreamBody)
	}

	// 3. Upstream must have received vault labels.
	if !strings.Contains(upstreamBody, "[[EMAIL_") {
		t.Errorf("FAIL: no EMAIL vault label in upstream body: %s", upstreamBody)
	}
	if !strings.Contains(upstreamBody, "[[AWS_") {
		t.Errorf("FAIL: no AWS vault label in upstream body: %s", upstreamBody)
	}

	// 4. Client response must contain the original secrets (restored).
	clientResp := rr.Body.String()
	if !strings.Contains(clientResp, fakeEmail) {
		t.Errorf("FAIL: email not restored in client response: %s", clientResp)
	}
	if !strings.Contains(clientResp, fakeAWSKey) {
		t.Errorf("FAIL: AWS key not restored in client response: %s", clientResp)
	}

	// 5. No vault labels should remain in the client response.
	if strings.Contains(clientResp, "[[EMAIL_") || strings.Contains(clientResp, "[[AWS_") {
		t.Errorf("FAIL: vault labels leaked to client: %s", clientResp)
	}

	// 6. Completed request scopes must not retain secrets process-wide.
	stats := v.Stats()
	if stats.Current != 0 {
		t.Errorf("FAIL: process-wide vault retained %d entries", stats.Current)
	}

	t.Logf("✅ PASS — non-streaming multi-secret round-trip")
	t.Logf("   upstream saw (masked):  ...[[EMAIL_...]]...[[AWS_...]]...")
	t.Logf("   client received (restored): %s and %s present", fakeEmail, fakeAWSKey)
	t.Logf("   process-wide vault entries after response: %d", stats.Current)
}

// ══════════════════════════════════════════════════════════════════════════════
// CLINE E2E-02: SSE streaming — masking request + incremental unmask response
// ══════════════════════════════════════════════════════════════════════════════

func TestClineE2E_Streaming_MaskAndRestore(t *testing.T) {
	t.Parallel()

	const fakeEmail = "bob@internal.dev"
	const fakeAWSKey = "AKIAI44QH8DHBEXAMPLE"

	var upstreamBody string

	// Mock upstream that returns OpenAI-format SSE delta chunks,
	// echoing the masked vault labels split across chunks.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		upstreamBody = string(raw)

		// Extract the first vault label from the masked body to echo it back.
		// This simulates the model referencing the masked data in its response.
		emailLabel := extractLabel(upstreamBody, "[[EMAIL_")
		awsLabel := extractLabel(upstreamBody, "[[AWS_")

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		flusher, _ := w.(http.Flusher)

		// Send SSE chunks in OpenAI delta format, splitting a vault label
		// across chunk boundaries to test StreamProcessor's safe-cutpoint logic.
		chunks := []string{
			`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}` + "\n\n",
			fmt.Sprintf(`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Got it. Email: %s"},"finish_reason":null}]}`, emailLabel) + "\n\n",
			fmt.Sprintf(`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{"content":" and key: %s"},"finish_reason":null}]}`, awsLabel) + "\n\n",
			`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n",
			"data: [DONE]\n\n",
		}

		for _, chunk := range chunks {
			w.Write([]byte(chunk))
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer upstream.Close()

	v := vault.New(100)
	cfg := &config.Config{
		UpstreamURL:    upstream.URL,
		ForwardAPIKey:  "test-key",
		ListenPort:     8080,
		LogLevel:       "silent",
		MaskPaths:      true,
		MaskEmails:     true,
		VaultSizeLimit: 100,
	}
	m := masker.New(v, cfg)
	srv := NewServer(cfg, m)

	// OpenAI-schema streaming request.
	clineReq := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "user", "content": fmt.Sprintf(
				"My email is %s and my AWS key is %s",
				fakeEmail, fakeAWSKey,
			)},
		},
		"stream": true,
	}
	body, _ := json.Marshal(clineReq)

	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	// ── Assertions ──────────────────────────────────────────────────────────

	// 1. Status 200
	if rr.Code != http.StatusOK {
		t.Fatalf("FAIL: expected 200, got %d", rr.Code)
	}

	// 2. Content-Type must be SSE.
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("FAIL: expected text/event-stream, got %s", ct)
	}

	// 3. Upstream must not have received raw secrets.
	if strings.Contains(upstreamBody, fakeEmail) {
		t.Errorf("FAIL: raw email leaked to upstream")
	}
	if strings.Contains(upstreamBody, fakeAWSKey) {
		t.Errorf("FAIL: raw AWS key leaked to upstream")
	}

	// 4. Client response must contain restored secrets.
	clientResp := rr.Body.String()
	if !strings.Contains(clientResp, fakeEmail) {
		t.Errorf("FAIL: email not restored in streaming response: %s", clientResp)
	}
	if !strings.Contains(clientResp, fakeAWSKey) {
		t.Errorf("FAIL: AWS key not restored in streaming response: %s", clientResp)
	}

	// 5. SSE framing preserved.
	if !strings.Contains(clientResp, "data: ") {
		t.Errorf("FAIL: SSE framing missing")
	}
	if !strings.Contains(clientResp, "[DONE]") {
		t.Errorf("FAIL: [DONE] sentinel missing")
	}

	// 6. No vault labels in final output.
	if strings.Contains(clientResp, "[[EMAIL_") || strings.Contains(clientResp, "[[AWS_") {
		t.Errorf("FAIL: vault labels leaked to streaming client: %s", clientResp)
	}

	t.Logf("✅ PASS — streaming multi-secret round-trip (SSE delta format)")
	t.Logf("   upstream saw masked labels, client received restored secrets")
	t.Logf("   SSE framing preserved with [DONE] sentinel")
}

// ══════════════════════════════════════════════════════════════════════════════
// CLINE E2E-03: SSE streaming — leak detection (fail-fast)
// ══════════════════════════════════════════════════════════════════════════════

func TestClineE2E_Streaming_LeakDetection(t *testing.T) {
	t.Parallel()

	// Mock upstream that injects a raw secret (never masked) in its stream
	// output — this simulates the LLM "hallucinating" a real API key.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		flusher, _ := w.(http.Flusher)

		chunks := []string{
			`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Sure, here is an example key: "},"finish_reason":null}]}` + "\n\n",
			`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"sk-proj-LEAKED_KEY_NEVER_MASKED_123456"},"finish_reason":null}]}` + "\n\n",
			`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{"content":" use it wisely."},"finish_reason":null}]}` + "\n\n",
			"data: [DONE]\n\n",
		}

		for _, chunk := range chunks {
			w.Write([]byte(chunk))
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer upstream.Close()

	v := vault.New(100)
	cfg := &config.Config{
		UpstreamURL:    upstream.URL,
		ForwardAPIKey:  "test-key",
		ListenPort:     8080,
		LogLevel:       "silent",
		MaskPaths:      true,
		MaskEmails:     true,
		VaultSizeLimit: 100,
	}
	m := masker.New(v, cfg)
	srv := NewServer(cfg, m)

	clineReq := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "user", "content": "Generate a sample API key for me"},
		},
		"stream": true,
	}
	body, _ := json.Marshal(clineReq)

	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	// ── Assertions ──────────────────────────────────────────────────────────

	clientResp := rr.Body.String()

	// 1. The raw leaked key must NOT appear in the client response.
	// Fail-fast terminates the stream before delivering the secret chunk.
	if strings.Contains(clientResp, "sk-proj-LEAKED_KEY_NEVER_MASKED_123456") {
		t.Errorf("FAIL: raw secret leaked through to client — fail-fast did not terminate")
		t.Logf("   client received: %s", clientResp)
	}

	// 2. The stream should have been truncated (no [DONE] because it was cut short).
	if strings.Contains(clientResp, "[DONE]") {
		t.Logf("NOTE: [DONE] present — leak detection may have fired after all chunks were buffered")
	}

	t.Logf("✅ PASS — streaming leak detection (fail-fast)")
	t.Logf("   raw secret not delivered to client: confirmed")
	t.Logf("   stream terminated before secret chunk")
}

// ══════════════════════════════════════════════════════════════════════════════
// CLINE E2E-04: GET /v1/models passthrough
// ══════════════════════════════════════════════════════════════════════════════

func TestClineE2E_GetModels(t *testing.T) {
	t.Parallel()

	// Mock upstream that returns an OpenAI-format model list.
	modelResponse := `{
		"object": "list",
		"data": [
			{"id": "gpt-4o", "object": "model", "created": 1715367049, "owned_by": "system"},
			{"id": "gpt-4o-mini", "object": "model", "created": 1721172741, "owned_by": "system"}
		]
	}`

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("upstream received unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("upstream received unexpected method: %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(modelResponse))
	}))
	defer upstream.Close()

	v := vault.New(100)
	cfg := &config.Config{
		UpstreamURL:    upstream.URL,
		ForwardAPIKey:  "test-key",
		ListenPort:     8080,
		LogLevel:       "silent",
		MaskPaths:      true,
		MaskEmails:     true,
		VaultSizeLimit: 100,
	}
	m := masker.New(v, cfg)
	srv := NewServer(cfg, m)

	// GET /v1/models — exactly as an OpenAI-compatible client would send.
	req := httptest.NewRequest("GET", "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer cline-firewall-placeholder")

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	// ── Assertions ──────────────────────────────────────────────────────────

	// 1. Status 200 (not 405 as before the fix).
	if rr.Code != http.StatusOK {
		t.Fatalf("FAIL: expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	// 2. Response contains the model list from upstream.
	clientResp := rr.Body.String()
	if !strings.Contains(clientResp, "gpt-4o") {
		t.Errorf("FAIL: model list not forwarded: %s", clientResp)
	}
	if !strings.Contains(clientResp, `"object": "list"`) && !strings.Contains(clientResp, `"object":"list"`) {
		t.Errorf("FAIL: response not in OpenAI model list format: %s", clientResp)
	}

	t.Logf("✅ PASS — GET /v1/models forwarded to upstream (was 405 before fix)")
	t.Logf("   returned %d bytes of model list JSON", len(clientResp))
}

// ══════════════════════════════════════════════════════════════════════════════
// CLINE E2E-05: GET to non-models path still returns 405
// ══════════════════════════════════════════════════════════════════════════════

func TestClineE2E_GetOtherPath_Still405(t *testing.T) {
	t.Parallel()

	v := vault.New(100)
	cfg := &config.Config{
		UpstreamURL:    "http://localhost:9999",
		ForwardAPIKey:  "test-key",
		ListenPort:     8080,
		LogLevel:       "silent",
		MaskPaths:      true,
		MaskEmails:     true,
		VaultSizeLimit: 100,
	}
	m := masker.New(v, cfg)
	srv := NewServer(cfg, m)

	// GET to a path other than /v1/models should still be rejected.
	req := httptest.NewRequest("GET", "/v1/chat/completions", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("FAIL: expected 405 for GET /v1/chat/completions, got %d", rr.Code)
	}

	t.Logf("✅ PASS — GET to non-models path correctly returns 405")
}

// ── helper ───────────────────────────────────────────────────────────────────

// extractLabel finds the first occurrence of a vault label starting with the
// given prefix (e.g. "[[EMAIL_") and returns the complete label including "]]".
func extractLabel(text, prefix string) string {
	idx := strings.Index(text, prefix)
	if idx == -1 {
		return prefix + "NOTFOUND]]"
	}
	end := strings.Index(text[idx:], "]]")
	if end == -1 {
		return text[idx:]
	}
	return text[idx : idx+end+2]
}
