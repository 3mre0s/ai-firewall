// Package proxy_test contains comprehensive integration tests for the proxy package.
// Tests verify: masking, round-trip recovery, fail-fast behavior, metrics, and vault state.
package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/3mre0s/ai_firewall/config"
	"github.com/3mre0s/ai_firewall/masker"
	"github.com/3mre0s/ai_firewall/metrics"
	"github.com/3mre0s/ai_firewall/vault"
)

// ══════════════════════════════════════════════════════════════════════════════
// TEST HELPERS
// ══════════════════════════════════════════════════════════════════════════════

// testSetup creates a fresh test environment with firewall server and mock upstream.
type testSetup struct {
	firewall *httptest.Server
	upstream *httptest.Server
	vault    *vault.Vault
	masker   *masker.Masker
	server   *Server
}

// newTestSetup creates a complete test environment with firewall and mock upstream.
func newTestSetup(t *testing.T, vaultLimit int, upstreamHandler http.HandlerFunc) *testSetup {
	t.Helper()

	// Create mock upstream server
	upstream := httptest.NewServer(upstreamHandler)

	// Create vault and masker
	v := vault.New(vaultLimit)
	cfg := &config.Config{
		UpstreamURL:    upstream.URL,
		ForwardAPIKey:  "test-api-key",
		ListenPort:     8080,
		LogLevel:       "silent",
		MaskPaths:      true,
		MaskEmails:     true,
		VaultSizeLimit: vaultLimit,
	}
	m := masker.New(v, cfg)

	// Create firewall server
	srv := NewServer(cfg, m)
	firewall := httptest.NewServer(srv)

	return &testSetup{
		firewall: firewall,
		upstream: upstream,
		vault:    v,
		masker:   m,
		server:   srv,
	}
}

func (ts *testSetup) Close() {
	ts.firewall.Close()
	ts.upstream.Close()
}

// ══════════════════════════════════════════════════════════════════════════════
// SENARYO IP-01: E-posta Maskeleme ve Geri Yükleme (Round-Trip)
// ══════════════════════════════════════════════════════════════════════════════

func TestEmailMaskingRoundTrip(t *testing.T) {
	t.Parallel()

	// Capture what upstream receives
	var upstreamReceivedBody string
	
	// Mock upstream that echoes back the request body
	upstreamHandler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamReceivedBody = string(body)
		
		// Echo back the masked content
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		
		// Echo back exactly what we received (should contain masked labels)
		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{
					"role":    "assistant",
					"content": upstreamReceivedBody,
				}},
			},
		}
		json.NewEncoder(w).Encode(response)
	}

	ts := newTestSetup(t, 1000, upstreamHandler)
	defer ts.Close()

	// Test case from requirements
	originalEmail := "sirket_admin@kurum.com"
	requestBody := map[string]interface{}{
		"model": "gpt-4",
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": "Lütfen " + originalEmail + " adresi için kurumsal bir hoş geldin e-postası taslağı oluşturur musun?",
			},
		},
	}

	bodyBytes, _ := json.Marshal(requestBody)

	// Send request through firewall
	resp, err := http.Post(ts.firewall.URL+"/v1/chat/completions", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(resp.Body)
	responseStr := string(responseBody)

	// ASSERTIONS:
	// 1. Upstream should have received MASKED data (email replaced with label)
	if strings.Contains(upstreamReceivedBody, originalEmail) {
		t.Errorf("FAIL: Original email leaked to upstream!\nUpstream received: %s", upstreamReceivedBody)
	}

	// 2. Upstream should have received a vault label
	if !strings.Contains(upstreamReceivedBody, "[[EMAIL_") {
		t.Errorf("FAIL: No vault label found in upstream request.\nUpstream received: %s", upstreamReceivedBody)
	}

	// 3. Client response should have UNMASKED data (original email restored)
	if !strings.Contains(responseStr, originalEmail) {
		t.Errorf("FAIL: Original email not restored in client response.\nClient received: %s", responseStr)
	}

	// 4. Vault should have the email stored
	stats := ts.vault.Stats()
	if stats.Current == 0 {
		t.Error("FAIL: Vault is empty, expected email to be stored")
	}

	// 5. Metrics should reflect masking
	snapshot := metrics.Global.Snapshot(ts.vault)
	if snapshot.MaskedItems == 0 {
		t.Error("FAIL: MaskedItems metric is 0, expected at least 1")
	}
	
	t.Logf("✓ Round-trip successful: upstream saw masked data, client received original")
	t.Logf("  Upstream received (masked): %s", upstreamReceivedBody)
	t.Logf("  Client received (unmasked): %s", responseStr)
}

// ══════════════════════════════════════════════════════════════════════════════
// SENARYO IP-02: Kritik Sır Engelleme (Vault-Full Protection)
// ══════════════════════════════════════════════════════════════════════════════

func TestGitHubPATBlocking_VaultFull(t *testing.T) {
	t.Parallel()

	// Mock upstream - should NEVER be called when vault is full
	upstreamCalled := false
	upstreamHandler := func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}

	// Create firewall with vault limit = 1, then fill it
	ts := newTestSetup(t, 1, upstreamHandler)
	defer ts.Close()

	// First, fill the vault with one item
	ts.vault.Store("[[FILL_00000000]]", "filler-value")

	// Now vault is full. Next masking attempt should fail.
	// Request with GitHub PAT (exactly 36 chars after ghp_)
	requestBody := map[string]interface{}{
		"model": "gpt-4",
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": "Şu kod satırındaki hatayı düzeltir misin: config.Token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'",
			},
		},
	}

	bodyBytes, _ := json.Marshal(requestBody)

	// Send request through firewall
	resp, err := http.Post(ts.firewall.URL+"/v1/chat/completions", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// ASSERTIONS:
	// 1. Response should be 507 Insufficient Storage (vault full)
	if resp.StatusCode != http.StatusInsufficientStorage {
		t.Errorf("FAIL: Expected status 507, got %d", resp.StatusCode)
	}

	// 2. Response should contain vault_full error
	responseBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(responseBody), "vault_full") {
		t.Errorf("FAIL: Expected vault_full error in response, got: %s", string(responseBody))
	}

	// 3. Upstream should NEVER be called (fail-fast)
	if upstreamCalled {
		t.Error("FAIL: Upstream was called despite vault being full - data leak risk!")
	}

	// 4. Metrics should show vault evictions and blocked requests
	snapshot := metrics.Global.Snapshot(ts.vault)
	if snapshot.VaultEvictions == 0 {
		t.Error("FAIL: VaultEvictions metric should be > 0")
	}
	if snapshot.BlockedRequests == 0 {
		t.Error("FAIL: BlockedRequests metric should be > 0")
	}

	t.Logf("✓ Vault-full protection: request blocked with 507, upstream not called")
}

// ══════════════════════════════════════════════════════════════════════════════
// SENARYO ST-01: Güvenli Akış (Safe SSE Streaming)
// ══════════════════════════════════════════════════════════════════════════════

func TestSafeSSEStreaming(t *testing.T) {
	t.Parallel()

	// Mock upstream that sends SSE chunks
	upstreamHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		// Flush header
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		// Send SSE chunks as specified in requirements
		chunks := []string{
			"data: {\"choices\": [{\"delta\": {\"content\": \"Merhaba \"}}]}\n\n",
			"data: {\"choices\": [{\"delta\": {\"content\": \"dünya! Nasıl \"}}]}\n\n",
			"data: {\"choices\": [{\"delta\": {\"content\": \"yardımcı olabilirim?\"}}]}\n\n",
			"data: [DONE]\n\n",
		}

		for _, chunk := range chunks {
			w.Write([]byte(chunk))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}

	ts := newTestSetup(t, 1000, upstreamHandler)
	defer ts.Close()

	// Send streaming request
	requestBody := map[string]interface{}{
		"model":  "gpt-4",
		"stream": true,
		"messages": []map[string]string{
			{"role": "user", "content": "Merhaba"},
		},
	}

	bodyBytes, _ := json.Marshal(requestBody)
	resp, err := http.Post(ts.firewall.URL+"/v1/chat/completions", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// ASSERTIONS:
	// 1. Response should be 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Errorf("FAIL: Expected status 200, got %d", resp.StatusCode)
	}

	// 2. Content-Type should be text/event-stream
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("FAIL: Expected text/event-stream, got %s", ct)
	}

	// 3. All chunks should pass through intact
	responseBody, _ := io.ReadAll(resp.Body)
	responseStr := string(responseBody)

	expectedPhrases := []string{"Merhaba", "dünya! Nasıl", "yardımcı olabilirim?", "[DONE]"}
	for _, phrase := range expectedPhrases {
		if !strings.Contains(responseStr, phrase) {
			t.Errorf("FAIL: Expected phrase %q not found in response", phrase)
		}
	}

	// 4. Metrics should show stream request
	snapshot := metrics.Global.Snapshot(ts.vault)
	if snapshot.StreamRequests == 0 {
		t.Error("FAIL: StreamRequests metric should be > 0")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// SENARYO ST-02: Canlı Akışta Sızıntı Yakalama (Stream Leak Detection)
// ══════════════════════════════════════════════════════════════════════════════

func TestSSEStreamLeakDetection(t *testing.T) {
	t.Parallel()

	// Mock upstream that sends chunks including a leaked API key
	chunksSent := 0
	upstreamHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		// Send chunks as specified in requirements
		chunks := []string{
			"data: {\"choices\": [{\"delta\": {\"content\": \"İşte bahsettiğiniz \"}}]}\n\n",
			"data: {\"choices\": [{\"delta\": {\"content\": \"API test anahtarı: \"}}]}\n\n",
			"data: {\"choices\": [{\"delta\": {\"content\": \"sk-proj-ABC123XYZ7890123456789\"}}]}\n\n",
			"data: {\"choices\": [{\"delta\": {\"content\": \" bu anahtarı kullanabilirsiniz.\"}}]}\n\n",
			"data: [DONE]\n\n",
		}

		for i, chunk := range chunks {
			chunksSent = i + 1
			w.Write([]byte(chunk))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}

	ts := newTestSetup(t, 1000, upstreamHandler)
	defer ts.Close()

	// Send streaming request
	requestBody := map[string]interface{}{
		"model":  "gpt-4",
		"stream": true,
		"messages": []map[string]string{
			{"role": "user", "content": "API anahtarı nedir?"},
		},
	}

	bodyBytes, _ := json.Marshal(requestBody)
	resp, err := http.Post(ts.firewall.URL+"/v1/chat/completions", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	responseBody, _ := io.ReadAll(resp.Body)
	responseStr := string(responseBody)

	// ASSERTIONS (fail-fast akış sızıntı tespiti):

	// 1. Leaked API key must NOT appear in client response.
	// Fail-fast terminates the stream before delivering the secret chunk.
	// (Sızdırılan API anahtarı istemci yanıtında görünmemeli.
	//  Fail-fast, gizli chunk iletilmeden önce akışı sonlandırır.)
	if strings.Contains(responseStr, "sk-proj-ABC123XYZ7890123456789") {
		t.Errorf("FAIL: Leaked API key found in stream response — fail-fast must terminate the stream before delivering the secret chunk")
		t.Logf("Response: %s", responseStr)
	}

	// 2. Upstream sends all of its chunks independently; fail-fast only controls
	// what the client receives, not what the upstream writes.
	// (Upstream chunk'larını bağımsız olarak gönderir; fail-fast yalnızca istemcinin
	//  aldıklarını kontrol eder, upstream'in yazdıklarını değil.)
	t.Logf("chunksSent from upstream: %d", chunksSent)
}

// ══════════════════════════════════════════════════════════════════════════════
// ADDITIONAL TESTS: Metrics and Vault Validation
// ══════════════════════════════════════════════════════════════════════════════

func TestMetricsIncrement(t *testing.T) {
	t.Parallel()

	upstreamHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}

	ts := newTestSetup(t, 1000, upstreamHandler)
	defer ts.Close()

	// Capture initial metrics
	initialSnapshot := metrics.Global.Snapshot(ts.vault)

	// Send request with sensitive data
	requestBody := map[string]interface{}{
		"model": "gpt-4",
		"messages": []map[string]string{
			{"role": "user", "content": "Email me at test@example.com"},
		},
	}

	bodyBytes, _ := json.Marshal(requestBody)
	resp, _ := http.Post(ts.firewall.URL+"/v1/chat/completions", "application/json", bytes.NewReader(bodyBytes))
	resp.Body.Close()

	// Capture final metrics
	finalSnapshot := metrics.Global.Snapshot(ts.vault)

	// ASSERTIONS: Verify metrics incremented
	if finalSnapshot.RequestsTotal <= initialSnapshot.RequestsTotal {
		t.Error("FAIL: RequestsTotal did not increment")
	}

	if finalSnapshot.MaskedItems <= initialSnapshot.MaskedItems {
		t.Error("FAIL: MaskedItems did not increment")
	}

	if finalSnapshot.MaskedRequests <= initialSnapshot.MaskedRequests {
		t.Error("FAIL: MaskedRequests did not increment")
	}
}

func TestVaultStateAfterMasking(t *testing.T) {
	t.Parallel()

	upstreamHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}

	ts := newTestSetup(t, 10, upstreamHandler)
	defer ts.Close()

	// Send multiple requests with different emails
	emails := []string{"alice@example.com", "bob@example.com", "charlie@example.com"}

	for _, email := range emails {
		requestBody := map[string]interface{}{
			"model": "gpt-4",
			"messages": []map[string]string{
				{"role": "user", "content": "Contact " + email},
			},
		}

		bodyBytes, _ := json.Marshal(requestBody)
		resp, _ := http.Post(ts.firewall.URL+"/v1/chat/completions", "application/json", bytes.NewReader(bodyBytes))
		resp.Body.Close()
	}

	// ASSERTIONS: Verify vault contains all emails
	stats := ts.vault.Stats()
	if stats.Current != len(emails) {
		t.Errorf("FAIL: Expected vault to contain %d items, got %d", len(emails), stats.Current)
	}

	if stats.TotalHits > 0 {
		t.Logf("Vault hits: %d (unmask operations occurred)", stats.TotalHits)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// TABLE-DRIVEN TESTS: Comprehensive Pattern Coverage
// ══════════════════════════════════════════════════════════════════════════════

func TestPatternMasking_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		inputContent   string
		shouldMask     bool
		sensitiveValue string // value that should NOT appear in masked output
		patternType    string // TOKEN, PII, KEY, etc.
	}{
		{
			name:           "GitHub PAT v1",
			inputContent:   "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ",
			shouldMask:     true,
			sensitiveValue: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
			patternType:    "TOKEN",
		},
		{
			name:           "OpenAI API Key",
			inputContent:   "Use this key: sk-proj-ABC123456789DEF",
			shouldMask:     true,
			sensitiveValue: "sk-proj-ABC123456789DEF",
			patternType:    "TOKEN",
		},
		{
			name:           "Email Address",
			inputContent:   "Contact admin@company.com for help",
			shouldMask:     true,
			sensitiveValue: "admin@company.com",
			patternType:    "PII",
		},
		{
			name:           "Credit Card (new pattern)",
			inputContent:   "Card: 4532 0151 1283 0366",
			shouldMask:     true,
			sensitiveValue: "4532 0151 1283 0366",
			patternType:    "PII",
		},
		{
			name:           "Turkish IBAN (new pattern)",
			inputContent:   "IBAN: TR330006100519786457841326",
			shouldMask:     true,
			sensitiveValue: "TR330006100519786457841326",
			patternType:    "PII",
		},
		{
			// 12345678950: oddSum=25 evenSum=20 → d10=5 sum10=50 → d11=0 (valid checksum)
			name:           "TC Kimlik No (new pattern)",
			inputContent:   "TC: 12345678950",
			shouldMask:     true,
			sensitiveValue: "12345678950",
			patternType:    "PII",
		},
		{
			name:           "Turkish Phone (new pattern)",
			inputContent:   "Phone: +90 532 123 45 67",
			shouldMask:     true,
			sensitiveValue: "+90 532 123 45 67",
			patternType:    "PII",
		},
		{
			name:           "AWS Access Key",
			inputContent:   "Key: AKIAIOSFODNN7EXAMPLE",
			shouldMask:     true,
			sensitiveValue: "AKIAIOSFODNN7EXAMPLE",
			patternType:    "KEY",
		},
		{
			name:         "Safe text (no masking)",
			inputContent: "This is completely safe text with no secrets",
			shouldMask:   false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			upstreamHandler := func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				
				// Verify sensitive data is NOT in request to upstream
				if tc.shouldMask && strings.Contains(string(body), tc.sensitiveValue) {
					t.Errorf("LEAK: Sensitive value %q found in upstream request", tc.sensitiveValue)
				}

				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"ok"}`))
			}

			ts := newTestSetup(t, 1000, upstreamHandler)
			defer ts.Close()

			requestBody := map[string]interface{}{
				"model": "gpt-4",
				"messages": []map[string]string{
					{"role": "user", "content": tc.inputContent},
				},
			}

			bodyBytes, _ := json.Marshal(requestBody)
			resp, err := http.Post(ts.firewall.URL+"/v1/chat/completions", "application/json", bytes.NewReader(bodyBytes))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			resp.Body.Close()

			// Verify masking occurred
			stats := ts.vault.Stats()
			if tc.shouldMask && stats.Current == 0 {
				t.Error("FAIL: Expected masking but vault is empty")
			}
			if !tc.shouldMask && stats.Current > 0 {
				t.Error("FAIL: Unexpected masking occurred for safe text")
			}
		})
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// BENCHMARK TESTS: Zero-Allocation Verification
// ══════════════════════════════════════════════════════════════════════════════

func BenchmarkStreamProcessing_ZeroAlloc(b *testing.B) {
	// Create test setup
	v := vault.New(1000)
	cfg := &config.Config{
		UpstreamURL:    "http://localhost:8080",
		ForwardAPIKey:  "test-key",
		MaskPaths:      true,
		MaskEmails:     true,
		VaultSizeLimit: 1000,
		LogLevel:       "silent",
	}
	m := masker.New(v, cfg)
	proc := NewStreamProcessor(m)

	// Simulate SSE chunks
	chunk := []byte("data: {\"choices\": [{\"delta\": {\"content\": \"Hello world\"}}]}\n\n")

	b.ResetTimer()
	b.ReportAllocs()

	// Benchmark should show minimal allocations
	for i := 0; i < b.N; i++ {
		proc.Process(chunk)
	}
}

func BenchmarkMaskingPerformance(b *testing.B) {
	v := vault.New(10000)
	cfg := &config.Config{
		UpstreamURL:    "http://localhost:8080",
		ForwardAPIKey:  "test-key",
		MaskPaths:      true,
		MaskEmails:     true,
		VaultSizeLimit: 10000,
		LogLevel:       "silent",
	}
	m := masker.New(v, cfg)

	input := "Email: test@example.com Token: ghp_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		m.Mask(input)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// CONCURRENT REQUEST TESTS: Thread-Safety Verification
// ══════════════════════════════════════════════════════════════════════════════

func TestConcurrentRequests_ThreadSafety(t *testing.T) {
	t.Parallel()

	upstreamHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}

	ts := newTestSetup(t, 1000, upstreamHandler)
	defer ts.Close()

	// Send 100 concurrent requests with different emails
	const numRequests = 100
	done := make(chan bool, numRequests)

	for i := 0; i < numRequests; i++ {
		go func(idx int) {
			requestBody := map[string]interface{}{
				"model": "gpt-4",
				"messages": []map[string]string{
					{"role": "user", "content": "Email user" + string(rune(idx)) + "@example.com"},
				},
			}

			bodyBytes, _ := json.Marshal(requestBody)
			resp, err := http.Post(ts.firewall.URL+"/v1/chat/completions", "application/json", bytes.NewReader(bodyBytes))
			if err != nil {
				t.Errorf("Request %d failed: %v", idx, err)
			} else {
				resp.Body.Close()
			}
			done <- true
		}(i)
	}

	// Wait for all requests to complete
	for i := 0; i < numRequests; i++ {
		<-done
	}

	// Verify vault state is consistent (no race conditions)
	stats := ts.vault.Stats()
	if stats.Current == 0 {
		t.Error("FAIL: Vault is empty after concurrent requests")
	}
	if stats.Current > numRequests {
		t.Errorf("FAIL: Vault has more items (%d) than requests (%d)", stats.Current, numRequests)
	}

	// Verify metrics are consistent
	snapshot := metrics.Global.Snapshot(ts.vault)
	if snapshot.RequestsTotal < int64(numRequests) {
		t.Errorf("FAIL: RequestsTotal (%d) less than expected (%d)", snapshot.RequestsTotal, numRequests)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// HEALTH ENDPOINT TEST
// ══════════════════════════════════════════════════════════════════════════════

func TestHealthEndpoint(t *testing.T) {
	t.Parallel()

	upstreamHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	ts := newTestSetup(t, 1000, upstreamHandler)
	defer ts.Close()

	resp, err := http.Get(ts.firewall.URL + "/health")
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	defer resp.Body.Close()

	// ASSERTIONS
	if resp.StatusCode != http.StatusOK {
		t.Errorf("FAIL: Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ok") {
		t.Errorf("FAIL: Expected 'ok' in response, got: %s", string(body))
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ROUND-TRIP VERIFICATION: Multiple Pattern Types
// ══════════════════════════════════════════════════════════════════════════════

func TestRoundTrip_MultiplePatterns(t *testing.T) {
	t.Parallel()

	// Mock upstream that echoes request in response
	upstreamHandler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		
		// Parse the request
		var req map[string]interface{}
		json.Unmarshal(body, &req)
		
		// Extract the content (which should be masked)
		messages := req["messages"].([]interface{})
		firstMsg := messages[0].(map[string]interface{})
		maskedContent := firstMsg["content"].(string)
		
		// Echo back in response (will be unmasked by firewall)
		response := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"role":    "assistant",
						"content": maskedContent,
					},
				},
			},
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}

	ts := newTestSetup(t, 1000, upstreamHandler)
	defer ts.Close()

	// Original content with multiple sensitive values
	originalContent := "Email: admin@company.com, Phone: +90 532 123 45 67, Card: 4532-0151-1283-0366"

	requestBody := map[string]interface{}{
		"model": "gpt-4",
		"messages": []map[string]string{
			{"role": "user", "content": originalContent},
		},
	}

	bodyBytes, _ := json.Marshal(requestBody)
	resp, err := http.Post(ts.firewall.URL+"/v1/chat/completions", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(resp.Body)
	
	var response map[string]interface{}
	json.Unmarshal(responseBody, &response)
	
	// Extract the unmasked content from response
	if choices, ok := response["choices"].([]interface{}); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]interface{}); ok {
			if message, ok := choice["message"].(map[string]interface{}); ok {
				if content, ok := message["content"].(string); ok {
					// ASSERTION: Unmasked content should match original
					if content != originalContent {
						t.Errorf("FAIL: Round-trip mismatch\nOriginal: %s\nGot:      %s", originalContent, content)
					}
					
					// Verify no vault labels remain
					if strings.Contains(content, "[[") {
						t.Errorf("FAIL: Vault labels remain in final output: %s", content)
					}
					
					return
				}
			}
		}
	}
	
	t.Errorf("FAIL: Could not extract content from response: %s", string(responseBody))
}
