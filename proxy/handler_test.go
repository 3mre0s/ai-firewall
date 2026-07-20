package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/3mre0s/ai-firewall/audit"
	"github.com/3mre0s/ai-firewall/config"
	"github.com/3mre0s/ai-firewall/masker"
	"github.com/3mre0s/ai-firewall/vault"
)

func TestServerPipelineStandard(t *testing.T) {
	t.Parallel()

	// 1. Set up mock upstream server (the real AI API)
	// It checks that the incoming payload is masked, and responds with masked labels
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		bodyStr := string(body)

		// Verify that the email addresses were masked before reaching upstream
		if strings.Contains(bodyStr, "alice@example.com") {
			t.Errorf("upstream received unmasked email: %s", bodyStr)
		}
		if !strings.Contains(bodyStr, "[[EMAIL_") {
			t.Errorf("upstream did not receive a masked email label: %s", bodyStr)
		}

		// Reply back containing the masked label
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"reply": "Hello ` + bodyStr + `"}`))
	}))
	defer mockUpstream.Close()

	// 2. Initialize proxy config, vault, masker, and server
	cfg := config.LoadForTest()
	cfg.UpstreamURL = mockUpstream.URL

	v := vault.New(100)
	m := masker.New(v, cfg)
	srv := NewServer(cfg, m)

	// 3. Make client request to our proxy
	payload := `{"text": "my contact is alice@example.com"}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	// 4. Validate proxy response
	if rr.Code != http.StatusOK {
		t.Fatalf("expected proxy status 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	responseBody := rr.Body.String()

	// Verify that the email is correctly unmasked back to the client
	if !strings.Contains(responseBody, "alice@example.com") {
		t.Errorf("client response did not contain unmasked email: %s", responseBody)
	}
	if strings.Contains(responseBody, "[[EMAIL_") {
		t.Errorf("client response still contained masked labels: %s", responseBody)
	}
}

func TestServerPipelineStreamingIntegration(t *testing.T) {
	t.Parallel()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		bodyStr := string(body)
		if strings.Contains(bodyStr, "alice@example.com") {
			t.Errorf("upstream received unmasked email: %s", bodyStr)
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("upstream response writer does not support flushing")
			return
		}

		splitAt := strings.Index(bodyStr, "[[EMAIL_")
		if splitAt == -1 {
			t.Errorf("upstream body did not contain a vault label: %s", bodyStr)
			return
		}
		splitAt += len("[[EMAIL_")

		_, _ = io.WriteString(w, "data: ")
		_, _ = io.WriteString(w, bodyStr[:splitAt])
		flusher.Flush()

		_, _ = io.WriteString(w, bodyStr[splitAt:])
		_, _ = io.WriteString(w, "\n\n")
		flusher.Flush()

		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer mockUpstream.Close()

	cfg := config.LoadForTest()
	cfg.UpstreamURL = mockUpstream.URL

	v := vault.New(100)
	m := masker.New(v, cfg)
	srv := NewServer(cfg, m)

	payload := `{"text":"my contact is alice@example.com"}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected proxy status 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	responseBody := rr.Body.String()
	if !strings.Contains(responseBody, "alice@example.com") {
		t.Errorf("streaming response did not contain unmasked email: %s", responseBody)
	}
	if strings.Contains(responseBody, "[[EMAIL_") {
		t.Errorf("streaming response still contained masked labels: %s", responseBody)
	}
	if !strings.Contains(responseBody, "data: ") {
		t.Errorf("expected SSE framing to be preserved, got: %s", responseBody)
	}
}

func TestServerRecoversFromPanic(t *testing.T) {
	t.Parallel()

	var srv *Server
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewBufferString(`{}`))
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 after panic recovery, got %d", rr.Code)
	}
}

func TestServerHealthEndpoint(t *testing.T) {
	t.Parallel()

	cfg := config.LoadForTest()
	v := vault.New(10)
	m := masker.New(v, cfg)
	srv := NewServer(cfg, m)

	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `{"status":"ok"}`) {
		t.Errorf("expected health body, got %q", rr.Body.String())
	}
}

func TestServerMethodNotAllowed(t *testing.T) {
	t.Parallel()

	cfg := config.LoadForTest()
	v := vault.New(10)
	m := masker.New(v, cfg)
	srv := NewServer(cfg, m)

	req := httptest.NewRequest("GET", "/v1/chat/completions", nil)
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", rr.Code)
	}
}

func TestServerSSRFProtection(t *testing.T) {
	t.Parallel()

	// Mock upstream server to verify the requested path
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// It should receive only the path, not the absolute URI sent by the client
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("SSRF protection failed: expected path /v1/chat/completions, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockUpstream.Close()

	cfg := config.LoadForTest()
	cfg.UpstreamURL = mockUpstream.URL

	v := vault.New(10)
	m := masker.New(v, cfg)
	srv := NewServer(cfg, m)

	// Simulate a malicious client sending an absolute URI (SSRF attempt)
	req := httptest.NewRequest("POST", "http://evil.com/v1/chat/completions", bytes.NewBufferString(`{}`))
	// Force the RequestURI to be the absolute malicious URL as if read directly from the socket
	req.RequestURI = "http://evil.com/v1/chat/completions"

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rr.Code)
	}
}

func TestServerPipelineAuthPassthrough(t *testing.T) {
	t.Parallel()

	// 1. Upstream checks that it receives the client's authentication headers,
	// including the account selector used by ChatGPT-authenticated Codex, and
	// does NOT receive x-api-key since forward API key is "none".
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer client-supplied-token" {
			t.Errorf("upstream did not receive expected client Authorization header, got %q", auth)
		}
		xkey := r.Header.Get("x-api-key")
		if xkey != "" {
			t.Errorf("upstream received x-api-key in passthrough mode: %q", xkey)
		}
		if accountID := r.Header.Get("ChatGPT-Account-ID"); accountID != "account-test" {
			t.Errorf("upstream did not receive ChatGPT account header, got %q", accountID)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockUpstream.Close()

	// 2. Load test config and override key to "none"
	cfg := config.LoadForTest()
	cfg.ForwardAPIKey = "none"
	cfg.UpstreamURL = mockUpstream.URL
	cfg.ProviderHint = "anthropic" // force Anthropic provider to test its PrepareHeaders

	v := vault.New(10)
	m := masker.New(v, cfg)
	srv := NewServer(cfg, m)

	// 3. Make client request with Authorization header
	req := httptest.NewRequest("POST", "/v1/messages", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", "Bearer client-supplied-token")
	req.Header.Set("ChatGPT-Account-ID", "account-test")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected proxy status 200, got %d", rr.Code)
	}
}

func TestServerCodexChatGPTRouteAndHeaders(t *testing.T) {
	t.Parallel()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/backend-api/codex/responses" {
			t.Errorf("upstream path = %q, want ChatGPT Codex Responses path", r.URL.Path)
		}
		for header, want := range map[string]string{
			"Authorization":      "Bearer chatgpt-test-token",
			"ChatGPT-Account-ID": "account-test",
			"Originator":         "codex_cli_rs",
		} {
			if got := r.Header.Get(header); got != want {
				t.Errorf("upstream %s = %q, want %q", header, got, want)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":[]}`))
	}))
	defer mockUpstream.Close()

	cfg := config.LoadForTest()
	cfg.ForwardAPIKey = "none"
	cfg.UpstreamURL = mockUpstream.URL + "/backend-api/codex"
	cfg.ProviderHint = "openai"
	srv := NewServer(cfg, masker.New(vault.New(10), cfg))

	req := httptest.NewRequest("POST", "/responses", bytes.NewBufferString(`{"input":"hello"}`))
	req.Header.Set("Authorization", "Bearer chatgpt-test-token")
	req.Header.Set("ChatGPT-Account-ID", "account-test")
	req.Header.Set("Originator", "codex_cli_rs")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected proxy status 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestServerBlocksRawSecretInStandardResponse(t *testing.T) {
	t.Parallel()
	const fakeToken = "ghp_FAKEDEMO0000000000000000000000000000"

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":"` + fakeToken + `"}`))
	}))
	defer mockUpstream.Close()

	cfg := config.LoadForTest()
	cfg.ForwardAPIKey = "none"
	cfg.UpstreamURL = mockUpstream.URL
	cfg.ProviderHint = "openai"
	traces := audit.NewStore(10)
	srv := NewServer(cfg, masker.New(vault.New(10), cfg), traces)

	req := httptest.NewRequest("POST", "/responses", bytes.NewBufferString(`{"input":"`+fakeToken+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if strings.Contains(rr.Body.String(), fakeToken) {
		t.Fatal("raw secret from standard upstream response reached the client")
	}
	got := traces.List()
	if len(got) != 1 || !got[0].ResponseLeakBlocked || got[0].RestoredItems != 0 {
		t.Fatalf("unexpected response leak trace: %#v", got)
	}
}

func TestServerRestoresPlaceholderDespiteUnrelatedResponsePath(t *testing.T) {
	t.Parallel()
	const fakeToken = "ghp_FAKEDEMO0000000000000000000000000000"

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(append(body, []byte("\n/home/model/workspace/result.txt")...))
	}))
	defer mockUpstream.Close()

	cfg := config.LoadForTest()
	cfg.ForwardAPIKey = "none"
	cfg.UpstreamURL = mockUpstream.URL
	cfg.ProviderHint = "openai"
	traces := audit.NewStore(10)
	srv := NewServer(cfg, masker.New(vault.New(10), cfg), traces)

	req := httptest.NewRequest("POST", "/responses", bytes.NewBufferString(`{"input":"`+fakeToken+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if !strings.Contains(rr.Body.String(), fakeToken) {
		t.Fatalf("known placeholder was not restored: %s", rr.Body.String())
	}
	got := traces.List()
	if len(got) != 1 || got[0].ResponseLeakBlocked || got[0].RestoredItems != 1 {
		t.Fatalf("unexpected restoration trace: %#v", got)
	}
}

func TestServerAllowsCodexModelCatalogGET(t *testing.T) {
	t.Parallel()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/backend-api/codex/models" {
			t.Errorf("upstream request = %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"models":[]}`))
	}))
	defer mockUpstream.Close()

	cfg := config.LoadForTest()
	cfg.ForwardAPIKey = "none"
	cfg.UpstreamURL = mockUpstream.URL + "/backend-api/codex"
	cfg.ProviderHint = "openai"
	srv := NewServer(cfg, masker.New(vault.New(10), cfg))

	req := httptest.NewRequest("GET", "/models?client_version=0.137.0", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("model catalog status = %d, want 200", rr.Code)
	}
}

func TestServerPipelineAuthOverwritten(t *testing.T) {
	t.Parallel()

	// 1. Upstream checks that the client's Authorization header was stripped,
	// and the configured FORWARD_API_KEY was injected as x-api-key.
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "" {
			t.Errorf("expected client Authorization header to be stripped, got %q", auth)
		}
		xkey := r.Header.Get("x-api-key")
		if xkey != "configured-override-key" {
			t.Errorf("expected x-api-key to be 'configured-override-key', got %q", xkey)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockUpstream.Close()

	// 2. Load test config with concrete forward key
	cfg := config.LoadForTest()
	cfg.ForwardAPIKey = "configured-override-key"
	cfg.UpstreamURL = mockUpstream.URL
	cfg.ProviderHint = "anthropic"

	v := vault.New(10)
	m := masker.New(v, cfg)
	srv := NewServer(cfg, m)

	// 3. Make client request with conflicting Authorization header
	req := httptest.NewRequest("POST", "/v1/messages", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", "Bearer client-supplied-token")
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected proxy status 200, got %d", rr.Code)
	}
}
