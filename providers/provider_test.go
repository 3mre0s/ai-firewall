package providers

import (
	"net/http"
	"testing"
)

func TestDetect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		url          string
		expectedName string
	}{
		{"https://api.anthropic.com/v1/messages", "Anthropic"},
		{"https://generativelanguage.googleapis.com/v1beta", "Google Gemini"},
		{"https://api.openai.com/v1", "OpenAI / Codex"},
		{"https://api.groq.com/openai/v1", "Groq"},
		{"http://localhost:11434", "Ollama (local)"},
		{"http://localhost:8080/v1", "Generic (OpenAI-compatible)"}, // catch-all generic provider
	}

	for _, tc := range tests {
		p := Detect(tc.url)
		if p.Name() != tc.expectedName {
			t.Errorf("for url %q: expected provider %q, got %q", tc.url, tc.expectedName, p.Name())
		}
	}
}

func TestDetectByHint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		hint         string
		expectedName string
	}{
		{"anthropic", "Anthropic"},
		{"gemini", "Google Gemini"},
		{"openai", "OpenAI / Codex"},
		{"groq", "Groq"},
		{"ollama", "Ollama (local)"},
		{"lmstudio", "LM Studio (local)"},
		{"generic", "Generic (OpenAI-compatible)"},
		{"unknown_hint", "Generic (OpenAI-compatible)"}, // fallback
	}

	for _, tc := range tests {
		p := DetectByHint(tc.hint)
		if p.Name() != tc.expectedName {
			t.Errorf("for hint %q: expected provider %q, got %q", tc.hint, tc.expectedName, p.Name())
		}
	}
}

func TestAnthropicPrepareHeaders(t *testing.T) {
	t.Parallel()

	p := &AnthropicProvider{}
	dst := make(http.Header)

	p.PrepareHeaders(dst, "my-anthropic-key")

	if dst.Get("x-api-key") != "my-anthropic-key" {
		t.Errorf("expected x-api-key to be 'my-anthropic-key', got %q", dst.Get("x-api-key"))
	}
	if dst.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type to be 'application/json', got %q", dst.Get("Content-Type"))
	}
	if dst.Get("anthropic-version") != "2023-06-01" {
		t.Errorf("expected anthropic-version to be set to default, got %q", dst.Get("anthropic-version"))
	}
}

func TestGeminiPrepareHeaders(t *testing.T) {
	t.Parallel()

	p := &GeminiProvider{}

	// simple key auth
	dst := make(http.Header)
	p.PrepareHeaders(dst, "my-gemini-key")
	if dst.Get("x-goog-api-key") != "my-gemini-key" {
		t.Errorf("expected x-goog-api-key to be 'my-gemini-key', got %q", dst.Get("x-goog-api-key"))
	}
	if dst.Get("Authorization") != "" {
		t.Errorf("expected Authorization to be empty, got %q", dst.Get("Authorization"))
	}

	// OAuth2 key auth
	dst2 := make(http.Header)
	p.PrepareHeaders(dst2, "ya29.oauth-token")
	if dst2.Get("Authorization") != "Bearer ya29.oauth-token" {
		t.Errorf("expected Authorization to be Bearer, got %q", dst2.Get("Authorization"))
	}
	if dst2.Get("x-goog-api-key") != "" {
		t.Errorf("expected x-goog-api-key to be empty, got %q", dst2.Get("x-goog-api-key"))
	}
}

func TestIsStream(t *testing.T) {
	t.Parallel()

	p := &AnthropicProvider{}

	respSSE := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"text/event-stream"},
		},
	}
	if !p.IsStream(respSSE) {
		t.Errorf("expected IsStream to return true for text/event-stream")
	}

	respJSON := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}
	if p.IsStream(respJSON) {
		t.Errorf("expected IsStream to return false for application/json")
	}
}

func TestAnthropicPrepareHeaders_PassthroughAndSanitize(t *testing.T) {
	t.Parallel()

	p := &AnthropicProvider{}

	// Case 1: Passthrough ("none") preserves existing client Authorization
	dst := make(http.Header)
	dst.Set("Authorization", "Bearer client-auth-token")
	p.PrepareHeaders(dst, "none")

	if dst.Get("x-api-key") != "" {
		t.Errorf("expected x-api-key to be empty in passthrough mode, got %q", dst.Get("x-api-key"))
	}
	if dst.Get("Authorization") != "Bearer client-auth-token" {
		t.Errorf("expected client Authorization header to be preserved, got %q", dst.Get("Authorization"))
	}

	// Case 2: Concrete key sets x-api-key and deletes client Authorization
	dst2 := make(http.Header)
	dst2.Set("Authorization", "Bearer client-auth-token")
	p.PrepareHeaders(dst2, "real-api-key")

	if dst2.Get("x-api-key") != "real-api-key" {
		t.Errorf("expected x-api-key to be set, got %q", dst2.Get("x-api-key"))
	}
	if dst2.Get("Authorization") != "" {
		t.Errorf("expected client Authorization to be deleted, got %q", dst2.Get("Authorization"))
	}
}

func TestGeminiPrepareHeaders_PassthroughAndSanitize(t *testing.T) {
	t.Parallel()

	p := &GeminiProvider{}

	// Case 1: Passthrough ("none") preserves existing client Authorization/x-goog-api-key
	dst := make(http.Header)
	dst.Set("Authorization", "Bearer client-auth-token")
	p.PrepareHeaders(dst, "none")

	if dst.Get("x-goog-api-key") != "" {
		t.Errorf("expected x-goog-api-key to be empty, got %q", dst.Get("x-goog-api-key"))
	}
	if dst.Get("Authorization") != "Bearer client-auth-token" {
		t.Errorf("expected client Authorization to be preserved, got %q", dst.Get("Authorization"))
	}

	// Case 2: Concrete key (simple key) deletes client Authorization/x-api-key
	dst2 := make(http.Header)
	dst2.Set("Authorization", "Bearer client-auth-token")
	dst2.Set("x-api-key", "some-other-key")
	p.PrepareHeaders(dst2, "real-gemini-key")

	if dst2.Get("x-goog-api-key") != "real-gemini-key" {
		t.Errorf("expected x-goog-api-key to be set, got %q", dst2.Get("x-goog-api-key"))
	}
	if dst2.Get("Authorization") != "" {
		t.Errorf("expected client Authorization to be deleted, got %q", dst2.Get("Authorization"))
	}
	if dst2.Get("x-api-key") != "" {
		t.Errorf("expected client x-api-key to be deleted, got %q", dst2.Get("x-api-key"))
	}

	// Case 3: Concrete key (OAuth2 ya29. key) deletes client x-goog-api-key
	dst3 := make(http.Header)
	dst3.Set("x-goog-api-key", "old-key")
	p.PrepareHeaders(dst3, "ya29.new-oauth-token")

	if dst3.Get("Authorization") != "Bearer ya29.new-oauth-token" {
		t.Errorf("expected Authorization to be set to Bearer token, got %q", dst3.Get("Authorization"))
	}
	if dst3.Get("x-goog-api-key") != "" {
		t.Errorf("expected x-goog-api-key to be deleted, got %q", dst3.Get("x-goog-api-key"))
	}
}

func TestOpenAICompatPrepareHeaders_PassthroughAndSanitize(t *testing.T) {
	t.Parallel()

	// Using OpenAIProvider which embeds openAICompatProvider
	p := NewOpenAIProvider()

	// Case 1: Passthrough ("none") preserves existing headers
	dst := make(http.Header)
	dst.Set("x-api-key", "client-anthropic-key")
	p.PrepareHeaders(dst, "none")

	if dst.Get("Authorization") != "" {
		t.Errorf("expected Authorization to be empty, got %q", dst.Get("Authorization"))
	}
	if dst.Get("x-api-key") != "client-anthropic-key" {
		t.Errorf("expected client x-api-key to be preserved, got %q", dst.Get("x-api-key"))
	}

	// Case 2: Concrete key sets Bearer token and deletes conflicting headers
	dst2 := make(http.Header)
	dst2.Set("x-api-key", "client-anthropic-key")
	dst2.Set("x-goog-api-key", "client-gemini-key")
	dst2.Set("api-key", "client-azure-key")
	p.PrepareHeaders(dst2, "real-openai-key")

	if dst2.Get("Authorization") != "Bearer real-openai-key" {
		t.Errorf("expected Authorization Bearer to be set, got %q", dst2.Get("Authorization"))
	}
	if dst2.Get("x-api-key") != "" {
		t.Errorf("expected client x-api-key to be deleted, got %q", dst2.Get("x-api-key"))
	}
	if dst2.Get("x-goog-api-key") != "" {
		t.Errorf("expected client x-goog-api-key to be deleted, got %q", dst2.Get("x-goog-api-key"))
	}
	if dst2.Get("api-key") != "" {
		t.Errorf("expected client api-key to be deleted, got %q", dst2.Get("api-key"))
	}
}

