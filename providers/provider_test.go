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
