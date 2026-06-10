package providers

import (
	"net/http"
	"strings"
)

// AnthropicProvider handles traffic to api.anthropic.com.
//
// Key differences from OpenAI (OpenAI'den temel farklar):
//   - Auth: x-api-key header (not Authorization: Bearer)
//   - Requires anthropic-version header (zorunlu başlık)
//   - Endpoint: POST /v1/messages
type AnthropicProvider struct{}

func (p *AnthropicProvider) Name() string { return "Anthropic" }

func (p *AnthropicProvider) Matches(u string) bool {
	return strings.Contains(u, "anthropic.com")
}

func (p *AnthropicProvider) Protocol() Protocol { return ProtocolAnthropic }

func (p *AnthropicProvider) PrepareHeaders(dst http.Header, apiKey string) {
	// Anthropic uses x-api-key, NOT Authorization: Bearer
	// (Anthropic, Authorization: Bearer yerine x-api-key kullanır)
	dst.Set("x-api-key", apiKey)
	dst.Set("Content-Type", "application/json")

	// anthropic-version is required; use latest stable if client didn't send one.
	// (anthropic-version zorunludur; istemci göndermemişse en son kararlı sürümü kullan.)
	if dst.Get("anthropic-version") == "" {
		dst.Set("anthropic-version", "2023-06-01")
	}
}

func (p *AnthropicProvider) IsStream(resp *http.Response) bool { return isSSE(resp) }
