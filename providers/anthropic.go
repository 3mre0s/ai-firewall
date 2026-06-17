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
	//
	// Passthrough mode: when FORWARD_API_KEY=none the firewall skips key injection
	// and lets the client's own Authorization: Bearer (ANTHROPIC_AUTH_TOKEN) flow
	// through unmodified — used by Claude Code Pro/Max subscription users.
	// (Passthrough modu: FORWARD_API_KEY=none olduğunda, firewall anahtar enjeksiyonunu
	//  atlar ve istemcinin kendi Authorization: Bearer header'ının geçmesine izin verir.
	//  Claude Code Pro/Max abonelik kullanıcıları için kullanılır.)
	if apiKey != "" && apiKey != "none" {
		dst.Set("x-api-key", apiKey)
		// Security cleanup: remove any client-supplied Bearer token so only our
		// injected key reaches the upstream — prevents confusion and credential leaks.
		// (Güvenlik temizliği: istemciden gelen Bearer token'ı kaldır, böylece upstream'e
		//  yalnızca enjekte ettiğimiz anahtar ulaşır — karışıklık ve sızıntı önlenir.)
		dst.Del("Authorization")
	}
	dst.Set("Content-Type", "application/json")

	// anthropic-version is required; use latest stable if client didn't send one.
	// (anthropic-version zorunludur; istemci göndermemişse en son kararlı sürümü kullan.)
	if dst.Get("anthropic-version") == "" {
		dst.Set("anthropic-version", "2023-06-01")
	}
}

func (p *AnthropicProvider) IsStream(resp *http.Response) bool { return isSSE(resp) }
