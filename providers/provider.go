// Package providers defines the Provider interface and an auto-detection
// registry that maps upstream URLs to the correct protocol adapter.
//
// Adding a new provider (yeni sağlayıcı eklemek):
//  1. Implement the Provider interface (or embed openAICompatProvider).
//  2. Register an instance in the Registry slice below.
//  3. More specific URL patterns must appear before broader ones.
//
// (Yeni bir sağlayıcı eklemek:
//  1. Provider arayüzünü uygula (veya openAICompatProvider'ı göm).
//  2. Bir örneği aşağıdaki Registry dilimine kaydet.
//  3. Daha spesifik URL desenleri genişlerden önce yer almalı.)
package providers

import (
	"net/http"
	"strings"
)

// Protocol identifies the wire format used by a provider.
// (Bir sağlayıcının kullandığı kablo formatını tanımlar.)
type Protocol string

const (
	ProtocolAnthropic Protocol = "anthropic" // /v1/messages, x-api-key
	ProtocolOpenAI    Protocol = "openai"    // /v1/chat/completions, Bearer token
	ProtocolGemini    Protocol = "gemini"    // /v1beta/models/..., x-goog-api-key
	ProtocolGeneric   Protocol = "generic"   // OpenAI-compatible catch-all (genel amaçlı)
)

// Provider describes how to authenticate and communicate with one AI backend.
// Each implementation is stateless (durumsuz) — safe to share across goroutines.
// (Her uygulama durumsuz olup goroutine'ler arasında paylaşılması güvenlidir.)
type Provider interface {
	// Name returns a human-readable identifier shown in logs.
	// (Log kayıtlarında gösterilen insan tarafından okunabilir tanımlayıcı.)
	Name() string

	// Matches reports whether this provider handles the given lowercase upstream URL.
	// (Bu sağlayıcının verilen küçük harfli upstream URL'yi yönetip yönetmediğini bildirir.)
	Matches(upstreamURL string) bool

	// Protocol returns the wire protocol so the handler can apply
	// provider-specific body transformations if needed in the future.
	// (Gelecekte gerekirse işleyicinin sağlayıcıya özgü gövde dönüşümleri
	//  uygulayabilmesi için kablo protokolünü döner.)
	Protocol() Protocol

	// PrepareHeaders sets auth and any required headers on the outgoing
	// upstream request. dst already contains the allow-listed client headers.
	// (Giden upstream isteğinde kimlik doğrulama ve gerekli başlıkları ayarlar.
	//  dst zaten izin listesindeki istemci başlıklarını içeriyor.)
	PrepareHeaders(dst http.Header, apiKey string)

	// IsStream reports whether resp is a Server-Sent Events (SSE) stream.
	// (resp'in bir Sunucu Tarafından Gönderilen Olaylar (SSE) akışı olup
	//  olmadığını bildirir.)
	IsStream(resp *http.Response) bool
}

// Registry is the ordered list of all known providers.
// Detect() iterates this list and returns the first match.
// GenericProvider must be last — it matches everything.
//
// (Detect() bu listeyi yineler ve ilk eşleşmeyi döner.
//  GenericProvider son olmalıdır — her şeyle eşleşir.)
var Registry = []Provider{
	// Closed / proprietary protocols (kapalı / tescilli protokoller)
	&AnthropicProvider{},
	&GeminiProvider{},

	// OpenAI-compatible (açık uyumlu) — specific hosts before generic
	&AzureOpenAIProvider{},
	&GroqProvider{},
	&TogetherAIProvider{},
	&PerplexityProvider{},
	&MistralProvider{},
	&CohereProvider{},
	&DeepSeekProvider{},
	&XAIProvider{},
	&AntigravityProvider{},
	&OllamaProvider{},
	&LMStudioProvider{},
	&OpenAIProvider{},

	// Catch-all (genel amaçlı) — must be last
	&GenericProvider{},
}

// hintMap maps PROVIDER_HINT values to concrete providers.
// (PROVIDER_HINT değerlerini somut sağlayıcılara eşler.)
var hintMap = map[string]Provider{
	"anthropic":   &AnthropicProvider{},
	"gemini":      &GeminiProvider{},
	"azure":       &AzureOpenAIProvider{},
	"groq":        &GroqProvider{},
	"together":    &TogetherAIProvider{},
	"perplexity":  &PerplexityProvider{},
	"mistral":     &MistralProvider{},
	"cohere":      &CohereProvider{},
	"deepseek":    &DeepSeekProvider{},
	"xai":         &XAIProvider{},
	"antigravity": &AntigravityProvider{},
	"ollama":      &OllamaProvider{},
	"lmstudio":    &LMStudioProvider{},
	"openai":      &OpenAIProvider{},
	"generic":     &GenericProvider{},
}

// Detect returns the best Provider for the given upstream base URL.
// The URL is lowercased before matching so callers need not normalise it.
//
// (Verilen upstream temel URL için en uygun Provider'ı döner.
//  URL, çağıranların normalleştirmesi gerekmeyecek şekilde küçük harfe çevrilir.)
func Detect(upstreamBaseURL string) Provider {
	u := strings.ToLower(upstreamBaseURL)
	for _, p := range Registry {
		if p.Matches(u) {
			return p
		}
	}
	return &GenericProvider{} // never reached, but satisfies the compiler
}

// DetectByHint returns the Provider matching the given hint string.
// hint must be one of the keys in hintMap (lowercase). If not found,
// falls back to GenericProvider.
//
// (Verilen hint dizesiyle eşleşen Provider'ı döner.
//  hint, hintMap'teki anahtarlardan biri (küçük harf) olmalıdır.
//  Bulunamazsa GenericProvider'a döner.)
func DetectByHint(hint string) Provider {
	if p, ok := hintMap[strings.ToLower(hint)]; ok {
		return p
	}
	return &GenericProvider{}
}

// ── shared helpers (paylaşılan yardımcılar) ───────────────────────────────────

// isSSE is reused by all providers' IsStream implementations.
// (Tüm sağlayıcıların IsStream uygulamaları tarafından yeniden kullanılır.)
func isSSE(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream")
}

// setBearer sets Authorization: Bearer <key> and Content-Type.
// (Authorization: Bearer <anahtar> ve Content-Type ayarlar.)
func setBearer(dst http.Header, apiKey string) {
	dst.Set("Authorization", "Bearer "+apiKey)
	dst.Set("Content-Type", "application/json")
}
