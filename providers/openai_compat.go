// openai_compat.go — All providers that speak the OpenAI /v1/chat/completions
// protocol (OpenAI uyumlu protokol konuşan tüm sağlayıcılar).
//
// Architecture (mimari):
//
//	openAICompatProvider is the shared base struct (paylaşılan temel yapı).
//	Each concrete provider type embeds it and optionally overrides methods.
//	Adding a new OpenAI-compatible provider = 3 lines.
//	(Yeni bir OpenAI uyumlu sağlayıcı eklemek = 3 satır.)
package providers

import (
	"net/http"
	"strings"
)

// ── Base struct (temel yapı) ──────────────────────────────────────────────────

// openAICompatProvider is the shared implementation for every provider
// that accepts the OpenAI chat-completions wire format.
// (OpenAI sohbet-tamamlama kablo formatını kabul eden her sağlayıcı için
//
//	paylaşılan uygulama.)
type openAICompatProvider struct {
	name    string // display name (görüntüleme adı)
	pattern string // lowercase URL substring to match (eşleştirilecek küçük harfli URL alt dizisi)
}

func (p *openAICompatProvider) Name() string       { return p.name }
func (p *openAICompatProvider) Protocol() Protocol { return ProtocolOpenAI }

func (p *openAICompatProvider) Matches(u string) bool {
	return strings.Contains(u, p.pattern)
}

func (p *openAICompatProvider) PrepareHeaders(dst http.Header, apiKey string) {
	if apiKey != "" && apiKey != "none" {
		setBearer(dst, apiKey)
		dst.Del("x-api-key")
		dst.Del("x-goog-api-key")
		dst.Del("api-key")
	} else {
		dst.Set("Content-Type", "application/json")
	}
}

func (p *openAICompatProvider) IsStream(resp *http.Response) bool { return isSSE(resp) }

// ── Concrete providers (somut sağlayıcılar) ───────────────────────────────────

// OpenAIProvider — https://api.openai.com
// Covers: GPT-4o, GPT-4, GPT-3.5, Codex (text-davinci-003, code-davinci-002)
// (GPT-4o, GPT-4, GPT-3.5, Codex modellerini kapsar)
type OpenAIProvider struct{ openAICompatProvider }

func NewOpenAIProvider() *OpenAIProvider {
	return &OpenAIProvider{openAICompatProvider{name: "OpenAI / Codex", pattern: "api.openai.com"}}
}

// Override — OpenAI specific: forward the organization header if present.
// (Geçersiz kılma — OpenAI'a özgü: varsa organizasyon başlığını ilet.)
func (p *OpenAIProvider) PrepareHeaders(dst http.Header, apiKey string) {
	p.openAICompatProvider.PrepareHeaders(dst, apiKey)
	// openai-organization is forwarded by the allow-list in handler.go
}

// ── AzureOpenAIProvider — https://<resource>.openai.azure.com ─────────────────
// Azure uses api-key header instead of Authorization: Bearer.
// URL pattern: *.openai.azure.com
// (Azure, Authorization: Bearer yerine api-key başlığı kullanır.)
type AzureOpenAIProvider struct{ openAICompatProvider }

func NewAzureOpenAIProvider() *AzureOpenAIProvider {
	return &AzureOpenAIProvider{openAICompatProvider{name: "Azure OpenAI", pattern: "openai.azure.com"}}
}

func (p *AzureOpenAIProvider) PrepareHeaders(dst http.Header, apiKey string) {
	if apiKey != "" && apiKey != "none" {
		dst.Set("api-key", apiKey) // Azure-specific header (Azure'a özgü başlık)
		dst.Del("Authorization")
		dst.Del("x-api-key")
		dst.Del("x-goog-api-key")
	}
	dst.Set("Content-Type", "application/json")
}

// ── GroqProvider — https://api.groq.com ──────────────────────────────────────
// Ultra-fast inference, fully OpenAI-compatible.
// (Ultra-hızlı çıkarım, tamamen OpenAI uyumlu.)
type GroqProvider struct{ openAICompatProvider }

func (p *GroqProvider) Name() string          { return "Groq" }
func (p *GroqProvider) Matches(u string) bool { return strings.Contains(u, "api.groq.com") }

// ── TogetherAIProvider — https://api.together.xyz ────────────────────────────
// Open-source model hosting, OpenAI-compatible.
// (Açık kaynak model barındırma, OpenAI uyumlu.)
type TogetherAIProvider struct{ openAICompatProvider }

func (p *TogetherAIProvider) Name() string { return "Together AI" }
func (p *TogetherAIProvider) Matches(u string) bool {
	return strings.Contains(u, "together.xyz") || strings.Contains(u, "together.ai")
}

// ── PerplexityProvider — https://api.perplexity.ai ───────────────────────────
// Web-search augmented LLM, OpenAI-compatible.
// (Web aramalı LLM, OpenAI uyumlu.)
type PerplexityProvider struct{ openAICompatProvider }

func (p *PerplexityProvider) Name() string          { return "Perplexity" }
func (p *PerplexityProvider) Matches(u string) bool { return strings.Contains(u, "perplexity.ai") }

// ── MistralProvider — https://api.mistral.ai ─────────────────────────────────
type MistralProvider struct{ openAICompatProvider }

func (p *MistralProvider) Name() string          { return "Mistral AI" }
func (p *MistralProvider) Matches(u string) bool { return strings.Contains(u, "mistral.ai") }

// ── CohereProvider — https://api.cohere.com ──────────────────────────────────
// Cohere has its own protocol but also exposes /v2/chat (OpenAI-compatible).
// (Cohere'nin kendi protokolü var ancak OpenAI uyumlu /v2/chat uç noktası da sunuyor.)
type CohereProvider struct{ openAICompatProvider }

func (p *CohereProvider) Name() string { return "Cohere" }
func (p *CohereProvider) Matches(u string) bool {
	return strings.Contains(u, "cohere.com") || strings.Contains(u, "cohere.ai")
}

// ── DeepSeekProvider — https://api.deepseek.com ──────────────────────────────
// High-performance Chinese LLM, OpenAI-compatible.
// (Yüksek performanslı Çin LLM'i, OpenAI uyumlu.)
type DeepSeekProvider struct{ openAICompatProvider }

func (p *DeepSeekProvider) Name() string          { return "DeepSeek" }
func (p *DeepSeekProvider) Matches(u string) bool { return strings.Contains(u, "deepseek.com") }

// ── XAIProvider — https://api.x.ai (Grok) ────────────────────────────────────
// Elon Musk's xAI Grok models, OpenAI-compatible.
// (Elon Musk'ın xAI Grok modelleri, OpenAI uyumlu.)
type XAIProvider struct{ openAICompatProvider }

func (p *XAIProvider) Name() string          { return "xAI (Grok)" }
func (p *XAIProvider) Matches(u string) bool { return strings.Contains(u, "api.x.ai") }

// ── Local providers (yerel sağlayıcılar) ─────────────────────────────────────

// OllamaProvider — http://localhost:11434
// Runs open-source models locally, fully OpenAI-compatible.
// (Açık kaynak modelleri yerel olarak çalıştırır, tamamen OpenAI uyumlu.)
type OllamaProvider struct{ openAICompatProvider }

func (p *OllamaProvider) Name() string { return "Ollama (local)" }
func (p *OllamaProvider) Matches(u string) bool {
	return strings.Contains(u, ":11434") || strings.Contains(u, "ollama")
}

// PrepareHeaders override — Ollama accepts any string as Bearer, but some
// builds require no auth at all. We still set it for uniformity.
// (Ollama, Bearer olarak herhangi bir dize kabul eder; bazı yapılarda
//
//	hiç kimlik doğrulaması gerekmez. Tekdüzelik için yine de ayarlıyoruz.)
func (p *OllamaProvider) PrepareHeaders(dst http.Header, apiKey string) {
	if apiKey != "" && apiKey != "none" {
		setBearer(dst, apiKey)
	}
	dst.Set("Content-Type", "application/json")
}

// LMStudioProvider — http://localhost:1234 (LM Studio local server)
// (LM Studio yerel sunucusu.)
type LMStudioProvider struct{ openAICompatProvider }

func (p *LMStudioProvider) Name() string { return "LM Studio (local)" }
func (p *LMStudioProvider) Matches(u string) bool {
	return strings.Contains(u, ":1234") || strings.Contains(u, "lmstudio")
}

func (p *LMStudioProvider) PrepareHeaders(dst http.Header, apiKey string) {
	// LM Studio ignores the auth header but expects Content-Type.
	// (LM Studio kimlik doğrulama başlığını yok sayar ancak Content-Type bekler.)
	if apiKey != "" && apiKey != "none" {
		setBearer(dst, apiKey) // harmless if ignored
	} else {
		dst.Set("Content-Type", "application/json")
	}
}

// ── GenericProvider ───────────────────────────────────────────────────────────

// GenericProvider is the catch-all (genel yakalayıcı) for any OpenAI-compatible
// API not listed above. It matches every URL so it must be last in Registry.
//
// Use cases (kullanım senaryoları):
//   - Internal/private model servers
//   - Future providers not yet in the registry
//   - UPSTREAM_URL overrides during development
//
// (İç/özel model sunucuları, henüz kayıtta olmayan gelecekteki sağlayıcılar,
//
//	geliştirme sırasındaki UPSTREAM_URL geçersiz kılmaları.)
type GenericProvider struct{ openAICompatProvider }

func (p *GenericProvider) Name() string          { return "Generic (OpenAI-compatible)" }
func (p *GenericProvider) Matches(_ string) bool { return true }
func (p *GenericProvider) Protocol() Protocol    { return ProtocolGeneric }

// init wires the concrete types that use NewXxx constructors into the
// exported struct vars used by Registry.  Simpler types set fields directly
// in the Registry literal above.
// (NewXxx yapıcılarını kullanan somut türleri, Registry tarafından kullanılan
//
//	dışa aktarılan yapı değişkenlerine bağlar.)
func init() {
	// Replace zero-value embeddings with properly named instances.
	// (Sıfır değerli gömme yapıları düzgün adlandırılmış örneklerle değiştir.)
	for i, p := range Registry {
		switch p.(type) {
		case *OpenAIProvider:
			Registry[i] = NewOpenAIProvider()
		case *AzureOpenAIProvider:
			Registry[i] = NewAzureOpenAIProvider()
		}
	}
	hintMap["openai"] = NewOpenAIProvider()
	hintMap["azure"] = NewAzureOpenAIProvider()
}

// ── compile-time interface checks (derleme zamanı arayüz kontrolleri) ─────────
// These lines produce a compile error if any type stops satisfying Provider.
// (Bu satırlar, herhangi bir tür Provider'ı karşılamayı bırakırsa derleme hatası üretir.)
var (
	_ Provider = (*OpenAIProvider)(nil)
	_ Provider = (*AzureOpenAIProvider)(nil)
	_ Provider = (*GroqProvider)(nil)
	_ Provider = (*TogetherAIProvider)(nil)
	_ Provider = (*PerplexityProvider)(nil)
	_ Provider = (*MistralProvider)(nil)
	_ Provider = (*CohereProvider)(nil)
	_ Provider = (*DeepSeekProvider)(nil)
	_ Provider = (*XAIProvider)(nil)
	_ Provider = (*OllamaProvider)(nil)
	_ Provider = (*LMStudioProvider)(nil)
	_ Provider = (*GenericProvider)(nil)
)
