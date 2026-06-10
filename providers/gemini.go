package providers

import (
	"net/http"
	"strings"
)

// GeminiProvider handles traffic to generativelanguage.googleapis.com.
//
// Auth mechanism (kimlik doğrulama mekanizması):
//   - x-goog-api-key header (Google Cloud API key)
//   - Alternatively: Authorization: Bearer <OAuth2 token>
//   - Endpoint pattern: /v1beta/models/{model}:generateContent
//   - Streaming endpoint: /v1beta/models/{model}:streamGenerateContent
type GeminiProvider struct{}

func (p *GeminiProvider) Name() string { return "Google Gemini" }

func (p *GeminiProvider) Matches(u string) bool {
	return strings.Contains(u, "generativelanguage.googleapis.com") ||
		strings.Contains(u, "aiplatform.googleapis.com")
}

func (p *GeminiProvider) Protocol() Protocol { return ProtocolGemini }

func (p *GeminiProvider) PrepareHeaders(dst http.Header, apiKey string) {
	// Google recommends x-goog-api-key for simple API key auth.
	// If an OAuth token is in use, it would start with "ya29." — in that
	// case fall back to Authorization: Bearer.
	// (Google, basit API anahtarı kimlik doğrulaması için x-goog-api-key önerir.
	//  OAuth token kullanılıyorsa "ya29." ile başlar — bu durumda
	//  Authorization: Bearer'a geri dönülür.)
	if strings.HasPrefix(apiKey, "ya29.") || strings.HasPrefix(apiKey, "Bearer ") {
		dst.Set("Authorization", "Bearer "+strings.TrimPrefix(apiKey, "Bearer "))
	} else {
		dst.Set("x-goog-api-key", apiKey)
	}
	dst.Set("Content-Type", "application/json")
}

func (p *GeminiProvider) IsStream(resp *http.Response) bool {
	// Gemini streaming uses the same SSE format.
	// (Gemini akışı aynı SSE formatını kullanır.)
	return isSSE(resp)
}
