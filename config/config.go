// Package config loads application settings from environment variables (çevre değişkenleri).
// No config file is needed — a single binary + a handful of env vars is enough.
// (Yapılandırma dosyasına gerek yok; tek binary + birkaç çevre değişkeni yeterli.)
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds every runtime setting for the firewall.
// (Güvenlik duvarının tüm çalışma zamanı ayarlarını tutar.)
type Config struct {
	// ListenPort — the local TCP port the proxy will bind to.
	// (Proxy'nin bağlanacağı yerel TCP portu.)
	// Default: 8080
	ListenPort int

	// UpstreamURL — base URL of the real AI provider.
	// (Gerçek AI sağlayıcısının temel URL'i.)
	// Default: https://api.anthropic.com
	UpstreamURL string

	// ProviderHint — optionally force a specific provider name instead of auto-detecting
	// from UpstreamURL. Leave empty to let the registry auto-detect.
	// (Auto-detect yerine belirli bir sağlayıcı adını zorlamak için isteğe bağlı.
	//  Kayıt defterinin otomatik algılaması için boş bırakın.)
	// Examples: "anthropic", "openai", "gemini", "groq", "ollama", "generic"
	// Env var: PROVIDER_HINT
	ProviderHint string

	// ForwardAPIKey — the real API key forwarded to the upstream provider.
	// NEVER logged or stored on disk.
	// (Gerçek API anahtarı; hiçbir zaman loglanmaz veya diske yazılmaz.)
	// Required.
	ForwardAPIKey string

	// VaultSizeLimit — max number of label→value entries held in memory per session.
	// Prevents unbounded RAM growth on very long conversations.
	// (Oturum başına bellekte tutulan maksimum etiket→değer giriş sayısı.
	//  Çok uzun konuşmalarda sınırsız RAM büyümesini önler.)
	// Default: 1000
	VaultSizeLimit int

	// MaskPaths — whether to detect and mask Unix/Windows file-system paths.
	// (Unix/Windows dosya sistemi yollarını tespit edip maskeleyip maskelemeyeceği.)
	// Default: true
	MaskPaths bool

	// MaskEmails — whether to detect and mask e-mail addresses (PII).
	// (E-posta adreslerini (KTB — Kişisel Tanımlanabilir Bilgi) maskeleyin mi.)
	// Default: true
	MaskEmails bool

	// LogLevel — verbosity: "silent" | "info" | "debug"
	// (Ayrıntı düzeyi: "silent" sessiz | "info" bilgi | "debug" hata ayıklama)
	// Default: info
	LogLevel string
}

// Load reads every setting from the environment and returns a validated Config.
// It returns an error if any required field is missing.
// (Her ayarı ortamdan okur ve doğrulanmış bir Config döner.
//
//	Gerekli bir alan eksikse hata döner.)
func Load() (*Config, error) {
	return load(os.Getenv)
}

func load(getenv func(string) string) (*Config, error) {
	cfg := &Config{
		ListenPort:     envInt(getenv, "FIREWALL_PORT", 8080),
		UpstreamURL:    envStr(getenv, "UPSTREAM_URL", "https://api.anthropic.com"),
		ProviderHint:   envStr(getenv, "PROVIDER_HINT", ""),
		ForwardAPIKey:  envStr(getenv, "FORWARD_API_KEY", ""),
		VaultSizeLimit: envInt(getenv, "VAULT_SIZE_LIMIT", 1000),
		MaskPaths:      envBool(getenv, "MASK_PATHS", true),
		MaskEmails:     envBool(getenv, "MASK_EMAILS", true),
		LogLevel:       envStr(getenv, "LOG_LEVEL", "info"),
	}

	// Validation (doğrulama) ────────────────────────────────────────────────
	if cfg.ListenPort < 1 || cfg.ListenPort > 65535 {
		return nil, fmt.Errorf(
			"FIREWALL_PORT must be between 1 and 65535 (FIREWALL_PORT 1-65535 arasında olmalıdır), got: %d", cfg.ListenPort)
	}

	if cfg.ForwardAPIKey == "" {
		return nil, fmt.Errorf(
			"FORWARD_API_KEY is required but not set (FORWARD_API_KEY zorunludur, ayarlanmamış)")
	}

	cfg.UpstreamURL = strings.TrimRight(cfg.UpstreamURL, "/")

	// ProviderHint is optional; validate only when explicitly set.
	// (ProviderHint isteğe bağlıdır; yalnızca açıkça ayarlandığında doğrula.)
	if cfg.ProviderHint != "" {
		validHints := map[string]bool{
			"anthropic":   true,
			"openai":      true,
			"gemini":      true,
			"groq":        true,
			"together":    true,
			"perplexity":  true,
			"mistral":     true,
			"cohere":      true,
			"deepseek":    true,
			"xai":         true,
			"antigravity": true,
			"ollama":      true,
			"lmstudio":    true,
			"azure":       true,
			"generic":     true,
		}
		if !validHints[strings.ToLower(cfg.ProviderHint)] {
			return nil, fmt.Errorf(
				"PROVIDER_HINT %q is not a recognised provider; leave empty for auto-detect (geçersiz PROVIDER_HINT; otomatik algılama için boş bırakın)",
				cfg.ProviderHint)
		}
		cfg.ProviderHint = strings.ToLower(cfg.ProviderHint)
	}

	return cfg, nil
}

// LoadForTest returns a Config suitable for unit tests without requiring
// any environment variables to be set.
// (Birim testleri için herhangi bir ortam değişkeni ayarlamadan uygun bir Config döner.)
func LoadForTest() *Config {
	return &Config{
		ListenPort:     8080,
		UpstreamURL:    "http://localhost:9999",
		ProviderHint:   "",
		ForwardAPIKey:  "test-key-do-not-use",
		VaultSizeLimit: 100,
		MaskPaths:      true,
		MaskEmails:     true,
		LogLevel:       "silent",
	}
}

// ── helpers (yardımcı fonksiyonlar) ──────────────────────────────────────────

func envStr(getenv func(string) string, key, fallback string) string {
	return envStrFrom(getenv, key, fallback)
}

func envStrFrom(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(getenv func(string) string, key string, fallback int) int {
	return envIntFrom(getenv, key, fallback)
}

func envIntFrom(getenv func(string) string, key string, fallback int) int {
	if v := getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envBool(getenv func(string) string, key string, fallback bool) bool {
	return envBoolFrom(getenv, key, fallback)
}

func envBoolFrom(getenv func(string) string, key string, fallback bool) bool {
	if v := getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}
