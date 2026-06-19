// Package config loads application settings from environment variables (çevre değişkenleri).
// No config file is needed — a single binary + a handful of env vars is enough.
// (Yapılandırma dosyasına gerek yok; tek binary + birkaç çevre değişkeni yeterli.)
package config

import (
	"fmt"
	"os"
	"path/filepath"
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
	//
	// Set to "none" to enable passthrough mode: the firewall skips key injection
	// and forwards the client's own Authorization: Bearer header unchanged.
	// This is used by Claude Code Pro/Max subscription users who authenticate
	// via ANTHROPIC_AUTH_TOKEN instead of an API key.
	// ("none" olarak ayarlandığında passthrough modu etkinleşir: firewall anahtar
	//  enjeksiyonunu atlar ve istemcinin kendi Authorization: Bearer header'ını
	//  değiştirmeden iletir. Claude Code Pro/Max abonelik kullanıcıları
	//  ANTHROPIC_AUTH_TOKEN ile kimlik doğruladığında bu mod kullanılır.)
	// Required (or "none" for passthrough mode).
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

	// MITMEnabled — whether to start the MITM proxy server.
	// Default: false
	MITMEnabled bool

	// MITMPort — the local TCP port the MITM proxy will bind to.
	// Default: 8082
	MITMPort int

	// MITMCertDir — directory for CA cert/key storage.
	// Default: ~/.ai-firewall
	MITMCertDir string
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
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	defaultCertDir := filepath.Join(home, ".ai-firewall")

	cfg := &Config{
		ListenPort:     envInt(getenv, "FIREWALL_PORT", 8080),
		UpstreamURL:    envStr(getenv, "UPSTREAM_URL", "https://api.anthropic.com"),
		ProviderHint:   envStr(getenv, "PROVIDER_HINT", ""),
		ForwardAPIKey:  envStr(getenv, "FORWARD_API_KEY", ""),
		VaultSizeLimit: envInt(getenv, "VAULT_SIZE_LIMIT", 1000),
		MaskPaths:      envBool(getenv, "MASK_PATHS", true),
		MaskEmails:     envBool(getenv, "MASK_EMAILS", true),
		LogLevel:       envStr(getenv, "LOG_LEVEL", "info"),
		MITMEnabled:    envBool(getenv, "MITM_ENABLED", false),
		MITMPort:       envInt(getenv, "MITM_PORT", 8082),
		MITMCertDir:    envStr(getenv, "MITM_CERT_DIR", defaultCertDir),
	}

	// Validation (doğrulama) ────────────────────────────────────────────────
	if cfg.ListenPort < 1 || cfg.ListenPort > 65535 {
		return nil, fmt.Errorf(
			"FIREWALL_PORT must be between 1 and 65535, got: %d", cfg.ListenPort)
	}

	if cfg.MITMEnabled {
		if cfg.MITMPort < 1 || cfg.MITMPort > 65535 {
			return nil, fmt.Errorf(
				"MITM_PORT must be between 1 and 65535, got: %d", cfg.MITMPort)
		}
	}

	if cfg.ForwardAPIKey == "" {
		return nil, fmt.Errorf(
			"FORWARD_API_KEY is required but not set; use \"none\" for passthrough mode")
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
			"ollama":      true,
			"lmstudio":    true,
			"azure":       true,
			"generic":     true,
		}
		if !validHints[strings.ToLower(cfg.ProviderHint)] {
			return nil, fmt.Errorf(
				"PROVIDER_HINT %q is not a recognised provider; leave empty for auto-detect",
				cfg.ProviderHint)
		}
		cfg.ProviderHint = strings.ToLower(cfg.ProviderHint)
	}

	return cfg, nil
}

// CACertPaths returns the CA certificate and key file paths based on the
// current environment, without requiring FORWARD_API_KEY.
// Used by CLI subcommands (install-ca, uninstall-ca).
//
// (FORWARD_API_KEY gerektirmeden çevre değişkenlerine göre CA sertifika ve
// anahtar dosya yollarını döner. CLI alt-komutları tarafından kullanılır.)
func CACertPaths() (certPath, keyPath string) {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".ai-firewall")
	if v := os.Getenv("MITM_CERT_DIR"); v != "" {
		dir = v
	}
	return filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
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
		MITMEnabled:    false,
		MITMPort:       8082,
		MITMCertDir:    ".ai-firewall-test",
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
