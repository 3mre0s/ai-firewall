package config

import (
	"testing"
)

func TestLoadDefaultsAndRequired(t *testing.T) {
	t.Parallel()

	env := map[string]string{}

	// Missing FORWARD_API_KEY should error
	_, err := load(func(key string) string { return env[key] })
	if err == nil {
		t.Errorf("expected error when FORWARD_API_KEY is missing")
	}

	// Set required key
	env["FORWARD_API_KEY"] = "sk-test1234"

	cfg, err := load(func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check defaults
	if cfg.ListenPort != 8080 {
		t.Errorf("expected default ListenPort = 8080, got %d", cfg.ListenPort)
	}
	if cfg.UpstreamURL != "https://api.anthropic.com" {
		t.Errorf("expected default UpstreamURL, got %q", cfg.UpstreamURL)
	}
	if cfg.ProviderHint != "" {
		t.Errorf("expected default ProviderHint to be empty, got %q", cfg.ProviderHint)
	}
	if cfg.VaultSizeLimit != 1000 {
		t.Errorf("expected default VaultSizeLimit = 1000, got %d", cfg.VaultSizeLimit)
	}
	if !cfg.MaskPaths {
		t.Errorf("expected default MaskPaths = true")
	}
	if !cfg.MaskEmails {
		t.Errorf("expected default MaskEmails = true")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default LogLevel = 'info', got %q", cfg.LogLevel)
	}
}

func TestLoadCustomValues(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"FORWARD_API_KEY":  "key",
		"FIREWALL_PORT":    "9090",
		"UPSTREAM_URL":     "https://api.openai.com/",
		"PROVIDER_HINT":    "OPENAI",
		"VAULT_SIZE_LIMIT": "500",
		"MASK_PATHS":       "false",
		"MASK_EMAILS":      "false",
		"LOG_LEVEL":        "debug",
	}

	cfg, err := load(func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ListenPort != 9090 {
		t.Errorf("expected ListenPort = 9090, got %d", cfg.ListenPort)
	}
	if cfg.UpstreamURL != "https://api.openai.com" { // note the trailing slash trim
		t.Errorf("expected UpstreamURL = 'https://api.openai.com', got %q", cfg.UpstreamURL)
	}
	if cfg.ProviderHint != "openai" { // lowercase conversion
		t.Errorf("expected ProviderHint = 'openai', got %q", cfg.ProviderHint)
	}
	if cfg.VaultSizeLimit != 500 {
		t.Errorf("expected VaultSizeLimit = 500, got %d", cfg.VaultSizeLimit)
	}
	if cfg.MaskPaths {
		t.Errorf("expected MaskPaths = false")
	}
	if cfg.MaskEmails {
		t.Errorf("expected MaskEmails = false")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected LogLevel = 'debug', got %q", cfg.LogLevel)
	}
}

func TestInvalidProviderHint(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"FORWARD_API_KEY": "key",
		"PROVIDER_HINT":   "INVALID_API",
	}

	_, err := load(func(key string) string { return env[key] })
	if err == nil {
		t.Errorf("expected error on invalid PROVIDER_HINT")
	}
}

func TestInvalidPortRange(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"FORWARD_API_KEY": "key",
		"FIREWALL_PORT":   "99999",
	}

	if _, err := load(func(key string) string { return env[key] }); err == nil {
		t.Errorf("expected error for port > 65535")
	}

	env["FIREWALL_PORT"] = "0"
	if _, err := load(func(key string) string { return env[key] }); err == nil {
		t.Errorf("expected error for port < 1")
	}
}

func TestLoadForTest(t *testing.T) {
	t.Parallel()

	cfg := LoadForTest()
	if cfg.ForwardAPIKey != "test-key-do-not-use" {
		t.Errorf("expected ForwardAPIKey = 'test-key-do-not-use', got %q", cfg.ForwardAPIKey)
	}
	if cfg.LogLevel != "silent" {
		t.Errorf("expected LogLevel = 'silent', got %q", cfg.LogLevel)
	}
}
