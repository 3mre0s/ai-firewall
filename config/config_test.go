package config

import (
	"strings"
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

func TestInvalidEnvironmentValuesFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "firewall port typo", key: "FIREWALL_PORT", value: "eight-thousand"},
		{name: "vault limit typo", key: "VAULT_SIZE_LIMIT", value: "many"},
		{name: "mask paths typo", key: "MASK_PATHS", value: "sometimes"},
		{name: "mask emails typo", key: "MASK_EMAILS", value: "enabled"},
		{name: "MITM enabled typo", key: "MITM_ENABLED", value: "perhaps"},
		{name: "MITM port typo", key: "MITM_PORT", value: "secure"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := map[string]string{"FORWARD_API_KEY": "secret-that-must-not-appear"}
			env[tt.key] = tt.value
			_, err := load(func(key string) string { return env[key] })
			if err == nil {
				t.Fatalf("expected invalid %s to fail", tt.key)
			}
			if !strings.Contains(err.Error(), tt.key) {
				t.Fatalf("error %q does not identify %s", err, tt.key)
			}
			if strings.Contains(err.Error(), env["FORWARD_API_KEY"]) {
				t.Fatal("configuration error exposed FORWARD_API_KEY")
			}
		})
	}
}

func TestAdditionalConfigurationValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
	}{
		{name: "empty vault", env: map[string]string{"VAULT_SIZE_LIMIT": "0"}},
		{name: "invalid log level", env: map[string]string{"LOG_LEVEL": "verbose"}},
		{name: "conflicting listeners", env: map[string]string{
			"MITM_ENABLED": "true", "FIREWALL_PORT": "8080", "MITM_PORT": "8080",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.env["FORWARD_API_KEY"] = "key"
			if _, err := load(func(key string) string { return tt.env[key] }); err == nil {
				t.Fatal("expected configuration validation error")
			}
		})
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

func TestNormalizeUpstreamURLSecurityPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "remote HTTPS", raw: "https://api.openai.com/v1/", want: "https://api.openai.com/v1"},
		{name: "loopback IPv4 HTTP", raw: "http://127.0.0.1:11434/", want: "http://127.0.0.1:11434"},
		{name: "loopback IPv6 HTTP", raw: "http://[::1]:1234", want: "http://[::1]:1234"},
		{name: "localhost HTTP", raw: "http://localhost:9999", want: "http://localhost:9999"},
		{name: "remote plaintext", raw: "http://api.example.test", wantErr: true},
		{name: "userinfo", raw: "https://user:pass@example.test", wantErr: true},
		{name: "query", raw: "https://example.test/v1?token=secret", wantErr: true},
		{name: "fragment", raw: "https://example.test/v1#fragment", wantErr: true},
		{name: "file URL", raw: "file:///tmp/model", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeUpstreamURL(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NormalizeUpstreamURL(%q) unexpectedly returned %q", tt.raw, got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("NormalizeUpstreamURL(%q) = %q, %v; want %q", tt.raw, got, err, tt.want)
			}
		})
	}
}
