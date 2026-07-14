package mitm

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIsAIHostExact verifies that isAIHost intercepts only whitelisted providers
// and rejects hosts that merely contain provider keywords in their name.
// Negative tests ensure attacker-controlled domains are never intercepted.
//
// (isAIHost'un yalnızca beyaz listeli sağlayıcıları yakaladığını ve yalnızca
//
//	adında sağlayıcı anahtar sözcükleri içeren hostları reddettiğini doğrular.
//	Negatif testler, saldırgan tarafından kontrol edilen domainlerin hiçbir zaman
//	yakalanmadığını garanti eder.)
func TestIsAIHostExact(t *testing.T) {
	t.Parallel()

	p := &MITMProxy{aiHosts: buildAIHostsMap()}

	cases := []struct {
		name     string
		hostport string
		want     bool
	}{
		// ── Known remote AI providers (bare hostname, no port in CONNECT) ─────────
		// (Bilinen uzak AI sağlayıcıları — port içermeyen çıplak hostname)
		{name: "anthropic", hostport: "api.anthropic.com", want: true},
		{name: "openai", hostport: "api.openai.com", want: true},
		{name: "openai with port", hostport: "api.openai.com:443", want: true},
		{name: "google generative", hostport: "generativelanguage.googleapis.com", want: true},
		{name: "google aiplatform", hostport: "aiplatform.googleapis.com", want: true},
		{name: "groq", hostport: "api.groq.com", want: true},
		{name: "together xyz", hostport: "api.together.xyz", want: true},
		{name: "mistral", hostport: "api.mistral.ai", want: true},
		{name: "deepseek", hostport: "api.deepseek.com", want: true},

		// ── Azure OpenAI: exact suffix *.openai.azure.com ─────────────────────────
		// (Azure OpenAI: tam sonek *.openai.azure.com)
		{name: "azure valid", hostport: "mycompany.openai.azure.com", want: true},
		{name: "azure with port", hostport: "mycompany.openai.azure.com:443", want: true},

		// ── Local providers matched by full host:port (not by name substring) ─────
		// (Yerel sağlayıcılar: ad alt dizisine değil, tam host:port'a göre eşleştirilir)
		{name: "ollama localhost", hostport: "localhost:11434", want: true},
		{name: "ollama 127.0.0.1", hostport: "127.0.0.1:11434", want: true},
		{name: "lmstudio localhost", hostport: "localhost:1234", want: true},
		{name: "lmstudio 127.0.0.1", hostport: "127.0.0.1:1234", want: true},

		// ── Negative: attacker hosts containing provider keywords — must NOT match ─
		// (Negatif: sağlayıcı anahtar sözcükleri içeren saldırgan hostları — eşleşmemeli)
		{name: "evil-ollama fqdn", hostport: "evil-ollama.attacker.com", want: false},
		{name: "evil-ollama with port", hostport: "evil-ollama.attacker.com:443", want: false},
		{name: "lmstudio attacker", hostport: "my-lmstudio-server.evil.com", want: false},
		{name: "ollama attacker no port", hostport: "ollama.attacker.com", want: false},

		// ── Negative: Azure suffix must be a true suffix, not a prefix/infix ───────
		// (Negatif: Azure soneki gerçek bir sonek olmalı, önek veya orta olmamalı)
		{name: "azure suffix attack openai.azure.com.evil", hostport: "openai.azure.com.evil.com", want: false},
		{name: "azure subdomain attack", hostport: "mycompany.openai.azure.com.attacker.com", want: false},
		{name: "fakeopenai.azure.com.evil", hostport: "fakeopenai.azure.com.evil.com", want: false},

		// ── Negative: unrelated / benign domains ─────────────────────────────────
		// (Negatif: alakasız / zararsız domainler)
		{name: "google.com", hostport: "google.com", want: false},
		{name: "localhost no port", hostport: "localhost", want: false},
		{name: "random attacker", hostport: "attacker.com:443", want: false},
		{name: "127.0.0.1 no port", hostport: "127.0.0.1", want: false},
		{name: "localhost wrong port", hostport: "localhost:8080", want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := p.isAIHost(tc.hostport)
			if got != tc.want {
				t.Errorf("isAIHost(%q) = %v, want %v", tc.hostport, got, tc.want)
			}
		})
	}
}

func TestUnknownConnectTargetIsRejected(t *testing.T) {
	p := &MITMProxy{aiHosts: buildAIHostsMap()}
	req := httptest.NewRequest(http.MethodConnect, "http://attacker.invalid", nil)
	req.Host = "attacker.invalid:443"
	recorder := httptest.NewRecorder()

	p.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func TestMITMUpstreamURLPreservesConnectPort(t *testing.T) {
	got := mitmUpstreamURL("localhost:11434", "/v1/chat", "stream=true")
	want := "https://localhost:11434/v1/chat?stream=true"
	if got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
}

func TestReadMITMBodyDetectsOversize(t *testing.T) {
	_, tooLarge, err := readMITMBody(bytes.NewReader(make([]byte, maxMITMRequestBody+1)))
	if err != nil {
		t.Fatal(err)
	}
	if !tooLarge {
		t.Fatal("oversized body was not rejected")
	}
}
