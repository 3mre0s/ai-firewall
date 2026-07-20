package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/3mre0s/ai-firewall/audit"
)

func TestLoopbackAddr(t *testing.T) {
	if got, want := loopbackAddr(8080), "127.0.0.1:8080"; got != want {
		t.Fatalf("loopbackAddr() = %q, want %q", got, want)
	}
}

func TestPrintCodexSessionEvidence(t *testing.T) {
	store := audit.NewStore(10)
	store.Add(audit.Trace{
		RequestID:      "req_test",
		Timestamp:      time.Unix(0, 0),
		Method:         "POST",
		Path:           "/responses",
		UpstreamStatus: 200,
		RestoredItems:  1,
		Detections: []audit.Detection{{
			SecretType:        "GitHub Personal Access Token v1",
			PlaceholderID:     "[[GH_PAT_TEST]]",
			OriginalPrevented: true,
		}},
	})
	var output bytes.Buffer
	printCodexSessionEvidence(&output, store)
	for _, want := range []string{"path=/responses", "detections=1", "restored=1", "prevented=true", "VERIFIED: 1"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("session evidence missing %q: %s", want, output.String())
		}
	}
}

func TestPrintCodexSessionEvidenceDoesNotClaimRoundTripWhenResponseWasBlocked(t *testing.T) {
	store := audit.NewStore(10)
	store.Add(audit.Trace{
		RequestID:           "req_blocked",
		Timestamp:           time.Unix(0, 0),
		Method:              "POST",
		Path:                "/responses",
		UpstreamStatus:      200,
		ResponseLeakBlocked: true,
		Detections: []audit.Detection{{
			SecretType:        "GitHub Personal Access Token v1",
			PlaceholderID:     "[[GH_PAT_TEST]]",
			OriginalPrevented: true,
		}},
	})
	var output bytes.Buffer
	printCodexSessionEvidence(&output, store)
	for _, want := range []string{"PREVENTION VERIFIED: 1", "ROUND TRIP NOT VERIFIED"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("session evidence missing %q: %s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "[ANONMYZ] VERIFIED:") {
		t.Fatalf("blocked response was incorrectly reported as verified: %s", output.String())
	}
}

func TestRunDemoEndToEndAndExitCodes(t *testing.T) {
	for attempt := 0; attempt < 2; attempt++ {
		if got := runDemo([]string{"--non-interactive"}); got != 0 {
			t.Fatalf("runDemo attempt %d exit = %d, want 0", attempt+1, got)
		}
	}
	if got := runDemo([]string{"--unknown"}); got != 2 {
		t.Fatalf("runDemo usage exit = %d, want 2", got)
	}
	if got := runCodex([]string{"--unknown"}); got != 2 {
		t.Fatalf("runCodex usage exit = %d, want 2", got)
	}
}

func TestCodexOptionsAndTemporaryOverrides(t *testing.T) {
	opts, help, err := parseCodexOptions([]string{
		"--dry-run", "--port", "9191", "--upstream=https://example.test/v1", "--", "--no-alt-screen",
	})
	if err != nil || help {
		t.Fatalf("parseCodexOptions() err=%v help=%v", err, help)
	}
	if !opts.dryRun || opts.port != 9191 || opts.upstream != "https://example.test/v1" {
		t.Fatalf("unexpected options: %#v", opts)
	}
	if len(opts.forwarded) != 1 || opts.forwarded[0] != "--no-alt-screen" {
		t.Fatalf("forwarded args = %#v", opts.forwarded)
	}

	t.Setenv("OPENAI_API_KEY", "sk-proj-FAKE_TEST_VALUE_MUST_NOT_APPEAR")
	args := buildCodexArgs("http://127.0.0.1:9191", codexAuthEnvironment, opts.forwarded)
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "FAKE_TEST_VALUE") {
		t.Fatal("Codex command line contains the API key value")
	}
	for _, want := range []string{"model_provider=\"anonmyz\"", "wire_api=\"responses\"", "env_key=\"OPENAI_API_KEY\"", "supports_websockets=false", "enable_request_compression=false", "--no-alt-screen"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("Codex args missing %q: %s", want, joined)
		}
	}

	chatGPTArgs := strings.Join(buildCodexArgs("http://127.0.0.1:9191", codexAuthChatGPT, nil), " ")
	for _, want := range []string{`model_provider="anonmyz"`, `base_url="http://127.0.0.1:9191"`, `requires_openai_auth=true`, `supports_websockets=false`} {
		if !strings.Contains(chatGPTArgs, want) {
			t.Fatalf("ChatGPT Codex args missing %q: %s", want, chatGPTArgs)
		}
	}
	if strings.Contains(chatGPTArgs, "env_key") {
		t.Fatalf("ChatGPT Codex args unexpectedly require an API key: %s", chatGPTArgs)
	}
	if got := defaultCodexUpstream(codexAuthChatGPT); got != chatGPTCodexUpstream {
		t.Fatalf("ChatGPT upstream = %q, want %q", got, chatGPTCodexUpstream)
	}
	if got := defaultCodexUpstream(codexAuthStoredAPI); got != openAICodexUpstream {
		t.Fatalf("API-key upstream = %q, want %q", got, openAICodexUpstream)
	}
}

func TestCodexOptionValidation(t *testing.T) {
	for _, args := range [][]string{
		{"--port", "70000"},
		{"--upstream", "file:///tmp/model"},
		{"--upstream", "https://user:pass@example.test"},
		{"--upstream", "https://example.test/v1?token=secret"},
	} {
		if _, _, err := parseCodexOptions(args); err == nil {
			t.Fatalf("parseCodexOptions(%q) unexpectedly succeeded", args)
		}
	}
}

func TestListenLoopbackDynamicAndPortConflict(t *testing.T) {
	listener, err := listenLoopback(0)
	if err != nil {
		t.Fatalf("dynamic loopback listen: %v", err)
	}
	defer listener.Close()
	addr := listener.Addr().(*net.TCPAddr)
	if !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) || addr.Port == 0 {
		t.Fatalf("unexpected dynamic address: %s", listener.Addr())
	}
	t.Logf("verified loopback-only listener: %s (not 0.0.0.0)", listener.Addr())
	if conflict, err := listenLoopback(addr.Port); err == nil {
		conflict.Close()
		t.Fatal("binding an occupied port unexpectedly succeeded")
	}
}

func TestCodexProviderHasNoDirectCloudFallback(t *testing.T) {
	args := strings.Join(buildCodexArgs("http://127.0.0.1:9191", codexAuthChatGPT, nil), " ")
	for _, forbidden := range []string{"api.openai.com", "chatgpt.com", "0.0.0.0"} {
		if strings.Contains(args, forbidden) {
			t.Fatalf("protected Codex arguments contain direct fallback %q: %s", forbidden, args)
		}
	}
	if got := strings.Count(args, `base_url=`); got != 1 {
		t.Fatalf("protected Codex arguments contain %d base URLs, want exactly one: %s", got, args)
	}
	if !strings.Contains(args, `base_url="http://127.0.0.1:9191"`) {
		t.Fatalf("protected Codex base URL is not the loopback proxy: %s", args)
	}
}
