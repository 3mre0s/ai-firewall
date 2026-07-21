package main

import (
	"strings"
	"testing"
)

func TestProbeDisablesCodexApps(t *testing.T) {
	if codexAppsOverride != "features.apps=false" {
		t.Fatalf("Apps override = %q", codexAppsOverride)
	}
}

func TestLoopbackModelRoutePasses(t *testing.T) {
	for _, rawURL := range []string{"http://127.0.0.1:9191", "http://[::1]:9191"} {
		if err := validateLoopbackModelURL(rawURL); err != nil {
			t.Fatalf("validateLoopbackModelURL(%q): %v", rawURL, err)
		}
	}
	if err := validateNoUnexpectedEgress(nil); err != nil {
		t.Fatalf("loopback-only route failed verification: %v", err)
	}
}

func TestNonLoopbackModelRouteFails(t *testing.T) {
	for _, rawURL := range []string{
		"https://chatgpt.com/backend-api/codex",
		"https://api.openai.com/v1",
		"http://example.com:9191",
		"http://192.0.2.1:9191",
	} {
		if err := validateLoopbackModelURL(rawURL); err == nil {
			t.Fatalf("validateLoopbackModelURL(%q) unexpectedly passed", rawURL)
		}
	}
}

func TestUnexpectedDirectTrafficFailsWithoutHostnameAllowlist(t *testing.T) {
	for _, attempt := range []string{
		"CONNECT chatgpt.com:443",
		"CONNECT api.openai.com:443",
		"CONNECT example.com:443",
	} {
		err := validateNoUnexpectedEgress([]string{attempt})
		if err == nil {
			t.Fatalf("unexpected traffic was allowed: %s", attempt)
		}
		if strings.Contains(err.Error(), attempt) {
			t.Fatalf("sanitized error leaked destination: %v", err)
		}
	}
}
