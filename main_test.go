package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestDemoCommandRunsOfflineWithoutAPIKey(t *testing.T) {
	t.Setenv("FORWARD_API_KEY", "")
	t.Setenv("UPSTREAM_URL", "")
	t.Setenv("ANALYTICS_OPT_IN", "true")

	var output bytes.Buffer
	handled, code := runOfflineCommand("demo", &output)
	if !handled {
		t.Fatal("demo command was not recognized")
	}
	if code != 0 {
		t.Fatalf("demo returned exit code %d:\n%s", code, output.String())
	}

	text := output.String()
	for _, expected := range []string{
		"No network request will be made.",
		"OpenAI API Key",
		"GitHub Personal Access Token v1",
		"E-mail Address",
		"Unix Absolute Path",
		"[[OAI_KEY_",
		"[[GH_PAT_",
		"[[EMAIL_",
		"[[UNIX_PATH_",
		"Demo complete.",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("demo output missing %q", expected)
		}
	}

	sanitized := strings.SplitN(text, "Sanitized prompt:", 2)
	if len(sanitized) != 2 {
		t.Fatal("demo output has no sanitized section")
	}
	for _, synthetic := range []string{
		"sk-test-not-a-real-key-000000",
		"ghp_TESTNOTREAL0000000000000000000000000",
		"developer@example.com",
		"/Users/example/project/.env",
	} {
		if strings.Contains(sanitized[1], synthetic) {
			t.Errorf("sanitized section exposes synthetic value %q", synthetic)
		}
	}
}

func TestDemoDoesNotCreateRuntimeFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("FORWARD_API_KEY", "")

	var output bytes.Buffer
	if code := runDemo(&output); code != 0 {
		t.Fatalf("demo returned exit code %d:\n%s", code, output.String())
	}

	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("demo created files in the temporary home: %v", entries)
	}
}

func TestHelpDocumentsDemo(t *testing.T) {
	var output bytes.Buffer
	handled, code := runOfflineCommand("help", &output)
	if !handled || code != 0 {
		t.Fatalf("help command failed: handled=%v code=%d", handled, code)
	}
	if !strings.Contains(output.String(), "ai-firewall demo") {
		t.Fatal("help output does not document demo command")
	}
}

func TestLoopbackAddr(t *testing.T) {
	if got, want := loopbackAddr(8080), "127.0.0.1:8080"; got != want {
		t.Fatalf("loopbackAddr() = %q, want %q", got, want)
	}
}
