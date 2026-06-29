package telemetry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestDisabledSendsNoRequest verifies the core privacy guarantee: when
// Enabled is false (the default), no network call is ever made.
func TestDisabledSendsNoRequest(t *testing.T) {
	t.Parallel()

	var called int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = 1
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := Config{Enabled: false, Endpoint: srv.URL, DataDir: dir}

	SendStartupEvent(cfg, "1.0.0-test", nil)

	// Give any (incorrectly fired) goroutine time to reach the server.
	time.Sleep(100 * time.Millisecond)

	if called != 0 {
		t.Fatal("expected no HTTP request when telemetry is disabled")
	}
	if _, err := os.Stat(filepath.Join(dir, idFileName)); !os.IsNotExist(err) {
		t.Fatal("expected no anon-id file to be written when telemetry is disabled")
	}
}

// TestEnabledSendsExpectedPayload checks the exact shape and content of the
// payload — in particular, that no unexpected fields (paths, secrets, env
// vars) ever leave the process.
func TestEnabledSendsExpectedPayload(t *testing.T) {
	t.Parallel()

	received := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("invalid JSON body: %v", err)
		}
		received <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := Config{Enabled: true, Endpoint: srv.URL, APIKey: "phc_test", DataDir: dir}

	SendStartupEvent(cfg, "1.2.3", t.Logf)

	select {
	case body := <-received:
		if body["event"] != "ai_firewall_startup" {
			t.Errorf("expected event=ai_firewall_startup, got %v", body["event"])
		}
		if body["api_key"] != "phc_test" {
			t.Errorf("expected api_key=phc_test, got %v", body["api_key"])
		}
		props, ok := body["properties"].(map[string]any)
		if !ok {
			t.Fatalf("expected properties object, got %T", body["properties"])
		}
		for _, want := range []string{"distinct_id", "version", "os", "arch"} {
			if _, ok := props[want]; !ok {
				t.Errorf("expected properties.%s to be present", want)
			}
		}
		if props["version"] != "1.2.3" {
			t.Errorf("expected version=1.2.3, got %v", props["version"])
		}
		// Privacy guarantee: only the four expected keys ever leave the process.
		allowed := map[string]bool{"distinct_id": true, "version": true, "os": true, "arch": true}
		for k := range props {
			if !allowed[k] {
				t.Errorf("unexpected property leaked in telemetry payload: %q", k)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for telemetry request")
	}
}

// TestAnonIDPersistsAcrossRuns ensures repeat startups reuse the same
// installation ID instead of minting a new one every run.
func TestAnonIDPersistsAcrossRuns(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	id1, err := loadOrCreateAnonID(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id1 == "" {
		t.Fatal("expected non-empty anon id")
	}

	id2, err := loadOrCreateAnonID(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("expected stable anon id across runs, got %q then %q", id1, id2)
	}

	// File must not be world/group readable — even though it contains no
	// personal data, it's still a stable cross-run identifier.
	info, err := os.Stat(filepath.Join(dir, idFileName))
	if err != nil {
		t.Fatalf("unexpected error stat-ing id file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected telemetry_id mode 0600, got %o", perm)
	}
}

// TestNoEndpointConfiguredSkipsSilently verifies that enabling telemetry
// without an endpoint never panics and never blocks.
func TestNoEndpointConfiguredSkipsSilently(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var logs []string
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logs = append(logs, format)
	}

	cfg := Config{Enabled: true, Endpoint: "", DataDir: t.TempDir()}
	SendStartupEvent(cfg, "1.0.0", logf)

	mu.Lock()
	defer mu.Unlock()
	if len(logs) == 0 {
		t.Fatal("expected a diagnostic log line when no endpoint is configured")
	}
}

// TestUnreachableEndpointDoesNotPanic confirms network failures are
// swallowed — telemetry must never be able to crash or hang the firewall.
func TestUnreachableEndpointDoesNotPanic(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Enabled:  true,
		Endpoint: "http://127.0.0.1:1", // closed port, connection refused
		APIKey:   "phc_test",
		DataDir:  t.TempDir(),
	}

	done := make(chan struct{})
	go func() {
		SendStartupEvent(cfg, "1.0.0", nil)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("SendStartupEvent should return immediately (it's fire-and-forget)")
	}
}
