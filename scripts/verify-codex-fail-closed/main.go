// verify-codex-fail-closed runs the installed Codex CLI through a real
// Anonmyz proxy, terminates that proxy during an in-flight model request, and
// verifies that Codex fails instead of attempting a direct cloud connection.
// It uses a synthetic local-only API key and never contacts an OpenAI service.
package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/3mre0s/ai-firewall/config"
	"github.com/3mre0s/ai-firewall/masker"
	"github.com/3mre0s/ai-firewall/proxy"
	"github.com/3mre0s/ai-firewall/vault"
)

const syntheticKey = "anonmyz-local-fail-closed-probe-not-a-real-key"

const codexAppsOverride = `features.apps=false`

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

type egressRecorder struct {
	mu       sync.Mutex
	attempts []string
}

func (r *egressRecorder) add(value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts = append(r.attempts, value)
}

func (r *egressRecorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.attempts...)
}

func main() {
	log.SetOutput(io.Discard)
	codexPath, err := exec.LookPath("codex")
	if err != nil {
		fatalf("Codex executable not found: %v", err)
	}

	directEgress := &egressRecorder{}
	egressTrap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directEgress.add(r.Method + " " + r.Host + " " + r.URL.String())
		http.Error(w, "direct egress blocked by fail-closed probe", http.StatusBadGateway)
	}))
	defer egressTrap.Close()

	requestReachedUpstream := make(chan struct{}, 1)
	releaseUpstream := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/models") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"models":[]}`)
			return
		}
		select {
		case requestReachedUpstream <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-releaseUpstream:
		}
	}))
	defer func() {
		close(releaseUpstream)
		upstream.Close()
	}()

	cfg := config.LoadForTest()
	cfg.UpstreamURL = upstream.URL
	cfg.ProviderHint = "openai"
	cfg.ForwardAPIKey = "none"
	cfg.LogLevel = "silent"
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		fatalf("cannot start loopback Anonmyz proxy: %v", err)
	}
	localURL := "http://" + listener.Addr().String()
	if err := validateLoopbackModelURL(localURL); err != nil {
		_ = listener.Close()
		fatalf("unsafe model route: %v", err)
	}
	anonmyzServer := &http.Server{Handler: proxy.NewServer(cfg, masker.New(vault.New(10), cfg))}
	go func() {
		_ = anonmyzServer.Serve(listener)
	}()

	args := []string{
		"-c", `model_provider="anonmyz_probe"`,
		"-c", `model_providers.anonmyz_probe.name="Anonmyz fail-closed probe"`,
		"-c", `model_providers.anonmyz_probe.base_url=` + strconv.Quote(localURL),
		"-c", `model_providers.anonmyz_probe.wire_api="responses"`,
		"-c", `model_providers.anonmyz_probe.supports_websockets=false`,
		"-c", `model_providers.anonmyz_probe.env_key="ANONMYZ_FAIL_CLOSED_PROBE_KEY"`,
		"-c", `features.enable_request_compression=false`,
		"-c", `features.plugins=false`,
		"-c", codexAppsOverride,
		"-c", `analytics.enabled=false`,
		"-c", `feedback.enabled=false`,
		"exec", "--ignore-user-config", "--ephemeral",
		"Fail-closed transport probe. Reply with only OK.",
	}
	cmd := exec.Command(codexPath, args...)
	cmd.Env = probeEnvironment(os.Environ(), egressTrap.URL)
	var output lockedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		_ = anonmyzServer.Close()
		fatalf("cannot start Codex: %v", err)
	}
	go func() { done <- cmd.Wait() }()

	select {
	case <-requestReachedUpstream:
		// Close aborts active connections immediately. Codex now has only the
		// configured loopback base URL; retries must fail locally.
		_ = anonmyzServer.Close()
	case err := <-done:
		_ = anonmyzServer.Close()
		fatalf("Codex exited before the in-flight request could be interrupted: %v", err)
	case <-time.After(25 * time.Second):
		_ = cmd.Process.Kill()
		_ = anonmyzServer.Close()
		fatalf("timed out waiting for Codex to reach the local Anonmyz proxy")
	}

	var exitErr error
	select {
	case exitErr = <-done:
	case <-time.After(110 * time.Second):
		_ = cmd.Process.Kill()
		exitErr = <-done
		fatalf("Codex did not stop after its local proxy disappeared: %v", exitErr)
	}
	if exitErr == nil {
		fatalf("Codex unexpectedly succeeded after its local proxy disappeared")
	}
	allEgress := directEgress.list()
	if err := validateNoUnexpectedEgress(allEgress); err != nil {
		fatalf("%v", err)
	}
	if strings.Contains(output.String(), syntheticKey) {
		fatalf("synthetic authentication value appeared in Codex output")
	}

	fmt.Println("[PASS] Codex request first traversed the real loopback Anonmyz proxy")
	fmt.Println("[PASS] Codex Apps disabled with temporary features.apps=false override")
	fmt.Println("[PASS] Anonmyz was terminated during the in-flight model request")
	fmt.Println("[PASS] Codex exited with an error after local proxy loss")
	fmt.Println("[PASS] Unexpected non-loopback connection attempts observed: 0")
	fmt.Println("[PASS] Authentication canary appeared in output: false")
}

func validateLoopbackModelURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() == "" {
		return fmt.Errorf("invalid local model URL")
	}
	ip := net.ParseIP(parsed.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("model URL destination is not a literal loopback address")
	}
	return nil
}

func validateNoUnexpectedEgress(attempts []string) error {
	if len(attempts) == 0 {
		return nil
	}
	return fmt.Errorf("unexpected outbound connection attempts reached the egress trap: count=%d", len(attempts))
}

func probeEnvironment(base []string, trapURL string) []string {
	blocked := map[string]bool{
		"ANONMYZ_FAIL_CLOSED_PROBE_KEY": true,
		"HTTP_PROXY":                    true,
		"HTTPS_PROXY":                   true,
		"ALL_PROXY":                     true,
		"NO_PROXY":                      true,
		"http_proxy":                    true,
		"https_proxy":                   true,
		"all_proxy":                     true,
		"no_proxy":                      true,
	}
	out := make([]string, 0, len(base)+9)
	for _, entry := range base {
		if key, _, ok := strings.Cut(entry, "="); !ok || !blocked[key] {
			out = append(out, entry)
		}
	}
	return append(out,
		"ANONMYZ_FAIL_CLOSED_PROBE_KEY="+syntheticKey,
		"HTTP_PROXY="+trapURL,
		"HTTPS_PROXY="+trapURL,
		"ALL_PROXY="+trapURL,
		"NO_PROXY=127.0.0.1,localhost",
		"http_proxy="+trapURL,
		"https_proxy="+trapURL,
		"all_proxy="+trapURL,
		"no_proxy=127.0.0.1,localhost",
	)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[FAIL] "+format+"\n", args...)
	os.Exit(1)
}
