package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/3mre0s/ai-firewall/audit"
	"github.com/3mre0s/ai-firewall/config"
	"github.com/3mre0s/ai-firewall/masker"
	"github.com/3mre0s/ai-firewall/metrics"
	"github.com/3mre0s/ai-firewall/proxy"
	"github.com/3mre0s/ai-firewall/vault"
)

type codexOptions struct {
	dryRun    bool
	port      int
	upstream  string
	forwarded []string
}

const (
	openAICodexUpstream  = "https://api.openai.com/v1"
	chatGPTCodexUpstream = "https://chatgpt.com/backend-api/codex"
)

type codexAuthMode string

const (
	codexAuthEnvironment codexAuthMode = "environment_api_key"
	codexAuthStoredAPI   codexAuthMode = "stored_api_key"
	codexAuthChatGPT     codexAuthMode = "chatgpt_subscription"
	codexAuthMissing     codexAuthMode = "missing"
)

func runCodex(args []string) int {
	opts, help, err := parseCodexOptions(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "codex: %v\n", err)
		return 2
	}
	if help {
		printCodexUsage()
		return 0
	}

	codexPath, err := exec.LookPath("codex")
	if err != nil {
		fmt.Fprintln(os.Stderr, "codex: executable not found; install Codex and ensure it is on PATH")
		return 1
	}
	authMode := detectCodexAuth(codexPath)
	if authMode == codexAuthMissing && !opts.dryRun {
		fmt.Fprintln(os.Stderr, "codex: no Codex login or API-key credential found; run `codex login` or set OPENAI_API_KEY")
		return 1
	}
	upstream := opts.upstream
	if upstream == "" {
		upstream = defaultCodexUpstream(authMode)
	}

	if opts.dryRun {
		plannedURL := "http://127.0.0.1:<dynamic>"
		if opts.port != 0 {
			plannedURL = fmt.Sprintf("http://127.0.0.1:%d", opts.port)
		}
		fmt.Println("Anonmyz Codex Safe Session (dry run)")
		fmt.Printf("  Codex executable: %s\n", codexPath)
		fmt.Printf("  Authentication:   %s\n", authMode)
		fmt.Printf("  Local model URL:  %s\n", plannedURL)
		fmt.Printf("  Upstream:         %s\n", upstream)
		fmt.Println("  Global config:    unchanged (temporary -c overrides only)")
		fmt.Println("  Request bodies:   masked locally; Codex authentication headers pass through")
		if authMode == codexAuthMissing {
			fmt.Println("  BLOCKED: complete `codex login` (ChatGPT is supported) or set OPENAI_API_KEY")
		}
		if len(opts.forwarded) > 0 {
			fmt.Printf("  Codex arguments:  %s\n", strings.Join(opts.forwarded, " "))
		}
		return 0
	}

	listener, err := listenLoopback(opts.port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "codex: cannot bind local proxy: %v\n", err)
		return 1
	}
	actualPort := listener.Addr().(*net.TCPAddr).Port
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", actualPort)

	cfg := config.LoadForTest()
	cfg.ListenPort = actualPort
	cfg.UpstreamURL = upstream
	cfg.ProviderHint = "openai"
	cfg.ForwardAPIKey = "none"
	cfg.LogLevel = "silent"
	v := vault.New(cfg.VaultSizeLimit)
	traces := audit.NewStore(200)
	firewall := proxy.NewServer(cfg, masker.New(v, cfg), traces)
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", localhostOnly(metrics.Global.Handler(v)))
	mux.HandleFunc("/dashboard", localhostOnly(metrics.Global.HTMLHandler(v)))
	mux.HandleFunc("/audit", localhostOnly(traces.Handler()))
	mux.Handle("/", firewall)
	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 6 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	childArgs := buildCodexArgs(baseURL, authMode, opts.forwarded)
	cmd := exec.Command(codexPath, childArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	fmt.Printf("[ANONMYZ] Codex model traffic -> %s -> %s\n", baseURL, upstream)
	fmt.Printf("[ANONMYZ] Privacy trace: http://127.0.0.1:%d/dashboard\n", actualPort)
	if err := cmd.Start(); err != nil {
		shutdownHTTPServer(server)
		fmt.Fprintf(os.Stderr, "codex: launch failed: %v\n", err)
		return 1
	}

	stopSignals := make(chan struct{})
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-signals:
			// Windows console control events are delivered to both parent and child.
			if runtime.GOOS != "windows" && cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		case <-stopSignals:
		}
	}()

	waitErr := cmd.Wait()
	close(stopSignals)
	signal.Stop(signals)
	printCodexSessionEvidence(os.Stdout, traces)
	shutdownHTTPServer(server)
	select {
	case err := <-serveErr:
		fmt.Fprintf(os.Stderr, "codex: local proxy failed: %v\n", err)
		return 1
	default:
	}
	if waitErr == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return exitErr.ExitCode()
	}
	fmt.Fprintf(os.Stderr, "codex: child process failed: %v\n", waitErr)
	return 1
}

func printCodexSessionEvidence(w io.Writer, traces *audit.Store) {
	list := traces.List()
	fmt.Fprintln(w, "[ANONMYZ] Session evidence (metadata only; raw values never retained)")
	modelRequests := 0
	prevented := 0
	roundTripVerified := 0
	for i := len(list) - 1; i >= 0; i-- {
		trace := list[i]
		if trace.Method != http.MethodPost {
			continue
		}
		modelRequests++
		tracePrevented := 0
		fmt.Fprintf(w, "[ANONMYZ] request=%s path=%s status=%d detections=%d restored=%d response_blocked=%t\n",
			trace.RequestID, trace.Path, trace.UpstreamStatus, len(trace.Detections), trace.RestoredItems, trace.ResponseLeakBlocked)
		for _, detection := range trace.Detections {
			fmt.Fprintf(w, "[ANONMYZ] prevented=%t type=%s placeholder=%s\n",
				detection.OriginalPrevented, detection.SecretType, detection.PlaceholderID)
			if detection.OriginalPrevented {
				tracePrevented++
			}
		}
		prevented += tracePrevented
		if tracePrevented > 0 && trace.UpstreamStatus >= 200 && trace.UpstreamStatus < 300 &&
			trace.RestoredItems > 0 && !trace.ResponseLeakBlocked {
			roundTripVerified += tracePrevented
		}
	}
	switch {
	case modelRequests == 0:
		fmt.Fprintln(w, "[ANONMYZ] NOT VERIFIED: no HTTP model request traversed the proxy")
	case prevented == 0:
		fmt.Fprintln(w, "[ANONMYZ] NOT VERIFIED: no sensitive pattern was prevented in this session")
	case roundTripVerified == 0:
		fmt.Fprintf(w, "[ANONMYZ] PREVENTION VERIFIED: %d sensitive occurrence(s) prevented before upstream\n", prevented)
		fmt.Fprintln(w, "[ANONMYZ] ROUND TRIP NOT VERIFIED: no successful safe restoration completed")
	default:
		fmt.Fprintf(w, "[ANONMYZ] VERIFIED: %d sensitive occurrence(s) prevented before upstream and safely restored\n", roundTripVerified)
	}
}

func listenLoopback(port int) (net.Listener, error) {
	return net.Listen("tcp", loopbackAddr(port))
}

func parseCodexOptions(args []string) (codexOptions, bool, error) {
	var opts codexOptions
parseArgs:
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			opts.forwarded = append([]string(nil), args[i+1:]...)
			break parseArgs
		}
		switch {
		case arg == "--help" || arg == "-h":
			return opts, true, nil
		case arg == "--dry-run" || arg == "--print-config":
			opts.dryRun = true
		case arg == "--port":
			i++
			if i >= len(args) {
				return opts, false, errors.New("--port requires a value")
			}
			port, err := strconv.Atoi(args[i])
			if err != nil || port < 0 || port > 65535 {
				return opts, false, fmt.Errorf("invalid port %q", args[i])
			}
			opts.port = port
		case strings.HasPrefix(arg, "--port="):
			port, err := strconv.Atoi(strings.TrimPrefix(arg, "--port="))
			if err != nil || port < 0 || port > 65535 {
				return opts, false, fmt.Errorf("invalid port %q", strings.TrimPrefix(arg, "--port="))
			}
			opts.port = port
		case arg == "--upstream":
			i++
			if i >= len(args) {
				return opts, false, errors.New("--upstream requires a value")
			}
			opts.upstream = strings.TrimRight(args[i], "/")
		case strings.HasPrefix(arg, "--upstream="):
			opts.upstream = strings.TrimRight(strings.TrimPrefix(arg, "--upstream="), "/")
		default:
			return opts, false, fmt.Errorf("unknown option %q (put Codex arguments after --)", arg)
		}
	}
	if opts.upstream != "" {
		parsed, err := url.Parse(opts.upstream)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil ||
			parsed.RawQuery != "" || parsed.Fragment != "" {
			return opts, false, fmt.Errorf("invalid upstream URL %q", opts.upstream)
		}
	}
	return opts, false, nil
}

func detectCodexAuth(codexPath string) codexAuthMode {
	cmd := exec.Command(codexPath, "login", "status")
	output, err := cmd.CombinedOutput()
	if err == nil {
		status := strings.ToLower(string(output))
		if strings.Contains(status, "chatgpt") {
			return codexAuthChatGPT
		}
		if strings.Contains(status, "api key") {
			return codexAuthStoredAPI
		}
	}
	if strings.TrimSpace(os.Getenv("OPENAI_API_KEY")) != "" {
		return codexAuthEnvironment
	}
	return codexAuthMissing
}

func defaultCodexUpstream(authMode codexAuthMode) string {
	if authMode == codexAuthChatGPT {
		return chatGPTCodexUpstream
	}
	return openAICodexUpstream
}

func buildCodexArgs(baseURL string, authMode codexAuthMode, forwarded []string) []string {
	quotedURL := strconv.Quote(baseURL)
	args := []string{
		"-c", `model_provider="anonmyz"`,
		"-c", `model_providers.anonmyz.name="Anonmyz protected Codex"`,
		"-c", "model_providers.anonmyz.base_url=" + quotedURL,
		"-c", `model_providers.anonmyz.wire_api="responses"`,
		"-c", `model_providers.anonmyz.supports_websockets=false`,
	}
	if authMode == codexAuthEnvironment || authMode == codexAuthMissing {
		args = append(args, "-c", `model_providers.anonmyz.env_key="OPENAI_API_KEY"`)
	} else {
		// Keep Codex's stored API-key or ChatGPT OAuth authentication while using
		// a non-WebSocket provider whose HTTP base is the local proxy.
		args = append(args, "-c", `model_providers.anonmyz.requires_openai_auth=true`)
	}
	// Anonmyz scans plaintext HTTP request bodies. Force this session off the
	// compressed-request transport so model traffic cannot bypass inspection.
	args = append(args, "-c", `features.enable_request_compression=false`)
	return append(args, forwarded...)
}

func shutdownHTTPServer(server *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func printCodexUsage() {
	fmt.Print(`Usage: anonmyz codex [options] -- [codex arguments]

Launch Codex with temporary model-provider overrides that route its model
traffic through a local Anonmyz proxy. Global Codex configuration is unchanged.

Options:
  --dry-run, --print-config  Explain the launch without starting Codex.
  --port PORT               Local proxy port (default: dynamically selected).
  --upstream URL            Provider API base (default selected from Codex authentication).
  -h, --help                Show this help message.

Authentication:
  Supported: Codex ChatGPT login, Codex API-key login, or OPENAI_API_KEY.
  ChatGPT credentials stay managed by Codex; Anonmyz never reads or stores them.
`)
}
