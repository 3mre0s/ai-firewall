package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/3mre0s/ai-firewall/audit"
	"github.com/3mre0s/ai-firewall/config"
	"github.com/3mre0s/ai-firewall/masker"
	"github.com/3mre0s/ai-firewall/proxy"
	"github.com/3mre0s/ai-firewall/vault"
)

var demoPlaceholderPattern = regexp.MustCompile(`\[\[[A-Z_]+_[0-9A-F]{8}\]\]`)

type demoSecret struct {
	name  string
	value string
}

func runDemo(args []string) int {
	for _, arg := range args {
		switch arg {
		case "--help", "-h":
			fmt.Print(`Usage: anonmyz demo [--non-interactive]

Runs a deterministic local security proof through the production masking and
streaming-restoration pipeline. No API key or external service is used.

Options:
  --non-interactive  Disable prompts (the demo is non-interactive by default).
  -h, --help         Show this help message.
`)
			return 0
		case "--non-interactive":
			// The demo never prompts; the flag documents CI/judge intent.
		default:
			fmt.Fprintf(os.Stderr, "demo: unknown option %q\n", arg)
			return 2
		}
	}

	secrets := []demoSecret{
		{name: "GitHub token", value: "ghp_FAKEDEMO0000000000000000000000000000"},
		{name: "OpenAI API key", value: "sk-proj-FAKE_DEMO_KEY_0000000000000000"},
		{name: "private file path", value: "/home/fake-judge/anonmyz/private/config.env"},
		{name: "inline password", value: "FAKE_DEMO_PASSWORD_12345"},
	}

	captured := make(chan []byte, 1)
	upstreamListener, err := listenLoopback(0)
	if err != nil {
		return demoError("start mock upstream", err)
	}
	upstreamServer := &http.Server{Handler: demoUpstreamHandler(captured)}
	go func() { _ = upstreamServer.Serve(upstreamListener) }()

	cfg := config.LoadForTest()
	cfg.UpstreamURL = "http://" + upstreamListener.Addr().String()
	cfg.ProviderHint = "generic"
	cfg.ForwardAPIKey = "none"
	cfg.LogLevel = "silent"
	traces := audit.NewStore(8)
	rootMasker := masker.New(vault.New(cfg.VaultSizeLimit), cfg)
	firewall := proxy.NewServer(cfg, rootMasker, traces)

	proxyListener, err := listenLoopback(0)
	if err != nil {
		_ = upstreamServer.Close()
		return demoError("start local proxy", err)
	}
	proxyServer := &http.Server{Handler: firewall}
	go func() { _ = proxyServer.Serve(proxyListener) }()

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = proxyServer.Shutdown(ctx)
		_ = upstreamServer.Shutdown(ctx)
	}()

	prompt := fmt.Sprintf(
		"Review a fake fixture containing github_token=%s api_key=%s in private file %s with password=%s",
		secrets[0].value, secrets[1].value, secrets[2].value, secrets[3].value,
	)
	payload, err := json.Marshal(map[string]any{
		"model":  "gpt-5.6-demo",
		"stream": true,
		"input":  prompt,
	})
	if err != nil {
		return demoError("build demo request", err)
	}

	requestURL := "http://" + proxyListener.Addr().String() + "/v1/responses"
	req, err := http.NewRequest(http.MethodPost, requestURL, bytes.NewReader(payload))
	if err != nil {
		return demoError("build local request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return demoError("send request through Anonmyz", err)
	}
	responseBody, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		return demoError("read restored stream", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "[FAILED] proxy returned HTTP %d\n", resp.StatusCode)
		return 1
	}

	var upstreamBody []byte
	select {
	case upstreamBody = <-captured:
	case <-time.After(2 * time.Second):
		fmt.Fprintln(os.Stderr, "[FAILED] mock upstream did not receive the request")
		return 1
	}

	for _, secret := range secrets {
		if bytes.Contains(upstreamBody, []byte(secret.value)) {
			fmt.Fprintf(os.Stderr, "[FAILED] %s reached the mock upstream\n", secret.name)
			return 1
		}
		if !bytes.Contains(responseBody, []byte(secret.value)) {
			fmt.Fprintf(os.Stderr, "[FAILED] %s was not restored locally\n", secret.name)
			return 1
		}
	}

	placeholders := demoPlaceholderPattern.FindAll(upstreamBody, -1)
	if len(placeholders) < len(secrets) {
		fmt.Fprintf(os.Stderr, "[FAILED] expected at least %d placeholders upstream, got %d\n", len(secrets), len(placeholders))
		return 1
	}

	traceList := traces.List()
	if len(traceList) != 1 || len(traceList[0].Detections) != len(secrets) {
		fmt.Fprintln(os.Stderr, "[FAILED] privacy trace did not record all demo detections")
		return 1
	}
	trace := traceList[0]
	if trace.StreamingRestoration != "restored" {
		fmt.Fprintf(os.Stderr, "[FAILED] streaming restoration state is %q\n", trace.StreamingRestoration)
		return 1
	}
	for _, detection := range trace.Detections {
		if !detection.OriginalPrevented {
			fmt.Fprintf(os.Stderr, "[FAILED] prevention proof failed for %s\n", detection.SecretType)
			return 1
		}
		if !bytes.Contains(upstreamBody, []byte(detection.PlaceholderID)) {
			fmt.Fprintf(os.Stderr, "[FAILED] placeholder for %s did not reach the mock upstream\n", detection.SecretType)
			return 1
		}
		if bytes.Contains(responseBody, []byte(detection.PlaceholderID)) {
			fmt.Fprintf(os.Stderr, "[FAILED] placeholder for %s was not restored locally\n", detection.SecretType)
			return 1
		}
		fmt.Printf("[DETECTED] %s\n", demoDisplayName(detection.SecretType))
		fmt.Printf("[MASKED]   Replaced with %s\n", strings.Trim(detection.PlaceholderID, "[]"))
	}
	fmt.Println("[UPSTREAM] Original sensitive values absent; placeholders present")
	fmt.Println("[STREAM]   Split placeholder restored correctly")
	fmt.Printf("[RESULT]   %d sensitive values prevented from leaving this machine\n", len(secrets))
	return 0
}

func demoDisplayName(patternName string) string {
	switch {
	case strings.HasPrefix(patternName, "GitHub Personal Access Token"):
		return "GitHub token"
	case patternName == "OpenAI API Key":
		return "OpenAI API key"
	case strings.HasPrefix(patternName, "Inline Secret Assignment"):
		return "inline password"
	case strings.HasPrefix(patternName, "Unix Absolute Path"):
		return "private file path"
	default:
		return patternName
	}
}

func demoUpstreamHandler(captured chan<- []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "cannot read request", http.StatusBadRequest)
			return
		}
		captured <- append([]byte(nil), body...)
		placeholders := demoPlaceholderPattern.FindAll(body, -1)
		if len(placeholders) == 0 {
			http.Error(w, "no placeholders received", http.StatusUnprocessableEntity)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)

		first := string(placeholders[0])
		split := len(first) / 2
		_, _ = io.WriteString(w, `data: {"type":"response.output_text.delta","delta":"`+first[:split])
		if flusher != nil {
			flusher.Flush()
		}
		time.Sleep(10 * time.Millisecond)
		_, _ = io.WriteString(w, first[split:]+`"}`+"\n\n")
		if flusher != nil {
			flusher.Flush()
		}

		for _, placeholder := range placeholders[1:] {
			_, _ = fmt.Fprintf(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":%q}\n\n", string(placeholder))
			if flusher != nil {
				flusher.Flush()
			}
		}
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	})
}

func demoError(action string, err error) int {
	fmt.Fprintf(os.Stderr, "[FAILED] %s: %v\n", action, err)
	return 1
}
