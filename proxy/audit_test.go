package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/3mre0s/ai-firewall/audit"
	"github.com/3mre0s/ai-firewall/config"
	"github.com/3mre0s/ai-firewall/masker"
	"github.com/3mre0s/ai-firewall/vault"
)

func TestPrivacyTraceAndLogsNeverContainRawSecret(t *testing.T) {
	secret := "ghp_FAKEAUDIT" + strings.Repeat("0", 27)
	var captured []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(captured)
	}))
	defer upstream.Close()

	cfg := config.LoadForTest()
	cfg.UpstreamURL = upstream.URL
	cfg.ProviderHint = "generic"
	cfg.ForwardAPIKey = "none"
	cfg.LogLevel = "silent"
	store := audit.NewStore(10)

	var logs bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldWriter)

	server := httptest.NewServer(NewServer(cfg, masker.New(vault.New(10), cfg), store))
	defer server.Close()
	resp, err := http.Post(server.URL+"/v1/responses", "application/json", strings.NewReader(`{"input":"`+secret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	responseBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !bytes.Contains(responseBody, []byte(secret)) {
		t.Fatal("response was not restored locally")
	}
	if bytes.Contains(captured, []byte(secret)) || !demoLabelPattern.Match(captured) {
		t.Fatalf("upstream proof failed: %s", captured)
	}

	traces := store.List()
	if len(traces) != 1 || len(traces[0].Detections) != 1 {
		t.Fatalf("unexpected trace: %#v", traces)
	}
	traceJSON, _ := json.Marshal(traces)
	if bytes.Contains(traceJSON, []byte(secret)) || strings.Contains(logs.String(), secret) {
		t.Fatal("raw secret appeared in audit JSON or logs")
	}
	trace := traces[0]
	if trace.RequestID == "" || trace.ProxyLatencyMS < 0 || !trace.Detections[0].OriginalPrevented {
		t.Fatalf("incomplete trace: %#v", trace)
	}
}

func TestAuthenticationMetadataNeverAppearsInLogsAuditOrErrors(t *testing.T) {
	const (
		authorizationValue = "Bearer oauth-canary-value-never-log"
		accountIDValue     = "account-canary-value-never-log"
		cookieValue        = "session=cookie-canary-value-never-log"
	)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != authorizationValue {
			t.Errorf("Authorization passthrough = %q", got)
		}
		if got := r.Header.Get("ChatGPT-Account-ID"); got != accountIDValue {
			t.Errorf("ChatGPT-Account-ID passthrough = %q", got)
		}
		if got := r.Header.Get("Cookie"); got != "" {
			t.Errorf("Cookie must not be forwarded, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"output":"ok"}`)
	}))
	defer upstream.Close()

	cfg := config.LoadForTest()
	cfg.UpstreamURL = upstream.URL
	cfg.ProviderHint = "openai"
	cfg.ForwardAPIKey = "none"
	cfg.LogLevel = "debug"
	store := audit.NewStore(10)

	var logs bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldWriter)

	server := httptest.NewServer(NewServer(cfg, masker.New(vault.New(10), cfg), store))
	defer server.Close()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/responses", strings.NewReader(`{"input":"safe"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authorizationValue)
	req.Header.Set("ChatGPT-Account-ID", accountIDValue)
	req.Header.Set("Cookie", cookieValue)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	auditJSON, err := json.Marshal(store.List())
	if err != nil {
		t.Fatal(err)
	}
	combined := strings.ToLower(logs.String() + string(auditJSON) + string(responseBody))
	for _, forbidden := range []string{
		strings.ToLower(authorizationValue),
		strings.ToLower(accountIDValue),
		strings.ToLower(cookieValue),
		"oauth-canary-value-never-log",
		"cookie-canary-value-never-log",
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("authentication metadata leaked into logs, audit, or response: %q", forbidden)
		}
	}
}

func TestMalformedStreamingResponseDoesNotExposeOriginal(t *testing.T) {
	secret := "ghp_FAKEMALFORMED" + strings.Repeat("0", 23)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		label := demoLabelPattern.Find(body)
		w.Header().Set("Content-Type", "text/event-stream")
		if len(label) > 4 {
			_, _ = w.Write(append([]byte("data: "), label[:len(label)-3]...))
		}
	}))
	defer upstream.Close()

	cfg := config.LoadForTest()
	cfg.UpstreamURL = upstream.URL
	cfg.ProviderHint = "generic"
	cfg.ForwardAPIKey = "none"
	cfg.LogLevel = "silent"
	store := audit.NewStore(10)
	server := httptest.NewServer(NewServer(cfg, masker.New(vault.New(10), cfg), store))
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/responses", "application/json", strings.NewReader(`{"input":"`+secret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if bytes.Contains(body, []byte(secret)) {
		t.Fatal("malformed upstream stream exposed the original value")
	}
	if got := store.List()[0].StreamingRestoration; got != "not_observed" {
		t.Fatalf("streaming restoration = %q, want not_observed", got)
	}
}

func TestCanceledRequestCancelsUpstream(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	cfg := config.LoadForTest()
	cfg.UpstreamURL = "https://upstream.invalid"
	cfg.ProviderHint = "generic"
	cfg.ForwardAPIKey = "none"
	cfg.LogLevel = "silent"
	server := NewServer(cfg, masker.New(vault.New(10), cfg))
	server.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		close(canceled)
		return nil, r.Context().Err()
	})}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "http://firewall.test/v1/responses", strings.NewReader(`{"input":"safe"}`)).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		server.ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request did not start")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream context was not canceled")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled client request did not return")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

var demoLabelPattern = regexp.MustCompile(`\[\[[A-Z_]+_[0-9A-F]{8}\]\]`)
