package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/3mre0s/ai-firewall/config"
	"github.com/3mre0s/ai-firewall/masker"
	"github.com/3mre0s/ai-firewall/vault"
)

type pipeHijackWriter struct {
	header http.Header
	conn   net.Conn
}

func (w *pipeHijackWriter) Header() http.Header         { return w.header }
func (w *pipeHijackWriter) WriteHeader(int)             {}
func (w *pipeHijackWriter) Write(p []byte) (int, error) { return w.conn.Write(p) }
func (w *pipeHijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

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

func TestWriteMITMErrorProducesFramedResponse(t *testing.T) {
	var output bytes.Buffer
	writeMITMError(&output, http.StatusBadGateway, "unsafe upstream")
	if !strings.Contains(output.String(), "HTTP/1.1 502 Bad Gateway") ||
		!strings.Contains(output.String(), "Content-Length: 16") ||
		!strings.HasSuffix(output.String(), "unsafe upstream\n") {
		t.Fatalf("malformed MITM error response: %q", output.String())
	}
}

func TestUnmaskStandardResponseFailsClosed(t *testing.T) {
	cfg := config.LoadForTest()
	requestMasker := masker.New(vault.New(cfg.VaultSizeLimit), cfg)
	t.Cleanup(requestMasker.Reset)

	original := "ghp_" + strings.Repeat("a", 36)
	masked := requestMasker.Mask(`{"token":"` + original + `"}`)
	if masked.MaskedCount != 1 {
		t.Fatalf("masked count = %d, want 1", masked.MaskedCount)
	}

	restored, safe := unmaskStandardResponse([]byte(masked.Text), requestMasker)
	if !safe {
		t.Fatal("response containing a known placeholder was rejected")
	}
	if !bytes.Contains(restored, []byte(original)) {
		t.Fatal("known placeholder was not restored")
	}

	for _, unsafe := range []string{
		original,
		"ghp_" + strings.Repeat("b", 36),
	} {
		if body, safe := unmaskStandardResponse([]byte(unsafe), requestMasker); safe || body != nil {
			t.Fatalf("unsafe response was accepted: %q", unsafe)
		}
	}
}

func TestKeepAliveRequestsUseIsolatedExchanges(t *testing.T) {
	var firstMasked string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if firstMasked == "" {
			firstMasked = string(body)
			_, _ = w.Write(body)
			return
		}
		_, _ = w.Write([]byte(firstMasked))
	}))
	defer upstream.Close()

	cfg := config.LoadForTest()
	m := masker.New(vault.New(cfg.VaultSizeLimit), cfg)
	p := NewMITMProxy(nil, m, cfg)
	p.httpClient = upstream.Client()
	authority := strings.TrimPrefix(upstream.URL, "https://")

	clientRaw, serverRaw := net.Pipe()
	defer func() { _ = clientRaw.Close() }()
	defer func() { _ = serverRaw.Close() }()
	serverTLS := tls.Server(serverRaw, upstream.TLS.Clone())
	clientTLS := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true}) // test-only in-memory peer

	serverDone := make(chan error, 1)
	go func() {
		if err := serverTLS.Handshake(); err != nil {
			serverDone <- err
			return
		}
		reader := bufio.NewReader(serverTLS)
		if !p.handleMITMRequest(serverTLS, reader, authority) {
			serverDone <- fmt.Errorf("first request unexpectedly closed keep-alive connection")
			return
		}
		if p.handleMITMRequest(serverTLS, reader, authority) {
			serverDone <- fmt.Errorf("second request unexpectedly kept connection alive")
			return
		}
		serverDone <- nil
	}()

	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	secret := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	firstBody := `{"value":"` + secret + `"}`
	if _, err := fmt.Fprintf(clientTLS, "POST /first HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s", authority, len(firstBody), firstBody); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(clientTLS)
	firstResp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstOutput, _ := io.ReadAll(firstResp.Body)
	_ = firstResp.Body.Close()
	if !bytes.Contains(firstOutput, []byte(secret)) {
		t.Fatalf("first response did not restore its own secret: %q", firstOutput)
	}

	secondBody := `{"value":"safe"}`
	if _, err := fmt.Fprintf(clientTLS, "POST /second HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", authority, len(secondBody), secondBody); err != nil {
		t.Fatal(err)
	}
	secondResp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondOutput, _ := io.ReadAll(secondResp.Body)
	_ = secondResp.Body.Close()
	if bytes.Contains(secondOutput, []byte(secret)) {
		t.Fatalf("first request secret restored in second request: %q", secondOutput)
	}
	if !bytes.Contains(secondOutput, []byte("[[GH_PAT_")) {
		t.Fatalf("unknown prior placeholder should remain inert: %q", secondOutput)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestServeHTTPConnectPerformsTLSInterception(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AI_FIREWALL_CA_PASSPHRASE", "")
	ca, err := LoadOrCreateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	cfg := config.LoadForTest()
	m := masker.New(vault.New(cfg.VaultSizeLimit), cfg)
	p := NewMITMProxy(ca, m, cfg)
	transport := upstream.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // test-only redirected upstream
	p.httpClient = &http.Client{Transport: transport}

	clientRaw, serverRaw := net.Pipe()
	writer := &pipeHijackWriter{header: make(http.Header), conn: serverRaw}
	req := httptest.NewRequest(http.MethodConnect, "http://api.openai.com:443", nil)
	req.Host = "api.openai.com:443"
	done := make(chan struct{})
	go func() {
		p.ServeHTTP(writer, req)
		close(done)
	}()

	reader := bufio.NewReader(clientRaw)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line, "200 Connection Established") {
		t.Fatalf("CONNECT response = %q, %v", line, err)
	}
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("failed to trust generated CA")
	}
	clientTLS := tls.Client(&bufferedConn{Conn: clientRaw, reader: reader}, &tls.Config{
		RootCAs: pool, ServerName: "api.openai.com", MinVersion: tls.VersionTLS12,
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	secret := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	body := `{"value":"` + secret + `"}`
	if _, err := fmt.Fprintf(clientTLS, "POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), nil)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Contains(responseBody, []byte(secret)) {
		t.Fatalf("intercepted response status=%d body=%q", resp.StatusCode, responseBody)
	}
	if resp.Header.Get("X-Anonmyz-Request-Id") == "" {
		t.Fatal("MITM response missing request ID")
	}
	_ = clientTLS.Close()
	<-done
}

func TestMITMStreamingResponseUsesSharedDLPProcessor(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		midpoint := len(body) / 2
		_, _ = w.Write(append([]byte("data: "), body[:midpoint]...))
		flusher.Flush()
		_, _ = w.Write(append(body[midpoint:], []byte("\n\n")...))
		flusher.Flush()
	}))
	defer upstream.Close()

	cfg := config.LoadForTest()
	m := masker.New(vault.New(cfg.VaultSizeLimit), cfg)
	p := NewMITMProxy(nil, m, cfg)
	p.httpClient = upstream.Client()
	authority := strings.TrimPrefix(upstream.URL, "https://")

	clientRaw, serverRaw := net.Pipe()
	defer func() { _ = clientRaw.Close() }()
	defer func() { _ = serverRaw.Close() }()
	serverTLS := tls.Server(serverRaw, upstream.TLS.Clone())
	clientTLS := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true}) // test-only in-memory peer
	serverDone := make(chan error, 1)
	go func() {
		if err := serverTLS.Handshake(); err != nil {
			serverDone <- err
			return
		}
		if p.handleMITMRequest(serverTLS, bufio.NewReader(serverTLS), authority) {
			serverDone <- fmt.Errorf("close request unexpectedly kept alive")
			return
		}
		serverDone <- nil
	}()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	secret := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	body := `{"value":"` + secret + `"}`
	if _, err := fmt.Fprintf(clientTLS, "POST /stream HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", authority, len(body), body); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), nil)
	if err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output, []byte(secret)) || !bytes.Contains(output, []byte("data:")) {
		t.Fatalf("stream response was not restored: %q", output)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
