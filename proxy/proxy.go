// Package proxy contains the HTTP handler and the streaming processor.
// (HTTP işleyici ve akış işlemcisini içerir.)
package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/3mre0s/ai-firewall/audit"
	"github.com/3mre0s/ai-firewall/config"
	"github.com/3mre0s/ai-firewall/dlp"
	"github.com/3mre0s/ai-firewall/masker"
	"github.com/3mre0s/ai-firewall/metrics"
	"github.com/3mre0s/ai-firewall/providers"
	"github.com/3mre0s/ai-firewall/securitylog"
)

const maxStandardResponseBody = 64 << 20

// ════════════════════════════════════════════════════════════════════════════
// Server — HTTP handler (HTTP işleyici)
// ════════════════════════════════════════════════════════════════════════════

// Server is the HTTP handler that implements the full firewall pipeline.
// It satisfies the http.Handler interface so it can be passed directly
// to http.ListenAndServe.
//
// (Tam güvenlik duvarı boru hattını (pipeline) uygulayan HTTP işleyici.
//
//	http.Handler arayüzünü karşılar, bu nedenle doğrudan http.ListenAndServe'e
//	geçirilebilir.)
type Server struct {
	cfg      *config.Config
	masker   *masker.Masker
	provider providers.Provider
	traces   *audit.Store
	engine   *dlp.Engine
	metrics  metrics.Recorder

	// client is a shared, reusable HTTP client with sensible timeouts.
	// Creating one per request would exhaust file descriptors under load.
	// (Paylaşılan, yeniden kullanılabilir ve makul zaman aşımlarına sahip HTTP istemcisi.
	//  İstek başına bir tane oluşturmak, yük altında dosya tanımlayıcılarını tüketir.)
	client *http.Client
}

// NewServer creates a Server from the provided Config and Masker.
// The provider is resolved via the registry: ProviderHint takes precedence
// over URL-based auto-detection.
// (Sağlanan Config ve Masker'dan bir Server oluşturur.
//
//	Sağlayıcı kayıt üzerinden çözümlenir: ProviderHint, URL tabanlı otomatik algılamadan önce gelir.)
func NewServer(cfg *config.Config, m *masker.Masker, traceStores ...*audit.Store) *Server {
	var traces *audit.Store
	if len(traceStores) > 0 {
		traces = traceStores[0]
	}
	return NewServerWithMetrics(cfg, m, traces, metrics.NopRecorder())
}

// NewServerWithMetrics creates an independently observable server. The
// recorder is injected so multiple servers and parallel tests do not share
// mutable counter state.
func NewServerWithMetrics(cfg *config.Config, m *masker.Masker, traces *audit.Store, recorder metrics.Recorder) *Server {
	var p providers.Provider
	if cfg.ProviderHint != "" {
		p = providers.DetectByHint(cfg.ProviderHint)
		if cfg.LogLevel != "silent" {
			log.Printf("[firewall][info] provider override: %s", p.Name())
		}
	} else {
		p = providers.Detect(cfg.UpstreamURL)
		if cfg.LogLevel != "silent" {
			log.Printf("[firewall][info] provider auto-detected: %s", p.Name())
		}
	}

	if recorder == nil {
		recorder = metrics.NopRecorder()
	}

	return &Server{
		cfg:      cfg,
		masker:   m,
		provider: p,
		traces:   traces,
		engine:   dlp.NewEngine(m, maxStandardResponseBody),
		metrics:  recorder,
		client: &http.Client{
			// 5-minute timeout accommodates long AI-generated responses.
			// (5 dakika zaman aşımı, uzun yapay zeka yanıtlarını karşılar.)
			Timeout: 5 * time.Minute,
			// Do not follow redirects automatically; surface them to the caller.
			// (Yönlendirmeleri otomatik takip etme; çağırana göster.)
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// ServeHTTP is the single entry point for every request.
// It runs the five-step firewall pipeline:
//
//  1. Read request body (istek gövdesini oku)
//  2. Mask sensitive data going upstream (hedefe giden hassas veriyi maskele)
//  3. Forward sanitised request to the real AI API (temiz isteği gerçek AI API'sine ilet)
//  4. Detect streaming vs. standard response (akış ile standart yanıtı tespit et)
//  5. Unmask labels in the response before returning to the client
//     (istemciye döndürmeden önce yanıttaki etiketlerin maskesini kaldır)
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := securitylog.NewRequestID()

	// ── Health / status endpoints (Sağlık / durum uç noktaları) ──────────────
	// These are handled before the pipeline so they never touch the vault.
	// (Bu noktalar boru hattından önce işlenir; vault'a asla dokunmazlar.)
	// Enforce a 32 MB request body limit. This covers Anthropic's 200K-token
	// context (~800 KB) and Claude Code whole-repository prompts with a generous
	// safety margin. Requests larger than this are rejected with 413.
	// (32 MB istek gövdesi sınırı. Anthropic 200K token bağlamı (~800 KB) ve
	//  Claude Code tam-repo prompt'larını geniş bir güvenlik marjıyla karşılar.
	//  Bu sınırı aşan istekler 413 ile reddedilir.)
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)

	// Recover from any unexpected panics so a single bad request never takes
	// down the proxy process.
	// (Beklenmedik paniklerden kurtar; tek bir hatalı istek proxy sürecini
	//  asla çökertmez.)
	defer func() {
		if rec := recover(); rec != nil {
			if s != nil {
				s.requestEvent(requestID, "error", "panic_recovered", "request handler panic", nil)
			} else {
				log.Printf("[firewall][error] panic recovered: %v", rec)
			}
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}()

	switch r.URL.Path {
	case "/health":
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
			log.Printf("[firewall][error] health response write failed: %v", err)
		}
		return
	}

	// Only POST requests reach AI endpoints; reject everything else early.
	// (Yalnızca POST istekleri AI uç noktalarına ulaşır; diğerlerini erken reddet.)
	modelCatalogRequest := r.Method == http.MethodGet && r.URL.Path == "/models"
	if r.Method != http.MethodPost && !modelCatalogRequest {
		s.metrics.IncBlockedRequests()
		w.Header().Set("X-Anonmyz-Request-Id", requestID)
		s.requestEvent(requestID, "warn", "request_blocked", "method not allowed", map[string]any{"method": r.Method, "path": r.URL.Path})
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.metrics.IncRequests()
	trace := audit.Trace{
		RequestID:            requestID,
		Timestamp:            time.Now().UTC(),
		Method:               r.Method,
		Path:                 r.URL.Path,
		StreamingRestoration: "not_applicable",
	}
	var localLatency time.Duration
	defer func() {
		trace.ProxyLatencyMS = float64(localLatency.Microseconds()) / 1000
		s.traces.Add(trace)
	}()
	w.Header().Set("X-Anonmyz-Request-Id", trace.RequestID)
	s.requestEvent(requestID, "info", "request_started", "request entered DLP pipeline", map[string]any{"method": r.Method, "path": r.URL.Path, "provider": s.provider.Name()})

	// ── Step 1: Read the full request body ───────────────────────────────────
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "cannot read request body", http.StatusBadRequest)
		return
	}
	defer func() { _ = r.Body.Close() }()

	// ── Step 2: Mask — sanitise the outgoing payload ─────────────────────────
	// (Maskeleme — giden yükü temizle)
	if encoding := strings.TrimSpace(r.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		s.metrics.IncBlockedRequests()
		s.requestEvent(requestID, "warn", "request_blocked", "compressed request body rejected", nil)
		http.Error(w, "compressed request bodies are not supported", http.StatusUnsupportedMediaType)
		return
	}

	localStart := time.Now()
	exchange, prepareErr := s.engine.Prepare(body)
	if exchange != nil {
		defer exchange.Close()
	}
	maskResult := exchange.Mask
	localLatency += time.Since(localStart)
	for _, detection := range maskResult.Detections {
		trace.Detections = append(trace.Detections, audit.Detection{
			SecretType:        detection.Name,
			PlaceholderID:     detection.PlaceholderID,
			OriginalPrevented: detection.OriginalPrevented,
		})
	}

	// Kısmi maskeleme gerçekleştiyse metrikleri kaydet (vault-full durumunda bile).
	// (Even if vault was full, count whatever was successfully masked.)
	if maskResult.MaskedCount > 0 {
		s.metrics.IncMaskedRequests()
		s.metrics.IncMaskedItems(int64(maskResult.MaskedCount))
		s.requestEvent(requestID, "info", "request_masked", "sensitive values replaced", map[string]any{"count": maskResult.MaskedCount})
	}

	// Vault-full guard: if any sensitive value could not be masked because the
	// vault was at capacity, we block the request with 507 rather than forwarding
	// plaintext secrets to the upstream AI.
	//
	// Resolution: increase VAULT_SIZE_LIMIT; the limit applies to this request scope.
	// (Vault dolu koruması: vault kapasitesi dolduğu için maskelenememiş hassas
	//  bir değer varsa, düz metin sırları upstream'e iletmek yerine isteği 507
	//  ile bloklarız.
	//  Çözüm: VAULT_SIZE_LIMIT değerini artır veya vault'u temizlemek için
	//  proxy'yi yeniden başlat.)
	if errors.Is(prepareErr, dlp.ErrVaultFull) {
		s.metrics.IncBlockedRequests()
		s.requestEvent(requestID, "error", "request_blocked", "vault capacity exceeded", map[string]any{"unmasked_count": maskResult.VaultEvictions})
		http.Error(w,
			`{"error":"firewall_vault_full","message":"Vault capacity exceeded. Request blocked to prevent data leak. Increase VAULT_SIZE_LIMIT or restart the proxy."}`,
			http.StatusInsufficientStorage) // 507
		return
	}
	if prepareErr != nil {
		http.Error(w, "request inspection failed", http.StatusInternalServerError)
		return
	}

	// ── Step 3: Forward the clean request upstream ───────────────────────────
	// (Temiz isteği yukarı yönlü ilet)

	// SSRF Protection: Use r.URL.Path and r.URL.RawQuery strictly instead of
	// r.URL.RequestURI() which might contain an absolute URI from a malicious client.
	// (SSRF Koruması: Kötü niyetli bir istemciden gelen tam URL'leri engellemek için
	// RequestURI yerine sadece Path ve RawQuery kullan.)
	localStart = time.Now()
	upstreamPath := r.URL.Path
	if r.URL.RawQuery != "" {
		upstreamPath += "?" + r.URL.RawQuery
	}
	upstreamURL := s.cfg.UpstreamURL + upstreamPath

	upstreamReq, err := http.NewRequestWithContext(
		r.Context(),
		r.Method,
		upstreamURL,
		bytes.NewBufferString(maskResult.Text),
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot build upstream request: %v", err),
			http.StatusInternalServerError)
		return
	}

	s.copyRequestHeaders(r.Header, upstreamReq.Header)
	// Response placeholders must remain visible so they can be restored.
	upstreamReq.Header.Set("Accept-Encoding", "identity")

	// Delegate authentication to the provider — it knows which headers to set.
	// (Kimlik doğrulamayı sağlayıcıya devret — hangi başlıkları ayarlayacağını bilir.)
	s.provider.PrepareHeaders(upstreamReq.Header, s.cfg.ForwardAPIKey)
	localLatency += time.Since(localStart)

	resp, err := s.client.Do(upstreamReq)
	if err != nil {
		s.metrics.IncUpstreamErrors()
		s.requestEvent(requestID, "error", "upstream_error", "upstream request failed", nil)
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	trace.UpstreamStatus = resp.StatusCode
	if encoding := strings.TrimSpace(resp.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		s.metrics.IncUpstreamErrors()
		s.requestEvent(requestID, "error", "response_blocked", "compressed upstream response rejected", map[string]any{"status": resp.StatusCode})
		http.Error(w, "compressed upstream response rejected", http.StatusBadGateway)
		return
	}

	s.requestEvent(requestID, "info", "upstream_response", "upstream response received", map[string]any{"status": resp.StatusCode, "streaming": s.provider.IsStream(resp)})
	if resp.StatusCode >= 400 {
		s.metrics.IncUpstreamErrors()
	}

	// ── Step 4: Detect streaming (akış tespiti) ───────────────────────────────
	// Delegate to the provider — each provider knows its own streaming convention.
	// (Sağlayıcıya devret — her sağlayıcı kendi akış kuralını bilir.)
	isStream := s.provider.IsStream(resp)
	trace.Streaming = isStream
	if isStream {
		s.metrics.IncStreamRequests()
	}

	// ── Step 5: Unmask and deliver the response ───────────────────────────────
	// (Maskeyi kaldır ve yanıtı teslim et)
	if isStream {
		// Streaming headers must be committed before the first chunk. Standard
		// responses are inspected completely before any upstream status/header is
		// exposed, allowing fail-closed errors to return a real 502.
		s.copyResponseHeaders(resp.Header, w.Header())
		w.WriteHeader(resp.StatusCode)
		restored, failed, processingLatency := s.handleStream(w, resp.Body, exchange.Masker, requestID)
		localLatency += processingLatency
		trace.RestoredItems = restored
		trace.ResponseLeakBlocked = failed
		switch {
		case failed:
			trace.StreamingRestoration = "failed"
		case restored > 0:
			trace.StreamingRestoration = "restored"
		default:
			trace.StreamingRestoration = "not_observed"
		}
	} else {
		restored, failed, processingLatency := s.handleStandard(w, resp.Body, exchange, requestID, resp.StatusCode, resp.Header)
		localLatency += processingLatency
		trace.RestoredItems = restored
		trace.ResponseLeakBlocked = failed
		trace.StreamingRestoration = "not_streaming"
	}
}

// handleStandard reads the entire response body, unmasks it, and writes once.
// (Tüm yanıt gövdesini okur, maskesini kaldırır ve bir kez yazar.)
func (s *Server) handleStandard(w http.ResponseWriter, body io.Reader, exchange *dlp.Exchange, requestID string, statusCode int, headers http.Header) (int, bool, time.Duration) {
	started := time.Now()
	result, err := s.engine.RestoreStandard(exchange, body)
	processingLatency := time.Since(started)
	if err != nil {
		s.requestEvent(requestID, "error", "response_blocked", "standard response rejected", map[string]any{"reason": err.Error()})
		if statusCode > 0 {
			http.Error(w, "unsafe upstream response rejected", http.StatusBadGateway)
		}
		return 0, true, processingLatency
	}
	// Count unmasked items (replaced labels) for metrics.
	// (Metrikler için maskeleri kaldırılan öğeleri say.)
	if result.Restored > 0 {
		s.metrics.IncUnmaskedItems(int64(result.Restored))
	}
	if statusCode > 0 {
		s.copyResponseHeaders(headers, w.Header())
		w.WriteHeader(statusCode)
	}
	if _, err := w.Write(result.Body); err != nil {
		s.requestEvent(requestID, "error", "client_write_error", "standard response write failed", nil)
		return result.Restored, true, processingLatency
	}
	s.requestEvent(requestID, "info", "response_restored", "standard response delivered", map[string]any{"restored": result.Restored})
	return result.Restored, false, processingLatency
}

func readLimitedBody(body io.Reader, limit int64) ([]byte, bool, error) {
	raw, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, false, err
	}
	return raw, int64(len(raw)) > limit, nil
}

// handleStream processes the SSE body chunk-by-chunk via streamProcessor.
// http.Flusher is required; if the ResponseWriter doesn't support it we fall
// back to buffering the whole response (graceful degradation).
//
// KNOWN LIMITATION — partial-chunk delivery on fail-fast:
// The fail-fast mechanism terminates the stream as soon as a secret pattern is
// detected in the CURRENT chunk.  Any chunks that were already flushed to the
// HTTP response writer before detection cannot be recalled — HTTP streaming
// has no rewind.  The leaked content (the offending chunk itself) is suppressed:
// the proxy drops it and closes the connection, so the client receives an abrupt
// EOF instead.  Chunks sent BEFORE the secret-bearing chunk are unaffected.
//
// (BİLİNEN SINIR — fail-fast sırasında kısmi-chunk iletimi:
//
//	Fail-fast mekanizması, MEVCUT chunk'ta bir sır deseni tespit edildiği anda
//	akışı sonlandırır. Tespitten önce HTTP yanıt yazıcısına aktarılmış chunk'lar
//	geri alınamaz — HTTP streaming'de geri sarma yoktur. Sızdırılan içerik
//	(sorunlu chunk'ın kendisi) bastırılır: proxy onu düşürür ve bağlantıyı kapatır,
//	böylece istemci beklenmedik bir EOF alır. Sır barındıran chunk'tan ÖNCEKİ
//	chunk'lar etkilenmez.)
func (s *Server) handleStream(w http.ResponseWriter, body io.Reader, requestMasker *masker.Masker, requestID string) (int, bool, time.Duration) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.logf("warn", "ResponseWriter does not support streaming (akışı desteklemiyor), buffering")
		exchange := &dlp.Exchange{Masker: requestMasker}
		return s.handleStandard(w, body, exchange, requestID, 0, nil)
	}

	processor := NewStreamProcessor(requestMasker)
	buf := make([]byte, 4096)
	var processingLatency time.Duration

	for {
		n, err := body.Read(buf)
		if n > 0 {
			started := time.Now()
			out := processor.Process(buf[:n])
			processingLatency += time.Since(started)
			// Fail-fast: secret detected in output — close connection immediately.
			// (Hızlı başarısızlık: çıktıda sır tespit edildi — bağlantıyı derhal kapat.)
			if processor.LeakDetected() {
				s.requestEvent(requestID, "error", "response_blocked", "secret detected in stream", nil)
				return processor.RestoredCount(), true, processingLatency
			}
			if out != "" {
				if _, err := w.Write([]byte(out)); err != nil {
					s.requestEvent(requestID, "error", "client_write_error", "stream response write failed", nil)
					return processor.RestoredCount(), true, processingLatency
				}
				flusher.Flush()
			}
		}
		if err != nil {
			if err != io.EOF {
				s.logf("error", "stream read (akış okuma): %v", err)
			}
			break
		}
	}

	// Flush any remaining buffered content.
	// (Kalan arabelleğe alınmış içeriği temizle.)
	started := time.Now()
	tail := processor.Flush()
	processingLatency += time.Since(started)
	if processor.LeakDetected() {
		s.requestEvent(requestID, "error", "response_blocked", "secret detected in stream tail", nil)
		return processor.RestoredCount(), true, processingLatency
	}
	if tail != "" {
		if _, err := w.Write([]byte(tail)); err != nil {
			s.requestEvent(requestID, "error", "client_write_error", "stream tail write failed", nil)
			return processor.RestoredCount(), true, processingLatency
		}
		flusher.Flush()
	}
	restored := processor.RestoredCount()
	if restored > 0 {
		s.metrics.IncUnmaskedItems(int64(restored))
	}
	s.requestEvent(requestID, "info", "response_restored", "stream response delivered", map[string]any{"restored": restored})
	return restored, false, processingLatency
}

// ════════════════════════════════════════════════════════════════════════════
// Header filtering (Başlık filtreleme)
// ════════════════════════════════════════════════════════════════════════════

// allowedRequestHeaders lists headers the client is permitted to send upstream.
// We use an explicit allow-list (izin listesi) rather than forwarding everything
// to prevent header injection attacks (başlık enjeksiyon saldırıları).
//
// NOTE: Authentication headers (like Authorization, X-Goog-Api-Key) are included
// in this list so they can flow through unchanged during passthrough mode
// (FORWARD_API_KEY=none). In API-key mode, provider.PrepareHeaders() will overwrite
// or delete them to prevent credential leaks.
var allowedRequestHeaders = []string{
	"Accept",
	"Accept-Language",
	"Content-Type",
	"X-Request-Id",
	"Anthropic-Version",
	"Anthropic-Beta",
	"Openai-Organization",
	"Openai-Project",
	"Openai-Beta",
	"ChatGPT-Account-ID",
	"Originator",
	"Version",
	"Session-ID",
	"Thread-ID",
	"X-Client-Request-ID",
	"X-Codex-Installation-ID",
	"X-Codex-Turn-State",
	"X-Codex-Turn-Metadata",
	"X-Codex-Parent-Thread-ID",
	"X-Codex-Window-ID",
	"X-OpenAI-Memgen-Request",
	"X-OpenAI-Subagent",
	"X-OpenAI-Internal-Codex-Responses-Lite",
	"X-ResponsesAPI-Include-Timing-Metrics",
	"X-OAI-Attestation",
	"Authorization", // passthrough mode (FORWARD_API_KEY=none): client's Bearer token flows through
	"X-Api-Key",
	"X-Goog-Api-Key",
	"Api-Key",
}

// allowedResponseHeaders lists upstream headers we forward back to the client.
var allowedResponseHeaders = []string{
	"Content-Type",
	"X-Request-Id",
	"Anthropic-Ratelimit-Requests-Limit",
	"Anthropic-Ratelimit-Requests-Remaining",
	"X-Ratelimit-Limit-Requests",
	"X-Ratelimit-Remaining-Requests",
	"X-Codex-Turn-State",
}

func (s *Server) copyRequestHeaders(src, dst http.Header) {
	for _, h := range allowedRequestHeaders {
		if v := src.Get(h); v != "" {
			dst.Set(h, v)
		}
	}
}

func (s *Server) copyResponseHeaders(src, dst http.Header) {
	for _, h := range allowedResponseHeaders {
		if v := src.Get(h); v != "" {
			dst.Set(h, v)
		}
	}
}

// ════════════════════════════════════════════════════════════════════════════
// Logging (Loglama)
// ════════════════════════════════════════════════════════════════════════════

func (s *Server) logf(level, format string, args ...any) {
	if s.cfg.LogLevel == "silent" {
		return
	}
	if level == "debug" && s.cfg.LogLevel != "debug" {
		return
	}
	log.Printf("[firewall][%s] %s", level, fmt.Sprintf(format, args...))
}

func (s *Server) requestEvent(requestID, level, event, message string, fields map[string]any) {
	if s.cfg.LogLevel == "silent" || (level == "debug" && s.cfg.LogLevel != "debug") {
		return
	}
	securitylog.Event("proxy", level, requestID, event, message, fields)
}

// ════════════════════════════════════════════════════════════════════════════
// streamProcessor — SSE chunk-by-chunk unmasking (SSE parça bazlı maskeleme kaldırma)
// ════════════════════════════════════════════════════════════════════════════

// streamProcessor handles chunk-by-chunk unmasking of a Server-Sent Events (SSE)
// (Sunucu Tarafından Gönderilen Olaylar) response.
//
// The core challenge (temel zorluk):
//
//	The upstream AI sends data in small chunks.  A vault label like
//	[[SECRET_A4F0C8B2]] might be split across two consecutive chunks:
//
//	  chunk 1: "Here is the value: [[SECRET_"
//	  chunk 2: "A4F0C8B2]] — use it wisely."
//
//	Naively unmasking each chunk independently would leave a broken label
//	in chunk 1 that can never be resolved.
//
//	Solution (çözüm): keep a rolling buffer (sürekli arabellek).  We only
//	flush (temizle) text up to the last position where we are certain no
//	label is still forming.  The tail of each chunk is held in the buffer
//	until the next chunk arrives and we can see the full label.
//
// (Yukarı yönlü AI küçük parçalar halinde veri gönderir. Bir kasa etiketi
//
//	iki ardışık parça arasında bölünebilir. Her parçayı bağımsız olarak
//	çözmek, asla çözülemeyen bozuk bir etiket bırakır.
//	Çözüm: sürekli bir arabellek tutmak. Yalnızca hiçbir etiketin hâlâ
//	oluşmadığından emin olduğumuz konuma kadar metni temizleriz.)
//
// StreamProcessor remains exported from proxy for compatibility. The implementation
// lives in dlp so explicit-proxy and MITM paths use the same security logic.
type StreamProcessor = dlp.StreamProcessor

const maxStreamBufBytes = dlp.MaxStreamBufferBytes

func NewStreamProcessor(m *masker.Masker) *StreamProcessor {
	return dlp.NewStreamProcessor(m)
}

func SafeCutpoint(text string) int {
	return dlp.SafeCutpoint(text)
}
