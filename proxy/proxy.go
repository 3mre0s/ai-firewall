// Package proxy contains the HTTP handler and the streaming processor.
// (HTTP işleyici ve akış işlemcisini içerir.)
package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/3mre0s/ai-firewall/audit"
	"github.com/3mre0s/ai-firewall/config"
	"github.com/3mre0s/ai-firewall/masker"
	"github.com/3mre0s/ai-firewall/metrics"
	"github.com/3mre0s/ai-firewall/providers"
)

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

	var traces *audit.Store
	if len(traceStores) > 0 {
		traces = traceStores[0]
	}

	return &Server{
		cfg:      cfg,
		masker:   m,
		provider: p,
		traces:   traces,
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
				s.logf("error", "panic recovered (panik kurtarıldı): %v", rec)
			} else {
				log.Printf("[firewall][error] panic recovered: %v", rec)
			}
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}()

	switch r.URL.Path {
	case "/health":
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
		return
	}

	// Only POST requests reach AI endpoints; reject everything else early.
	// (Yalnızca POST istekleri AI uç noktalarına ulaşır; diğerlerini erken reddet.)
	modelCatalogRequest := r.Method == http.MethodGet && r.URL.Path == "/models"
	if r.Method != http.MethodPost && !modelCatalogRequest {
		metrics.Global.IncBlockedRequests()
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metrics.Global.IncRequests()
	trace := audit.Trace{
		RequestID:            newRequestID(),
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
	s.logf("info", "→ %s %s [provider: %s]", r.Method, r.URL.Path, s.provider.Name())

	requestMasker := s.masker.NewScope()
	defer requestMasker.Reset()

	// ── Step 1: Read the full request body ───────────────────────────────────
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "cannot read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// ── Step 2: Mask — sanitise the outgoing payload ─────────────────────────
	// (Maskeleme — giden yükü temizle)
	if encoding := strings.TrimSpace(r.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		metrics.Global.IncBlockedRequests()
		http.Error(w, "compressed request bodies are not supported", http.StatusUnsupportedMediaType)
		return
	}

	localStart := time.Now()
	maskResult := requestMasker.Mask(string(body))
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
		metrics.Global.IncMaskedRequests()
		metrics.Global.IncMaskedItems(int64(maskResult.MaskedCount))
		s.logf("info", "🛡  masked %d item(s) (maskelendi): %v",
			maskResult.MaskedCount, maskResult.ByType)
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
	if maskResult.VaultEvictions > 0 {
		metrics.Global.IncBlockedRequests()
		s.logf("error", "🚨 vault full — %d secret(s) could not be masked, request blocked",
			maskResult.VaultEvictions)
		http.Error(w,
			`{"error":"firewall_vault_full","message":"Vault capacity exceeded. Request blocked to prevent data leak. Increase VAULT_SIZE_LIMIT or restart the proxy."}`,
			http.StatusInsufficientStorage) // 507
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
		metrics.Global.IncUpstreamErrors()
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	trace.UpstreamStatus = resp.StatusCode
	if encoding := strings.TrimSpace(resp.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		metrics.Global.IncUpstreamErrors()
		http.Error(w, "compressed upstream response rejected", http.StatusBadGateway)
		return
	}

	s.logf("info", "← upstream %d", resp.StatusCode)
	if resp.StatusCode >= 400 {
		metrics.Global.IncUpstreamErrors()
	}

	// ── Step 4: Detect streaming (akış tespiti) ───────────────────────────────
	// Delegate to the provider — each provider knows its own streaming convention.
	// (Sağlayıcıya devret — her sağlayıcı kendi akış kuralını bilir.)
	isStream := s.provider.IsStream(resp)
	trace.Streaming = isStream
	if isStream {
		metrics.Global.IncStreamRequests()
	}

	// Copy safe response headers to the client.
	// (Güvenli yanıt başlıklarını istemciye kopyala.)
	s.copyResponseHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)

	// ── Step 5: Unmask and deliver the response ───────────────────────────────
	// (Maskeyi kaldır ve yanıtı teslim et)
	if isStream {
		restored, failed, processingLatency := s.handleStream(w, resp.Body, requestMasker)
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
		restored, failed, processingLatency := s.handleStandard(w, resp.Body, requestMasker)
		localLatency += processingLatency
		trace.RestoredItems = restored
		trace.ResponseLeakBlocked = failed
		trace.StreamingRestoration = "not_streaming"
	}
}

func newRequestID() string {
	var buf [6]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return "req_" + hex.EncodeToString(buf[:])
	}
	return fmt.Sprintf("req_%x", time.Now().UnixNano())
}

// handleStandard reads the entire response body, unmasks it, and writes once.
// (Tüm yanıt gövdesini okur, maskesini kaldırır ve bir kez yazar.)
func (s *Server) handleStandard(w http.ResponseWriter, body io.Reader, requestMasker *masker.Masker) (int, bool, time.Duration) {
	raw, err := io.ReadAll(body)
	if err != nil {
		s.logf("error", "reading standard response (standart yanıt okunuyor): %v", err)
		return 0, true, 0
	}
	started := time.Now()
	if requestMasker.ContainsOriginal(string(raw)) || requestMasker.HasCredentialSecrets(string(raw)) {
		processingLatency := time.Since(started)
		s.logf("error", "secret detected in standard response - suppressing body")
		return 0, true, processingLatency
	}
	unmasked, replaced := requestMasker.UnmaskWithCount(string(raw))
	processingLatency := time.Since(started)
	// Count unmasked items (replaced labels) for metrics.
	// (Metrikler için maskeleri kaldırılan öğeleri say.)
	if replaced > 0 {
		metrics.Global.IncUnmaskedItems(int64(replaced))
	}
	w.Write([]byte(unmasked))
	return replaced, false, processingLatency
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
func (s *Server) handleStream(w http.ResponseWriter, body io.Reader, requestMasker *masker.Masker) (int, bool, time.Duration) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.logf("warn", "ResponseWriter does not support streaming (akışı desteklemiyor), buffering")
		return s.handleStandard(w, body, requestMasker)
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
				s.logf("error", "🚨 secret detected in stream — terminating connection (akışta sır tespit edildi — bağlantı sonlandırılıyor)")
				return processor.RestoredCount(), true, processingLatency
			}
			if out != "" {
				w.Write([]byte(out))
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
		s.logf("error", "🚨 secret in stream tail — terminating (akış kuyruğunda sır — sonlandırılıyor)")
		return processor.RestoredCount(), true, processingLatency
	}
	if tail != "" {
		w.Write([]byte(tail))
		flusher.Flush()
	}
	restored := processor.RestoredCount()
	if restored > 0 {
		metrics.Global.IncUnmaskedItems(int64(restored))
	}
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
type StreamProcessor struct {
	masker       *masker.Masker
	buf          strings.Builder // incomplete tail from previous chunk (önceki parçadan tamamlanmamış kuyruk)
	leakDetected bool            // set when a secret is found in stream output (akış çıktısında sır bulunduğunda set edilir)
	restored     int
}

// LeakDetected reports whether a secret pattern was found in the stream output.
// When true, the caller must terminate the stream immediately.
// (Akış çıktısında bir sır deseni bulunup bulunmadığını bildirir.
//
//	True olduğunda çağıranın akışı derhal sonlandırması gerekir.)
func (sp *StreamProcessor) LeakDetected() bool {
	return sp.leakDetected
}

// RestoredCount reports how many placeholders were restored so far.
func (sp *StreamProcessor) RestoredCount() int {
	return sp.restored
}

// NewStreamProcessor creates a processor for one streaming response lifetime.
// (Bir akış yanıtının ömrü için bir işlemci oluşturur.)
func NewStreamProcessor(m *masker.Masker) *StreamProcessor {
	return &StreamProcessor{masker: m}
}

// maxStreamBufBytes is the upper bound for the rolling buffer inside
// StreamProcessor. If the buffer grows beyond this (e.g. upstream drops
// mid-stream or an LLM emits a bare "[[" that never closes), we force-flush
// to prevent unbounded memory growth, accepting a small risk of a split label.
//
// (StreamProcessor içindeki sürekli arabellek için üst sınır.
// Arabellek bu değeri aşarsa (örn. upstream bağlantısı koparsa veya LLM
// kapanmayan bir "[["  üretirse), bellek birikimini önlemek amacıyla zorla
// temizleme yapılır; bu durumda bölünmüş etiket küçük bir risk oluşturur.)
const maxStreamBufBytes = 512 * 1024 // 512 KB

// Process appends chunk to the internal buffer, then flushes (temizler)
// everything up to the last safe cut-point.
//
// Returns the unmasked text that is safe to write to the client right now.
// May return an empty string if the entire buffer could be an incomplete label.
//
// (Parçayı iç arabelleğe ekler, ardından son güvenli kesim noktasına kadar
// her şeyi temizler.
// Şu anda istemciye yazmak için güvenli olan maskelenmemiş metni döner.
// Tüm arabellek tamamlanmamış bir etiket olabiliyorsa boş dize döndürebilir.)
func (sp *StreamProcessor) Process(chunk []byte) string {
	sp.buf.Write(chunk)

	// Tampon sınırı aşıldıysa, yarım etiket riski göze alınarak zorla temizle.
	if sp.buf.Len() > maxStreamBufBytes {
		content := sp.buf.String()
		sp.buf.Reset()
		// Fail-fast check on the raw content BEFORE unmasking.
		// Vault labels ([[PREFIX_HEX]]) never match secret patterns, so any hit here
		// is a genuine leak that was never routed through our masking pipeline.
		// (Maskeleme kaldırmadan ÖNCE ham içeriği kontrol et.
		//  Kasa etiketleri [[PREFIX_HEX]] asla sır desenlerine uymaz; dolayısıyla
		//  buradaki her eşleşme maskeleme hattımızdan hiç geçmemiş gerçek bir sızıntıdır.)
		if sp.masker.ContainsOriginal(content) || sp.masker.HasCredentialSecrets(content) {
			log.Printf("[stream][error] 🚨 secret detected in stream output — terminating")
			sp.leakDetected = true
			return ""
		}
		unmasked, restored := sp.masker.UnmaskWithCount(content)
		sp.restored += restored
		return unmasked
	}

	current := sp.buf.String()

	cutpoint := SafeCutpoint(current)
	if cutpoint == 0 {
		// Hold everything; wait for the next chunk to complete the label.
		// (Her şeyi tut; etiketi tamamlamak için bir sonraki parçayı bekle.)
		return ""
	}

	safe := current[:cutpoint]
	tail := current[cutpoint:]

	sp.buf.Reset()
	sp.buf.WriteString(tail)

	// Fail-fast: check the safe window BEFORE unmasking.
	// Vault labels like [[EMAIL_A4F0C8B2]] contain no @, sk-, ghp_ etc., so they
	// will never match — only raw leaked secrets are caught here.
	// (Güvenli pencereyi maskeleme kaldırmadan ÖNCE kontrol et.
	//  [[EMAIL_A4F0C8B2]] gibi kasa etiketleri @, sk-, ghp_ içermez,
	//  dolayısıyla eşleşmez — yalnızca ham sızdırılan sırlar burada yakalanır.)
	if sp.masker.ContainsOriginal(safe) || sp.masker.HasCredentialSecrets(safe) {
		log.Printf("[stream][error] 🚨 secret detected in stream output — terminating")
		sp.leakDetected = true
		return ""
	}

	// Unmask any complete labels in the safe window.
	// (Güvenli penceredeki tüm tam etiketlerin maskesini kaldır.)
	unmasked, restored := sp.masker.UnmaskWithCount(safe)
	sp.restored += restored
	return unmasked
}

// Flush drains the buffer unconditionally, unmasking whatever remains.
// Call this after the upstream body reaches EOF.
// (Arabelleği koşulsuz olarak boşaltır, kalanların maskesini kaldırır.
//
//	Yukarı yönlü gövde EOF'a ulaştıktan sonra çağırın.)
func (sp *StreamProcessor) Flush() string {
	remaining := sp.buf.String()
	sp.buf.Reset()
	if remaining == "" {
		return ""
	}
	// Fail-fast: check BEFORE unmasking — same rationale as Process().
	// (Maskeleme kaldırmadan ÖNCE kontrol et — Process() ile aynı gerekçe.)
	if sp.masker.ContainsOriginal(remaining) || sp.masker.HasCredentialSecrets(remaining) {
		log.Printf("[stream][error] 🚨 secret detected in stream tail — terminating")
		sp.leakDetected = true
		return ""
	}
	unmasked, restored := sp.masker.UnmaskWithCount(remaining)
	sp.restored += restored
	return unmasked
}

// ════════════════════════════════════════════════════════════════════════════
// safeCutpoint
// ════════════════════════════════════════════════════════════════════════════

// SafeCutpoint returns the index up to which text can be safely unmasked.
// Any text at or after this index might be the start of an incomplete label
// and must be held in the buffer.
//
// (Metnin güvenle maskelenebileceği indisi döner.
// Bu indis veya sonrasındaki metin, tamamlanmamış bir etiketin başlangıcı
// olabilir ve arabellekte tutulmalıdır.)
//
// Logic (mantık):
//   - Find the last "[[" that has no matching "]]" after it.
//   - Everything before that "[[" is safe.
//   - If all "[[" are closed by "]]", the whole text is safe.
//   - If the text contains no "[[" at all, the whole text is safe.
func SafeCutpoint(text string) int {
	lastOpen := strings.LastIndex(text, "[[")
	if lastOpen == -1 {
		// A network chunk can split the opening delimiter between its two
		// brackets. Retain a trailing single '[' until the next chunk arrives.
		if strings.HasSuffix(text, "[") {
			return len(text) - 1
		}
		// No label opening anywhere — the entire text is safe to flush.
		// (Hiçbir yerde etiket açılışı yok — metnin tamamını temizlemek güvenli.)
		return len(text)
	}

	// Is the last opening bracket closed?
	// (Son açılış köşeli parantezi kapatılmış mı?)
	afterOpen := text[lastOpen:]
	if strings.Contains(afterOpen, "]]") {
		if strings.HasSuffix(text, "[") {
			return len(text) - 1
		}
		// Label is complete; the whole text is safe.
		// (Etiket tamamlandı; metnin tamamı güvenli.)
		return len(text)
	}

	// The last "[[" has no matching "]]" yet.  Hold from that position.
	// (Son "[[" için henüz eşleşen "]]" yok. O konumdan itibaren tut.)
	return lastOpen
}
