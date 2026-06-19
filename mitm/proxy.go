// Package mitm implements a transparent Man-in-the-Middle proxy that intercepts
// TLS connections to known AI providers, enabling the firewall to mask/unmask
// sensitive data in transit.
//
// (Bilinen AI sağlayıcılarına yapılan TLS bağlantılarını yakalayan şeffaf bir
//	Ortadaki Adam (MITM) proxy'si uygular. Güvenlik duvarının aktarım sırasında
//	hassas verileri maskelemesini/maskesini kaldırmasını sağlar.)
package mitm

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/3mre0s/ai_firewall/config"
	"github.com/3mre0s/ai_firewall/masker"
	"github.com/3mre0s/ai_firewall/proxy"
)

// ════════════════════════════════════════════════════════════════════════════
// limitedReadCloser wraps an io.Reader with a Close method to satisfy io.ReadCloser.
// (limitedReadCloser, io.ReadCloser arayüzünü karşılamak için Close yöntemiyle io.Reader'ı sarar.)
type limitedReadCloser struct {
	io.Reader
	close func() error
}

func (l *limitedReadCloser) Close() error {
	if l.close != nil {
		return l.close()
	}
	return nil
}

// ════════════════════════════════════════════════════════════════════════════
// MITMProxy — Transparent MITM Proxy Handler
// ════════════════════════════════════════════════════════════════════════════

// MITMProxy handles HTTP CONNECT requests to intercept TLS traffic to AI providers.
// For AI hosts, it performs TLS termination with dynamically generated leaf certs,
// masks sensitive data, forwards to the real API, and unmasks responses.
// For non-AI hosts, it creates a blind TCP tunnel (no TLS interception).
//
// (HTTP CONNECT isteklerini işleyerek AI sağlayıcılarına yapılan TLS trafiğini
//	yakalar. AI ana bilgisayarları için dinamik olarak oluşturulan yaprak sertifikalar
//	ile TLS sonlandırması yapar, hassas verileri maskele, gerçe API'ye iletir ve
//	yanıtların maskelerini kaldırır. AI olmayan ana bilgisayarlar için kör TCP
//	tüneli oluşturur (TLS müdahalesi olmaz).)
type MITMProxy struct {
	ca    *CA
	masker *masker.Masker
	cfg   *config.Config

	// aiHosts maps hostnames to their provider patterns for interception.
	// If a CONNECT request targets a host in this map, TLS is intercepted.
	// Otherwise, a blind TCP tunnel is created.
	// (aiHosts, müdahale için ana bilgisayar adlarını sağlayıcı desenlerine eşler.
	//	Eğer bir CONNECT isteği bu haritada yer alan bir ana bilgisayara yönelikse,
	//	TLS yakalanır. Aksi halde kör TCP tüneli oluşturulur.)
	aiHosts map[string]bool

	// httpClient is a shared HTTP client for forwarding requests to AI APIs.
	// (Paylaşılan HTTP istemcisi, AI API'lerine istek iletmek için kullanılır.)
	httpClient *http.Client
}

// NewMITMProxy creates a new MITM proxy handler.
// (Yeni bir MITM proxy işleyicisi oluşturur.)
func NewMITMProxy(ca *CA, m *masker.Masker, cfg *config.Config) *MITMProxy {
	// Build the AI host detection map from provider patterns.
	// (Sağlayıcı desenlerinden AI ana bilgisayarı tespit haritasını oluştur.)
	aiHosts := buildAIHostsMap()

	return &MITMProxy{
		ca:    ca,
		masker: m,
		cfg:   cfg,
		aiHosts: aiHosts,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
			Transport: &http.Transport{
				TLSHandshakeTimeout: 10 * time.Second,
				// Explicitly require TLS 1.2+ and full certificate verification for all
				// upstream AI API connections.  InsecureSkipVerify MUST remain false.
				// (Tüm upstream AI API bağlantıları için açıkça TLS 1.2+ ve tam sertifika
				//  doğrulaması gerektirir. InsecureSkipVerify kesinlikle false kalmalıdır.)
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}
}

// buildAIHostsMap creates a map of known AI provider hostnames for interception.
// Extracted from providers' Matches() patterns.
// (Bilinen AI sağlayıcı ana bilgisayar adlarını müdahale için haritalar.
//	Sağlayıcıların Matches() desenlerinden çıkarılır.)
func buildAIHostsMap() map[string]bool {
	return map[string]bool{
		// Anthropic
		"api.anthropic.com": true,
		// OpenAI
		"api.openai.com": true,
		// Google
		"generativelanguage.googleapis.com": true,
		"aiplatform.googleapis.com":       true,
		// Groq
		"api.groq.com": true,
		// Together AI
		"api.together.xyz": true,
		"api.together.ai":  true,
		// Perplexity
		"api.perplexity.ai": true,
		// Mistral
		"api.mistral.ai": true,
		// Cohere
		"api.cohere.com": true,
		"api.cohere.ai":  true,
		// DeepSeek
		"api.deepseek.com": true,
		// xAI (Grok)
		"api.x.ai": true,
		// Azure OpenAI (all *.openai.azure.com)
		"openai.azure.com": true,
		// Local providers
		"localhost:11434": true, // Ollama default
		"127.0.0.1:11434": true,
		"localhost:1234":  true, // LM Studio default
		"127.0.0.1:1234":  true,
	}
}

// isAIHost checks if the given host:port (as received in the CONNECT request)
// should be intercepted for masking.  Matching is exact — no substring checks —
// to prevent hostile hostnames like "evil-ollama.attacker.com" from being intercepted.
//
// (CONNECT isteğinde alınan host:port'un maskeleme için yakalanıp yakalanmayacağını
//	kontrol eder. Eşleştirme kesindir — alt dize kontrolü yoktur — "evil-ollama.attacker.com"
//	gibi düşmanca hostname'lerin yakalanmasını önlemek için.)
func (p *MITMProxy) isAIHost(hostport string) bool {
	// Exact match on the full host:port string.
	// This covers local providers registered with port (e.g. localhost:11434).
	// (Tam host:port eşleşmesi. Port içeren yerel sağlayıcıları kapsar.)
	if p.aiHosts[hostport] {
		return true
	}

	// Strip port to get the bare hostname for remote-provider and Azure matching.
	// (Uzak sağlayıcı ve Azure eşleşmesi için port'u ayır.)
	hostname := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		hostname = h
	}

	// Exact match on bare hostname (covers remote providers like api.anthropic.com).
	// (Tam hostname eşleşmesi — uzak sağlayıcıları kapsar.)
	if p.aiHosts[hostname] {
		return true
	}

	// Azure OpenAI: match only *.openai.azure.com using a true suffix check.
	// "openai.azure.com.evil.com" does NOT end in ".openai.azure.com".
	// (Azure OpenAI: gerçek sonek kontrolüyle yalnızca *.openai.azure.com'u eşleştir.
	//	"openai.azure.com.evil.com" ".openai.azure.com" ile bitmez.)
	if strings.HasSuffix(hostname, ".openai.azure.com") {
		return true
	}

	return false
}

// ════════════════════════════════════════════════════════════════════════════
// ServeHTTP — Main Entry Point
// ════════════════════════════════════════════════════════════════════════════

// ServeHTTP handles incoming requests. Only CONNECT method is supported for
// establishing TLS tunnels. All other requests receive a 405 Method Not Allowed.
//
// (Gelen istekleri işler. Yalnızca CONNECT yöntemi, TLS tünelleri kurmak için
//	desteklenir. Diğer tüm istekler 405 Yöntem Izin Verilmiyor yanıtı alır.)
func (p *MITMProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract host and port from CONNECT request.
	// CONNECT requests use the format: CONNECT host:port
	// (CONNECT isteğinden ana bilgisayar ve portu çıkar.)
	hostport := r.Host

	// Strip port to get the bare hostname for TLS cert generation and URL construction.
	// (TLS sertifika üretimi ve URL oluşturma için port'u ayır.)
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}

	// Check if this is an AI host we should intercept.
	// Pass the original host:port so that exact local-provider entries (e.g. localhost:11434)
	// are matched without any substring checks.
	// (Müdahale etmemiz gereken bir AI ana bilgisayarı mı?
	//	Tam yerel sağlayıcı girişlerini herhangi bir alt dize kontrolü olmadan eşleştirebilmek
	//	için orijinal host:port'u iletir.)
	if !p.isAIHost(hostport) {
		// Non-AI traffic: create a blind TCP tunnel.
		// (AI olmayan trafik: kör TCP tüneli oluştur.)
		p.handleBlindTunnel(w, r, host)
		return
	}

	// AI host: intercept TLS, mask/unmask data.
	// (AI ana bilgisayarı: TLS'yi yakala, verileri maskele/çöz.)
	p.handleMITMTunnel(w, r, host)
}

// ════════════════════════════════════════════════════════════════════════════
// Blind TCP Tunnel (Kör TCP Tüneli)
// ════════════════════════════════════════════════════════════════════════════

// handleBlindTunnel creates a raw TCP tunnel for non-AI traffic.
// No TLS interception is performed; data is relayed byte-for-byte.
//
// (AI olmayan trafik için ham TCP tüneli oluşturur.
//	TLS müdahalesi yapılmaz; veriler bayt bayt iletilir.)
func (p *MITMProxy) handleBlindTunnel(w http.ResponseWriter, r *http.Request, host string) {
	// Send 200 Connection Established to client.
	// (İstemciye 200 Bağlantı Kuruldu yanıtı gönder.)
	w.WriteHeader(http.StatusOK)

	// Hijack the client connection to get raw TCP access.
	// (İstemci bağlantısını ele geçirerek ham TCP erişimi elde et.)
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		log.Printf("[mitm][error] hijack failed: %v", err)
		return
	}
	defer clientConn.Close()

	// Connect to the target host.
	// (Hedef ana bilgisayarına bağlan.)
	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		log.Printf("[mitm][error] dial target failed: %v", err)
		return
	}
	defer targetConn.Close()

	// Send 200 Connection Established after successful dial.
	// (Başarılı bağlanmadan sonra 200 Bağlantı Kuruldu gönder.)
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Printf("[mitm][error] write connection established failed: %v", err)
		return
	}

	// Start bidirectional copying.
	// (Çift yönlü kopyalamayı başlat.)
	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
}

// ════════════════════════════════════════════════════════════════════════════
// MITM Tunnel with TLS Interception (TLS Müdahalesi ile MITM Tüneli)
// ════════════════════════════════════════════════════════════════════════════

// handleMITMTunnel handles TLS interception for AI hosts.
// It performs the MITM handshake, decrypts the HTTP request, masks sensitive data,
// forwards to the real API, and unmasks the response.
//
// (AI ana bilgisayarları için TLS müdahalesini işler.
//	MITM el sıkışmasını yapar, HTTP isteğini şifresini çözer, hassas verileri maskele,
//	gerçek API'ye iletir ve yanıtın maskesini kaldırır.)
func (p *MITMProxy) handleMITMTunnel(w http.ResponseWriter, r *http.Request, host string) {
	// Send 200 Connection Established to client.
	// (İstemciye 200 Bağlantı Kuruldu yanıtı gönder.)
	w.WriteHeader(http.StatusOK)

	// Hijack the client connection.
	// (İstemci bağlantısını ele geçir.)
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		log.Printf("[mitm][error] hijack failed: %v", err)
		return
	}
	defer clientConn.Close()

	// Get or generate a leaf certificate for the target host.
	// (Hedef ana bilgisayar için bir yaprak sertifika al veya oluştur.)
	leafCert, err := p.ca.LeafCert(host)
	if err != nil {
		log.Printf("[mitm][error] leaf cert generation failed: %v", err)
		return
	}

	// Create TLS config for the client-side connection.
	// (İstemci tarafı bağlantısı için TLS yapılandırması oluştur.)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
		// We don't verify the client's certificate (this is a proxy, not a server).
		// (İstemcinin sertifikasını doğrulamıyoruz (bu bir proxy, sunucu değil).)
		ClientAuth: tls.NoClientCert,
	}

	// Wrap the client connection with TLS.
	// (İstemci bağlantısını TLS ile sar.)
	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	// Set timeout for TLS handshake.
	// (TLS el sıkışması için zaman aşımı ayarla.)
	if err := tlsConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Printf("[mitm][error] set deadline failed: %v", err)
		return
	}

	// Perform TLS handshake with the client.
	// (İstemci ile TLS el sıkışması yap.)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[mitm][error] TLS handshake with client failed: %v", err)
		return
	}

	// Reset deadline for normal operation.
	// (Normal işlem için zaman aşımını sıfırla.)
	tlsConn.SetDeadline(time.Time{})

	log.Printf("[mitm][info] TLS handshake complete with client for %s", host)

	// Read the decrypted HTTP request from the client.
	// (İstemciden şifresi çözülmüş HTTP isteğini oku.)
	req, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		log.Printf("[mitm][error] read HTTP request failed: %v", err)
		return
	}

	// Limit request body size to 32 MB.
	// Since we can't return a 413 error easily through the TLS connection,
	// we use io.LimitReader and handle size errors manually.
	// (İstek gövdesi boyutunu 32 MB ile sınırla.
	//	TLS bağlantısı üzerinden kolayca 413 hatası döndüremediğimiz için,
	//	io.LimitReader kullanıyor ve boyut hatalarını elle işliyoruz.)
	req.Body = &limitedReadCloser{
		Reader: io.LimitReader(req.Body, 32<<20),
		close:  req.Body.Close,
	}

	// Read the full request body.
	// (Tüm istek gövdesini oku.)
	body, err := io.ReadAll(req.Body)
	if err != nil {
		// Check if error is due to body size limit.
		// (Hatanın gövde boyut sınırından kaynaklanıp kaynaklanmadığını kontrol et.)
		if err.Error() == "http: request body too large" {
			log.Printf("[mitm][error] request body too large")
			// Send 413 error response.
			// (413 hata yanıtı gönder.)
			response := "HTTP/1.1 413 Request Entity Too Large\r\n"
			response += "Content-Type: text/plain\r\n"
			response += "Connection: close\r\n\r\n"
			response += "request body too large"
			if _, err := tlsConn.Write([]byte(response)); err != nil {
				log.Printf("[mitm][error] write 413 response failed: %v", err)
			}
			return
		}
		log.Printf("[mitm][error] read request body failed: %v", err)
		return
	}
	defer req.Body.Close()

	log.Printf("[mitm][info] → %s %s", req.Method, req.URL.Path)

	// ── Step 1: Mask sensitive data in the request body ─────────────────────
	// (Adım 1: İstek gövdesindeki hassas verileri maskele)
	maskResult := p.masker.Mask(string(body))

	if maskResult.MaskedCount > 0 {
		log.Printf("[mitm][info] 🛡 masked %d item(s)", maskResult.MaskedCount)
	}

	// Vault-full guard: if any sensitive value could not be masked because the
	// vault was at capacity, we block the request.
	// (Kasa dolu koruması: kasa kapasitesi dolduğu için maskelenememiş hassas
	//	bir değer varsa isteği engelle.)
	if maskResult.VaultEvictions > 0 {
		log.Printf("[mitm][error] 🚨 vault full — %d secret(s) could not be masked, request blocked",
			maskResult.VaultEvictions)
		// Send error response back to client.
		// (İstemciye hata yanıtı gönder.)
		resp := &http.Response{
			StatusCode: http.StatusInsufficientStorage,
			Status:     "507 Insufficient Storage",
			Body:       io.NopCloser(bytes.NewBufferString(`{"error":"firewall_vault_full","message":"Vault capacity exceeded. Request blocked to prevent data leak."}`)),
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "application/json")
		resp.Write(tlsConn)
		return
	}

	// ── Step 2: Forward masked request to the real AI API ────────────────
	// (Adım 2: Maskelelenmiş isteği gerçek AI API'sine ilet)
	// Build the upstream URL.
	// (Upstream URL'sini oluştur.)
	upstreamURL := fmt.Sprintf("https://%s%s", host, req.URL.Path)
	if req.URL.RawQuery != "" {
		upstreamURL += "?" + req.URL.RawQuery
	}

	// Create a new request to the upstream.
	// (Upstream'e yeni bir istek oluştur.)
	upstreamReq, err := http.NewRequestWithContext(req.Context(), req.Method, upstreamURL, bytes.NewBufferString(maskResult.Text))
	if err != nil {
		log.Printf("[mitm][error] create upstream request failed: %v", err)
		return
	}

	// Copy headers from the client request.
	// Passthrough mode: client's own auth headers flow through unchanged.
	// (İstemci isteğinden başlıkları kopyala.
	//	Geçiş modu: istemcinin kendi kimlik doğrulama başlıkları değiştirilmeden iletilir.)
	for key, values := range req.Header {
		for _, value := range values {
			upstreamReq.Header.Add(key, value)
		}
	}

	// Remove hop-by-hop headers that shouldn't be forwarded.
	// (İletilmemesi gereken atlama-başına (hop-by-hop) başlıklarını kaldır.)
	upstreamReq.Header.Del("Connection")
	upstreamReq.Header.Del("Keep-Alive")
	upstreamReq.Header.Del("Proxy-Authenticate")
	upstreamReq.Header.Del("Proxy-Authorization")
	upstreamReq.Header.Del("TE")
	upstreamReq.Header.Del("Trailers")
	upstreamReq.Header.Del("Transfer-Encoding")
	upstreamReq.Header.Del("Upgrade")

	// Forward the request to the real API.
	// (İsteği gerçek API'ye ilet.)
	resp, err := p.httpClient.Do(upstreamReq)
	if err != nil {
		log.Printf("[mitm][error] upstream request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Printf("[mitm][info] ← upstream %d", resp.StatusCode)

	// ── Step 3: Unmask and deliver the response ───────────────────────────
	// (Adım 3: Yanıtın maskesini kaldır ve ilet)

	// Check if this is a streaming response (SSE).
	// (Bu bir akış yanıtı mı (SSE)?)
	isStream := false
	if contentType := resp.Header.Get("Content-Type"); strings.Contains(contentType, "text/event-stream") {
		isStream = true
	}

	// Unmasking changes body length (placeholders are swapped for real secret
	// values of different size), so the upstream's Content-Length no longer
	// describes what we actually send. For standard responses we buffer the
	// unmasked body and compute a correct Content-Length. For streaming
	// responses the final length is unknowable up front, so we re-frame the
	// body with our own "Transfer-Encoding: chunked" instead of forwarding
	// whatever framing the upstream used.
	//
	// (Maskeleme kaldırma, gövde uzunluğunu değiştirir (yer tutucular, farklı
	//  boyuttaki gerçek sır değerleriyle değiştirilir), bu yüzden upstream'in
	//  Content-Length'i artık gönderdiğimiz şeyi tanımlamaz. Standart yanıtlar
	//  için maskesi kaldırılmış gövdeyi arabelleğe alıp doğru bir Content-Length
	//  hesaplıyoruz. Akış yanıtları için son uzunluk önceden bilinemediğinden,
	//  gövdeyi upstream'in kullandığı çerçeveleme yerine kendi
	//  "Transfer-Encoding: chunked" çerçevelememizle yeniden çerçeveliyoruz.)
	var standardBody []byte
	if !isStream {
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[mitm][error] read response body failed: %v", err)
			return
		}
		standardBody = []byte(p.masker.Unmask(string(raw)))
	}

	// Write response status line.
	// (Yanıt durum satırını yaz.)
	text := fmt.Sprintf("HTTP/1.1 %03d %s\r\n", resp.StatusCode, resp.Status)
	if _, err := tlsConn.Write([]byte(text)); err != nil {
		log.Printf("[mitm][error] write status line failed: %v", err)
		return
	}

	// Copy response headers to the client, skipping hop-by-hop headers and
	// any framing headers (Content-Length/Transfer-Encoding) — those are
	// recomputed below to match what we actually send.
	// (Yanıt başlıklarını istemciye kopyala; atlama-başına başlıkları ve
	//  herhangi bir çerçeveleme başlığını (Content-Length/Transfer-Encoding)
	//  atla — bunlar, gerçekten gönderdiğimiz şeyle eşleşmesi için aşağıda
	//  yeniden hesaplanır.)
	for key, values := range resp.Header {
		switch key {
		case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailers", "Transfer-Encoding", "Upgrade", "Content-Length":
			continue
		}
		for _, value := range values {
			_, err := fmt.Fprintf(tlsConn, "%s: %s\r\n", key, value)
			if err != nil {
				log.Printf("[mitm][error] write header failed: %v", err)
				return
			}
		}
	}

	if isStream {
		if _, err := tlsConn.Write([]byte("Transfer-Encoding: chunked\r\n")); err != nil {
			log.Printf("[mitm][error] write transfer-encoding header failed: %v", err)
			return
		}
	} else {
		if _, err := fmt.Fprintf(tlsConn, "Content-Length: %d\r\n", len(standardBody)); err != nil {
			log.Printf("[mitm][error] write content-length header failed: %v", err)
			return
		}
	}

	// End of headers.
	// (Başlıkların sonu.)
	if _, err := tlsConn.Write([]byte("\r\n")); err != nil {
		log.Printf("[mitm][error] write header separator failed: %v", err)
		return
	}

	if isStream {
		// Handle streaming response with chunk-by-chunk unmasking.
		// (Akış yanıtını parça parça maskeleme kaldırma ile işle.)
		p.handleStreamResponse(tlsConn, resp.Body)
	} else {
		if _, err := tlsConn.Write(standardBody); err != nil {
			log.Printf("[mitm][error] write unmasked response failed: %v", err)
		}
	}
}

// handleStreamResponse processes SSE response chunk-by-chunk with unmasking.
// It terminates the stream immediately if a secret pattern is detected in the output.
//
// KNOWN LIMITATION — partial-chunk delivery on fail-fast:
// Fail-fast stops all chunks that arrive AFTER the secret is detected.  The
// offending chunk itself is suppressed (dropped, never written to the TLS
// connection).  Chunks already written to the connection before the detection
// point cannot be recalled — this is a fundamental HTTP/TLS streaming constraint.
// The client receives an abrupt connection close rather than a complete response.
//
// (BİLİNEN SINIR — fail-fast sırasında kısmi-chunk iletimi:
//
//	Fail-fast, sır tespit edildikten SONRA gelen tüm chunk'ları durdurur.
//	Sorunlu chunk'ın kendisi bastırılır (TLS bağlantısına hiç yazılmaz).
//	Tespit noktasından önce bağlantıya yazılmış chunk'lar geri alınamaz —
//	bu temel bir HTTP/TLS streaming kısıtıdır. İstemci eksiksiz bir yanıt
//	yerine beklenmedik bir bağlantı kapanması alır.)
func (p *MITMProxy) handleStreamResponse(conn *tls.Conn, body io.Reader) {
	// Reuse the StreamProcessor from proxy package.
	// (proxy paketinden StreamProcessor'u yeniden kullan.)
	processor := proxy.NewStreamProcessor(p.masker)
	buf := make([]byte, 4096)

	for {
		n, err := body.Read(buf)
		if n > 0 {
			out := processor.Process(buf[:n])
			// Fail-fast: secret in stream output — close connection immediately.
			// (Hızlı başarısızlık: akış çıktısında sır — bağlantıyı derhal kapat.)
			if processor.LeakDetected() {
				log.Printf("[mitm][error] 🚨 secret detected in stream — terminating connection")
				return
			}
			if out != "" {
				if err := writeChunk(conn, []byte(out)); err != nil {
					log.Printf("[mitm][error] write stream chunk failed: %v", err)
					return
				}
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[mitm][error] stream read error: %v", err)
			}
			break
		}
	}

	// Flush any remaining buffered content.
	// (Kalan arabelleğe alınmış içeriği temizle.)
	tail := processor.Flush()
	if processor.LeakDetected() {
		log.Printf("[mitm][error] 🚨 secret in stream tail — terminating")
		return
	}
	if tail != "" {
		if err := writeChunk(conn, []byte(tail)); err != nil {
			log.Printf("[mitm][error] write final stream chunk failed: %v", err)
			return
		}
	}

	// Terminating chunk — signals end of body under chunked transfer encoding.
	// (Sonlandırma chunk'ı — chunked transfer encoding altında gövdenin sonunu bildirir.)
	if _, err := conn.Write([]byte("0\r\n\r\n")); err != nil {
		log.Printf("[mitm][error] write final chunk terminator failed: %v", err)
	}
}

// writeChunk writes data as a single HTTP/1.1 chunked-transfer-encoding chunk:
// the size in hex, CRLF, the data itself, then a trailing CRLF.
// (Veriyi tek bir HTTP/1.1 chunked-transfer-encoding parçası olarak yazar:
//  onaltılık boyut, CRLF, verinin kendisi, ardından sonda CRLF.)
func writeChunk(conn *tls.Conn, data []byte) error {
	if _, err := fmt.Fprintf(conn, "%x\r\n", len(data)); err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}
	_, err := conn.Write([]byte("\r\n"))
	return err
}
