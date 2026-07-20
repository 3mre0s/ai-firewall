// Local AI Firewall — main entry point (ana giriş noktası)
//
// Startup sequence (başlatma sırası):
//  1. Dispatch CLI subcommands (install-ca, uninstall-ca, version, help) if present
//     (varsa CLI alt-komutlarını yönlendir)
//  2. Load Config from environment variables (çevre değişkenlerinden Config yükle)
//  3. Create the Vault (Vault oluştur)
//  4. Create the Masker, wiring it to the Vault (Masker oluştur, Vault'a bağla)
//  5. Create the proxy Server (proxy Sunucusu oluştur)
//  6. Register /health and /metrics endpoints
//  7. Listen for HTTP connections (HTTP bağlantıları dinle)
//  8. Block until SIGINT / SIGTERM, then shut down cleanly
//     (SIGINT / SIGTERM gelene kadar bekle, ardından temizce kapat)
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/3mre0s/ai-firewall/audit"
	"github.com/3mre0s/ai-firewall/config"
	"github.com/3mre0s/ai-firewall/masker"
	"github.com/3mre0s/ai-firewall/metrics"
	"github.com/3mre0s/ai-firewall/mitm"
	"github.com/3mre0s/ai-firewall/proxy"
	"github.com/3mre0s/ai-firewall/vault"
)

// version is set at build time via -ldflags "-X main.version=<tag>".
// Falls back to "dev" for local builds without ldflags.
// (Derleme sırasında -ldflags ile ayarlanır; ldflags kullanılmazsa "dev" değerini alır.)
var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	// ── Subcommand dispatch (alt-komut yönlendirmesi) ─────────────────────────
	// Must run before config.Load() so CLI commands never require FORWARD_API_KEY.
	// (config.Load()'dan önce çalışmalıdır; CLI komutları hiçbir zaman
	//  FORWARD_API_KEY gerektirmez.)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install-ca":
			os.Exit(runInstallCA())
		case "uninstall-ca":
			os.Exit(runUninstallCA())
		case "version":
			runVersion()
			os.Exit(0)
		case "demo":
			os.Exit(runDemo(os.Args[2:]))
		case "codex":
			os.Exit(runCodex(os.Args[2:]))
		case "help", "-h", "--help":
			runUsage()
			os.Exit(0)
		}
	}

	// ── 1. Configuration (Yapılandırma) ───────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("[fatal] config error: %v\n", err)
	}

	// ── 2. Vault (Kasa) ───────────────────────────────────────────────────────
	// The vault lives for the entire process lifetime.
	// (Vault, tüm süreç ömrü boyunca yaşar.)
	v := vault.New(cfg.VaultSizeLimit)

	// ── 3. Masker (Maskeleme Motoru) ──────────────────────────────────────────
	m := masker.New(v, cfg)
	traces := audit.NewStore(200)

	// ── 4. Proxy Server + HTTP mux ────────────────────────────────────────────
	firewallSrv := proxy.NewServer(cfg, m, traces)

	mux := http.NewServeMux()

	// /metrics — operational observability (işlevsel gözlemlenebilirlik)
	// Returns JSON with vault occupancy, mask counts, latency, etc.
	// (Vault doluluk oranı, maske sayıları ve gecikme içeren JSON döner.)
	// Restricted to localhost to prevent leaking internal state to AI providers.
	// (Yapay zeka sağlayıcılarına iç durumu sızdırmamak için yalnızca localhost'a kısıtlandı.)
	mux.HandleFunc("/metrics", localhostOnly(metrics.Global.Handler(v)))

	// /dashboard — visual metrics dashboard (görsel metrik gösterge paneli)
	// HTML interface for monitoring firewall stats in real-time.
	// (Gerçek zamanlı güvenlik duvarı istatistiklerini izlemek için HTML arayüz.)
	mux.HandleFunc("/dashboard", localhostOnly(metrics.Global.HTMLHandler(v)))
	mux.HandleFunc("/audit", localhostOnly(traces.Handler()))

	// All other paths go through the firewall pipeline.
	// (Diğer tüm yollar güvenlik duvarı boru hattından geçer.)
	mux.Handle("/", firewallSrv)

	httpServer := &http.Server{
		Addr:         loopbackAddr(cfg.ListenPort),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 6 * time.Minute, // must exceed longest AI response (en uzun AI yanıtını aşmalı)
		IdleTimeout:  60 * time.Second,
	}

	// ── 5. Start listening (Dinlemeye Başla) ──────────────────────────────────
	// Run in a goroutine (iş parçacığı) so main can block on the signal channel.
	// (Main, sinyal kanalında bloklayabilsin diye goroutine içinde çalıştır.)
	go func() {
		printBanner(cfg)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[fatal] server error: %v\n", err)
		}
	}()

	// ── MITM Proxy (optional, transparent mode) ───────────────────────────────
	// The MITM proxy runs on a separate port and intercepts TLS connections
	// to AI providers via HTTP CONNECT, enabling masking/unmasking without
	// requiring clients to explicitly configure an upstream URL.
	//
	// (MITM proxy'si, ayrı bir portta çalışır ve AI sağlayıcılarına yapılan
	//	TLS bağlantılarını HTTP CONNECT aracılığıyla yakalar, istemcilerin
	//	açıkça bir upstream URL yapılandırması gerektirmeden maskeleme/çözme
	//	işlemlerini sağlar.)
	var mitmServer *http.Server
	if cfg.MITMEnabled {
		ca, err := mitm.LoadOrCreateCA(
			filepath.Join(cfg.MITMCertDir, "ca.crt"),
			filepath.Join(cfg.MITMCertDir, "ca.key"),
		)
		if err != nil {
			log.Fatalf("[fatal] MITM CA error: %v\n", err)
		}

		mitmProxy := mitm.NewMITMProxy(ca, m, cfg)
		mitmServer = &http.Server{
			Addr:         loopbackAddr(cfg.MITMPort),
			Handler:      mitmProxy,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 6 * time.Minute,
			IdleTimeout:  60 * time.Second,
		}

		go func() {
			log.Printf("[firewall][info] MITM proxy listening on :%d", cfg.MITMPort)
			if err := mitmServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[fatal] MITM server error: %v\n", err)
			}
		}()
	}

	// ── 6. Graceful shutdown (Zarif Kapatma) ─────────────────────────────────
	// Block until the OS sends SIGINT (Ctrl-C) or SIGTERM (container stop).
	// (İşletim sistemi SIGINT (Ctrl-C) veya SIGTERM (container durdurma)
	//  gönderene kadar bekle.)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	log.Printf("[firewall][info] received signal: %s — shutting down…", sig)

	// ── Step 1: Complete in-flight requests (Devam eden istekleri tamamla) ──────
	// httpServer.Shutdown() waits for all active handlers to complete before
	// returning. This eliminates the race between vault.Reset() and any
	// concurrent Unmask() calls still running in in-flight requests.
	//
	// (httpServer.Shutdown() tüm aktif handler'lar bitene kadar bekler.
	//	Bu, v.Reset() ile eş zamanlı Unmask() çağrıları arasındaki
	//	yarış durumunu (race condition) ortadan kaldırır.)
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutCancel()

	if err := httpServer.Shutdown(shutCtx); err != nil {
		log.Printf("[firewall][warn] graceful shutdown timed out: %v", err)
	}

	// Shutdown MITM proxy server if it was running.
	// (MITM proxy sunucusunu kapat, çalışıyorsa.)
	if mitmServer != nil {
		if err := mitmServer.Shutdown(shutCtx); err != nil {
			log.Printf("[firewall][warn] MITM server graceful shutdown timed out: %v", err)
		}
	}

	// ── Adım 2: Vault artık boşta — silmek güvenli ───────────────────────────
	// (Step 2: Vault is now idle — safe to wipe sensitive data from memory.)
	v.Reset()
	finalStats := v.Stats()
	log.Printf("[firewall][info] vault cleared — final stats: %+v", finalStats)
	log.Printf("[firewall][info] metrics snapshot: %+v", metrics.Global.Snapshot(nil))
	log.Println("[firewall][info] goodbye.")
}

// loopbackAddr keeps both proxy surfaces local to this machine. The firewall
// has no client authentication or tenant isolation, so exposing either listener
// on a LAN would turn it into an unauthenticated gateway/open proxy.
func loopbackAddr(port int) string {
	return fmt.Sprintf("127.0.0.1:%d", port)
}

// localhostOnly is an HTTP middleware that restricts access to requests
// originating from the loopback interface (127.0.0.1 or ::1).
// All other callers receive 403 Forbidden.
//
// Kullanım amacı: /metrics endpoint'ini dış ağlardan ve yapay zeka
// sağlayıcılarından gizlemek. İç durum verileri (vault doluluk, maske sayısı
// vb.) yalnızca yerel operatörler tarafından görülmeli.
//
// (Purpose: hide /metrics from external networks and AI providers.
//
//	Internal state — vault occupancy, mask counts, etc. — should only
//	be visible to the local operator.)
func localhostOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// RemoteAddr biçimi: "IP:port" veya "[IPv6]:port"
		// (RemoteAddr format: "IP:port" or "[IPv6]:port")
		host := r.RemoteAddr
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
		host = strings.Trim(host, "[]")

		if host != "127.0.0.1" && host != "::1" {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w,
				`{"error":"forbidden","message":"local observability endpoints are localhost-only"}`,
				http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// ════════════════════════════════════════════════════════════════════════════
// CLI subcommand handlers (CLI alt-komut işleyicileri)
// ════════════════════════════════════════════════════════════════════════════

// caCertPaths resolves the CA certificate and key paths from environment
// variables, mirroring config.Load() logic but without requiring FORWARD_API_KEY.
// Respects MITM_CERT_DIR; falls back to ~/.ai-firewall.
//
// (FORWARD_API_KEY gerektirmeden config.Load() mantığını yansıtarak çevre
// değişkenlerinden CA sertifika ve anahtar yollarını çözer.
// MITM_CERT_DIR'ı dikkate alır; varsayılan ~/.ai-firewall'dır.)
func caCertPaths() (certPath, keyPath string) {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".ai-firewall")
	if v := os.Getenv("MITM_CERT_DIR"); v != "" {
		dir = v
	}
	return filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
}

// runInstallCA generates the CA if it does not exist yet, then installs it
// into the OS trust store. Idempotent: exits cleanly if already installed.
// Returns 0 on success, 1 on error.
//
// (CA henüz yoksa oluşturur, ardından işletim sistemi güven deposuna kurar.
// Idempotent: zaten kuruluysa temiz çıkış yapar. Başarıda 0, hatada 1 döner.)
func runInstallCA() int {
	certPath, keyPath := caCertPaths()

	// Generate the CA if the cert file does not exist yet.
	// LoadOrCreateCA is idempotent: loads from disk when files exist, creates otherwise.
	// (Sertifika dosyası henüz yoksa CA'yı oluştur.
	//  LoadOrCreateCA idempotent'tir: dosyalar varsa diskten yükler, yoksa oluşturur.)
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		fmt.Printf("CA certificate not found. Generating new CA at %s ...\n", certPath)
		if _, err := mitm.LoadOrCreateCA(certPath, keyPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error: could not generate CA: %v\n", err)
			return 1
		}
		fmt.Println("CA generated successfully.")
		fmt.Println()
	}

	// Idempotency: skip if already trusted.
	// (Idempotens: zaten güvenilirse atla.)
	if mitm.CheckInstalled() {
		fmt.Printf("✅  CA is already installed in the system trust store.\n"+
			"    Certificate: %s\n", certPath)
		return 0
	}

	if err := mitm.InstallCA(certPath); err != nil {
		fmt.Fprintf(os.Stderr, "\n%v\n", err)
		return 1
	}

	fmt.Printf("\n✅  CA certificate installed successfully.\n"+
		"    Certificate: %s\n", certPath)
	return 0
}

// runUninstallCA removes the AI Firewall CA from the OS trust store.
// Returns 0 on success (or if it was not installed), 1 on error.
//
// (AI Firewall CA'sını işletim sistemi güven deposundan kaldırır.
// Başarıda (veya kurulu değilse) 0, hatada 1 döner.)
func runUninstallCA() int {
	certPath, _ := caCertPaths()

	if !mitm.CheckInstalled() {
		fmt.Println("CA is not currently installed in the system trust store. Nothing to do.")
		return 0
	}

	if err := mitm.UninstallCA(certPath); err != nil {
		fmt.Fprintf(os.Stderr, "\n%v\n", err)
		return 1
	}

	fmt.Printf("\n✅  CA certificate removed from the system trust store.\n"+
		"    Certificate: %s\n", certPath)
	return 0
}

// runVersion prints the build version injected via -ldflags.
// (ldflags ile enjekte edilen derleme sürümünü yazdırır.)
func runVersion() {
	fmt.Printf("anonmyz %s (ai-firewall compatible)\n", version)
}

// runUsage prints a short command reference. Shown only for "help"/"-h"/"--help";
// running without arguments still starts the server.
//
// (Kısa komut referansını yazdırır. Yalnızca "help"/"-h"/"--help" için gösterilir;
//
//	argümansız çalıştırma sunucuyu başlatmaya devam eder.)
func runUsage() {
	fmt.Print(`Anonmyz — local-first AI security and DLP gateway

Usage:
  anonmyz                    Start the proxy server (reads config from env vars).
  anonmyz demo [--non-interactive]
                             Run the deterministic, key-free security proof.
  anonmyz codex [options] -- [codex args]
                             Launch a protected Codex API-key session.
  anonmyz install-ca         Install the MITM CA certificate into the system trust store.
  anonmyz uninstall-ca       Remove the MITM CA certificate from the system trust store.
  anonmyz version            Print the build version.
  anonmyz help               Show this help message.

The legacy ai-firewall binary name remains fully compatible.

Key environment variables (server mode):
  FORWARD_API_KEY   Real API key forwarded to the upstream provider (required).
  UPSTREAM_URL      Base URL of the upstream AI provider (default: https://api.anthropic.com).
  FIREWALL_PORT     TCP port for the API proxy (default: 8080).
  MITM_ENABLED      Enable transparent MITM proxy mode (default: false).
  MITM_CERT_DIR     CA cert/key storage directory (default: ~/.ai-firewall).

See README.md for full configuration reference.
`)
}

// printBanner displays the startup summary so operators can verify config at a glance.
// (Operatörlerin yapılandırmayı tek bakışta doğrulayabilmesi için başlatma özetini gösterir.)
func printBanner(cfg *config.Config) {
	hint := cfg.ProviderHint
	if hint == "" {
		hint = "auto-detect"
	}

	// Build banner with or without MITM info.
	// (MITM bilgisi ile veya olmadan banner oluştur.)
	var mitmLines string
	if cfg.MITMEnabled {
		mitmLines = fmt.Sprintf("║  MITM Proxy                : :%d\n║  MITM CA Cert              : ~/.ai-firewall/ca.crt\n", cfg.MITMPort)
	}

	banner := fmt.Sprintf(`
╔══════════════════════════════════════════════╗
║         🛡️  Anonmyz AI Gateway              ║
╠══════════════════════════════════════════════╣
║  Listen                    : :%d
║  Upstream                  : %s
║  Provider                  : %s
║  Mask paths                : %v
║  Mask emails               : %v
║  Vault limit               : %d entries
║  Log level                 : %s
║  Metrics                   : http://localhost:%d/metrics
║  Dashboard                 : http://localhost:%d/dashboard
%s╚══════════════════════════════════════════════╝
`,
		cfg.ListenPort, cfg.UpstreamURL, hint,
		cfg.MaskPaths, cfg.MaskEmails, cfg.VaultSizeLimit, cfg.LogLevel, cfg.ListenPort, cfg.ListenPort, mitmLines)
	fmt.Print(banner)
}
