// Local AI Firewall — main entry point (ana giriş noktası)
//
// Startup sequence (başlatma sırası):
//  1. Load Config from environment variables (çevre değişkenlerinden Config yükle)
//  2. Create the Vault (Vault oluştur)
//  3. Create the Masker, wiring it to the Vault (Masker oluştur, Vault'a bağla)
//  4. Create the proxy Server (proxy Sunucusu oluştur)
//  5. Register /health and /metrics endpoints
//  6. Listen for HTTP connections (HTTP bağlantıları dinle)
//  7. Block until SIGINT / SIGTERM, then shut down cleanly
//     (SIGINT / SIGTERM gelene kadar bekle, ardından temizce kapat)
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/localai/firewall/config"
	"github.com/localai/firewall/masker"
	"github.com/localai/firewall/metrics"
	"github.com/localai/firewall/proxy"
	"github.com/localai/firewall/vault"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	// ── 1. Configuration (Yapılandırma) ───────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("[fatal] config error (yapılandırma hatası): %v\n", err)
	}

	// ── 2. Vault (Kasa) ───────────────────────────────────────────────────────
	// The vault lives for the entire process lifetime.
	// (Vault, tüm süreç ömrü boyunca yaşar.)
	v := vault.New(cfg.VaultSizeLimit)

	// ── 3. Masker (Maskeleme Motoru) ──────────────────────────────────────────
	m := masker.New(v, cfg)

	// ── 4. Proxy Server + HTTP mux ────────────────────────────────────────────
	firewallSrv := proxy.NewServer(cfg, m)

	mux := http.NewServeMux()

	// /metrics — operational observability (işlevsel gözlemlenebilirlik)
	// Returns JSON with vault occupancy, mask counts, latency, etc.
	// (Vault doluluk oranı, maske sayıları ve gecikme içeren JSON döner.)
	// Restricted to localhost to prevent leaking internal state to AI providers.
	// (Yapay zeka sağlayıcılarına iç durumu sızdırmamak için yalnızca localhost'a kısıtlandı.)
	mux.HandleFunc("/metrics", localhostOnly(metrics.Global.Handler(v)))

	// All other paths go through the firewall pipeline.
	// (Diğer tüm yollar güvenlik duvarı boru hattından geçer.)
	mux.Handle("/", firewallSrv)

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.ListenPort),
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
			log.Fatalf("[fatal] server error (sunucu hatası): %v\n", err)
		}
	}()

	// ── 6. Graceful shutdown (Zarif Kapatma) ─────────────────────────────────
	// Block until the OS sends SIGINT (Ctrl-C) or SIGTERM (container stop).
	// (İşletim sistemi SIGINT (Ctrl-C) veya SIGTERM (container durdurma)
	//  gönderene kadar bekle.)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	log.Printf("[firewall][info] received signal (sinyal alındı): %s — shutting down…", sig)

	// ── Adım 1: Devam eden istekleri tamamla ─────────────────────────────────
	// httpServer.Shutdown() tüm aktif handler'lar bitene kadar bekler.
	// Bu, v.Reset() ile eş zamanlı Unmask() çağrıları arasındaki
	// yarış durumunu (race condition) ortadan kaldırır.
	//
	// (httpServer.Shutdown() waits for all active handlers to complete before
	//  returning. This eliminates the race between vault.Reset() and any
	//  concurrent Unmask() calls still running in in-flight requests.)
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutCancel()

	if err := httpServer.Shutdown(shutCtx); err != nil {
		log.Printf("[firewall][warn] graceful shutdown timed out (zarif kapatma zaman aşımı): %v", err)
	}

	// ── Adım 2: Vault artık boşta — silmek güvenli ───────────────────────────
	// (Step 2: Vault is now idle — safe to wipe sensitive data from memory.)
	v.Reset()
	finalStats := v.Stats()
	log.Printf("[firewall][info] vault cleared (vault temizlendi) — final stats (son istatistikler): %+v", finalStats)
	log.Printf("[firewall][info] metrics snapshot (metrik anlık görüntü): %+v", metrics.Global.Snapshot(nil))
	log.Println("[firewall][info] goodbye (görüşürüz).")
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
//  Internal state — vault occupancy, mask counts, etc. — should only
//  be visible to the local operator.)
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
				`{"error":"forbidden","message":"metrics endpoint is localhost-only (yalnızca localhost'tan erişilebilir)"}`,
				http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// printBanner displays the startup summary so operators can verify config at a glance.
// (Operatörlerin yapılandırmayı tek bakışta doğrulayabilmesi için başlatma özetini gösterir.)
func printBanner(cfg *config.Config) {
	hint := cfg.ProviderHint
	if hint == "" {
		hint = "auto-detect"
	}
	fmt.Printf(`
╔══════════════════════════════════════════════╗
║         🔥  Local AI Firewall                ║
╠══════════════════════════════════════════════╣
║  Listen   (dinleme portu) : :%d
║  Upstream (hedef sunucu)  : %s
║  Provider (sağlayıcı)     : %s
║  Mask paths (yollar)      : %v
║  Mask emails (e-postalar) : %v
║  Vault limit (kasa limiti): %d entries
║  Log level (log seviyesi) : %s
║  Metrics  (metrikler)     : http://localhost:%d/metrics
╚══════════════════════════════════════════════╝

`, cfg.ListenPort, cfg.UpstreamURL, hint,
		cfg.MaskPaths, cfg.MaskEmails, cfg.VaultSizeLimit, cfg.LogLevel, cfg.ListenPort)
}
