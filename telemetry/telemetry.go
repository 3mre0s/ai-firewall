// Package telemetry sends a single anonymous "startup" ping per process run,
// but only if the operator has explicitly opted in via ANALYTICS_OPT_IN=true.
//
// What is sent (when enabled): a random, non-identifying installation ID,
// the build version, OS, and architecture.
//
// What is NEVER sent: prompt content, secrets, file paths, environment
// variables, IP-derived geolocation, or anything captured by the firewall's
// masking pipeline. Telemetry and the firewall pipeline are fully isolated —
// this package has no import of masker, vault, or proxy.
//
// Telemetry is opt-in, not opt-out: if ANALYTICS_OPT_IN is unset or false,
// this package performs no network activity at all.
//
// (telemetry paketi süreç başına tek bir anonim "startup" sinyali gönderir,
//
//	ama yalnızca operatör ANALYTICS_OPT_IN=true ile açıkça izin verdiyse.
//	Gönderilenler: rastgele bir kurulum kimliği, sürüm, işletim sistemi,
//	mimari. ASLA gönderilmeyenler: prompt içeriği, secret, dosya yolu, ortam
//	değişkenleri veya maskeleme hattının yakaladığı herhangi bir şey.)
package telemetry

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	idFileName  = "telemetry_id"
	sendTimeout = 3 * time.Second
)

// Config controls whether and where the anonymous ping is sent.
// Built from config.Config — see config.AnalyticsOptIn / AnalyticsEndpoint /
// AnalyticsAPIKey / AnalyticsDataDir for field meanings.
type Config struct {
	Enabled  bool
	Endpoint string
	APIKey   string
	DataDir  string
}

// Logf is the minimal logging hook telemetry needs. Pass log.Printf, or nil
// to silence telemetry's own diagnostic lines entirely.
type Logf func(format string, args ...any)

// SendStartupEvent fires one "ai_firewall_startup" event in the background
// if cfg.Enabled is true. It never blocks the caller, never panics, and
// never affects the firewall's primary request pipeline — all failures
// (missing API key, network error, disk error) are swallowed and only
// surfaced via the optional logf hook.
//
// (cfg.Enabled true ise arka planda tek bir "ai_firewall_startup" olayı
//
//	gönderir. Çağıranı asla bloklamaz, panic atmaz ve güvenlik duvarının
//	ana istek hattını asla etkilemez — tüm hatalar yutulur, yalnızca
//	isteğe bağlı logf kancası üzerinden görünür kılınır.)
func SendStartupEvent(cfg Config, version string, logf Logf) {
	if !cfg.Enabled {
		return
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if cfg.Endpoint == "" {
		logf("[telemetry] enabled but no endpoint configured — skipping")
		return
	}
	// Key is compiled in by CI; if missing, the binary was built locally
	// without the secret and telemetry cannot be attributed to a project.
	if cfg.APIKey == "" {
		logf("[telemetry] enabled but no API key compiled in — skipping")
		return
	}

	// Fire-and-forget: a slow or unreachable analytics endpoint must never
	// delay startup or hold the process open.
	// (Yavaş veya erişilemez bir analiz uç noktası asla başlatmayı geciktirmemeli
	//  veya süreci açık tutmamalıdır.)
	go func() {
		id, err := loadOrCreateAnonID(cfg.DataDir)
		if err != nil {
			logf("[telemetry] could not persist anonymous id (non-fatal): %v", err)
			return
		}

		payload := buildPayload(cfg.APIKey, id, version)
		if err := post(cfg.Endpoint, payload); err != nil {
			logf("[telemetry] send failed (non-fatal, firewall unaffected): %v", err)
		}
	}()
}

// loadOrCreateAnonID returns a persisted random identifier with no relation
// to any user, machine, or network identity. Reused across runs so that
// repeat starts of the same install aren't double-counted as new installs.
//
// (Herhangi bir kullanıcı, makine veya ağ kimliğiyle ilişkisi olmayan,
//
//	kalıcı rastgele bir kimlik döner. Aynı kurulumun tekrar başlatılması
//	yeni kurulum olarak sayılmasın diye çalıştırmalar arasında yeniden kullanılır.)
func loadOrCreateAnonID(dir string) (string, error) {
	if dir == "" {
		dir = "."
	}
	path := filepath.Join(dir, idFileName)

	if b, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id, nil
		}
	}

	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	id := hex.EncodeToString(buf)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(id), 0o600); err != nil {
		return "", err
	}
	return id, nil
}

// posthogEvent is the JSON shape expected by PostHog-compatible /capture/
// endpoints. Kept private and minimal — only the fields telemetry actually
// uses, so no accidental extra data can be added later without review.
type posthogEvent struct {
	APIKey     string         `json:"api_key,omitempty"`
	Event      string         `json:"event"`
	Properties map[string]any `json:"properties"`
	Timestamp  string         `json:"timestamp"`
}

func buildPayload(apiKey, anonID, version string) posthogEvent {
	return posthogEvent{
		APIKey: apiKey,
		Event:  "ai_firewall_startup",
		Properties: map[string]any{
			"distinct_id": anonID,
			"version":     version,
			"os":          runtime.GOOS,
			"arch":        runtime.GOARCH,
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

func post(endpoint string, payload posthogEvent) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: sendTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
