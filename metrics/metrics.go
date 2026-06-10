// Package metrics provides lightweight, lock-free (kilit gerektirmez) counters
// for operational visibility into the firewall.
//
// All counters use sync/atomic so they are safe to increment from
// concurrent goroutines (eş zamanlı goroutine'ler) without a mutex.
//
// The /metrics HTTP endpoint returns JSON so it works out-of-the-box
// with cURL, Prometheus textfile collector, or any dashboard.
// (/metrics HTTP uç noktası JSON döner; cURL, Prometheus veya herhangi bir
//  gösterge paneliyle kutudan çıkar çıkmaz çalışır.)
package metrics

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// VaultStats is the subset of vault state needed by the metrics snapshot.
// Defined here to avoid an import cycle between metrics ↔ vault.
// (Döngüsel bağımlılığı önlemek için vault.Stats yerine bu minimal interface kullanılır.)
type VaultStats struct {
	Current   int   // current entry count (mevcut giriş sayısı)
	Limit     int   // configured maximum (yapılandırılmış maksimum)
	TotalHits int64 // cumulative unmask operations (kümülatif maske kaldırma sayısı)
}

// VaultStatsProvider is any object that can report its current occupancy.
// vault.Vault satisfies this interface automatically.
// (vault.Vault bu arayüzü otomatik olarak karşılar.)
type VaultStatsProvider interface {
	Stats() VaultStats
}

// Counters holds all tracked (izlenen) metrics.
// Fields are int64 so atomic operations work on 32-bit platforms.
// (Alanlar int64'tür, 32-bit platformlarda atomik işlemler çalışır.)
type Counters struct {
	// RequestsTotal — every POST that entered the pipeline
	// (Boru hattına giren her POST)
	RequestsTotal int64

	// StreamRequests — requests that returned a streaming SSE response
	// (Akış SSE yanıtı döndüren istekler)
	StreamRequests int64

	// MaskedItems — total individual sensitive values replaced
	// (Değiştirilen toplam hassas değer sayısı)
	MaskedItems int64

	// MaskedRequests — requests where at least one item was masked
	// (En az bir öğenin maskelendiği istekler)
	MaskedRequests int64

	// UnmaskedItems — total label→original replacements in responses
	// (Yanıtlarda yapılan toplam etiket→orijinal değiştirme sayısı)
	UnmaskedItems int64

	// UpstreamErrors — non-2xx or network errors from the upstream provider
	// (Upstream sağlayıcıdan gelen 2xx olmayan veya ağ hataları)
	UpstreamErrors int64

	// VaultEvictions — times a masking was skipped because vault was full
	// (Vault dolu olduğu için maskelemenin atlandığı sayı)
	VaultEvictions int64

	// startTime is captured at construction for uptime calculation.
	// (Çalışma süresi hesaplaması için yapım anında kaydedilir.)
	startTime time.Time
}

// Global is the single shared Counters instance used by the proxy.
// (Proxy tarafından kullanılan tek paylaşılan Counters örneği.)
var Global = &Counters{startTime: time.Now()}

// ── Increment helpers (artırma yardımcıları) ──────────────────────────────────

func (c *Counters) IncRequests()             { atomic.AddInt64(&c.RequestsTotal, 1) }
func (c *Counters) IncStreamRequests()       { atomic.AddInt64(&c.StreamRequests, 1) }
func (c *Counters) IncMaskedItems(n int64)   { atomic.AddInt64(&c.MaskedItems, n) }
func (c *Counters) IncMaskedRequests()       { atomic.AddInt64(&c.MaskedRequests, 1) }
func (c *Counters) IncUnmaskedItems(n int64) { atomic.AddInt64(&c.UnmaskedItems, n) }
func (c *Counters) IncUpstreamErrors()       { atomic.AddInt64(&c.UpstreamErrors, 1) }
func (c *Counters) IncVaultEvictions()       { atomic.AddInt64(&c.VaultEvictions, 1) }

// ── Snapshot (anlık görüntü) ──────────────────────────────────────────────────

// snapshot is the JSON-serialisable view of all metrics.
// snake_case field names match Prometheus naming conventions.
// (Alan adları Prometheus adlandırma kurallarıyla eşleşen JSON serileştirilebilir görünüm.)
type snapshot struct {
	// --- Process metrics ---
	UptimeSeconds  float64 `json:"uptime_seconds"`
	RequestsTotal  int64   `json:"requests_total"`
	StreamRequests int64   `json:"stream_requests"`

	// --- Masking metrics ---
	MaskedItems    int64  `json:"masked_items_total"`
	MaskedRequests int64  `json:"masked_requests_total"`
	UnmaskedItems  int64  `json:"unmasked_items_total"`
	MaskRate       string `json:"mask_rate_pct"` // % of requests that triggered masking (maskelemeyi tetikleyen istek yüzdesi)

	// --- Error metrics ---
	UpstreamErrors int64 `json:"upstream_errors_total"`
	VaultEvictions int64 `json:"vault_evictions_total"`

	// --- Vault occupancy (Vault doluluk) ---
	VaultCurrent int     `json:"vault_current"`          // entries currently stored (mevcut giriş sayısı)
	VaultLimit   int     `json:"vault_limit"`             // configured maximum (yapılandırılmış maksimum)
	VaultFillPct string  `json:"vault_fill_pct"`          // occupancy percentage (doluluk yüzdesi)
	VaultHits    int64   `json:"vault_unmask_hits_total"` // cumulative Retrieve() calls (kümülatif Retrieve() çağrıları)
}

// Snapshot returns a point-in-time view of all metrics.
// vault is optional — pass nil if vault stats are unavailable.
// (vault isteğe bağlıdır — vault istatistikleri mevcut değilse nil geçin.)
func (c *Counters) Snapshot(vault VaultStatsProvider) snapshot {
	reqs := atomic.LoadInt64(&c.RequestsTotal)
	masked := atomic.LoadInt64(&c.MaskedRequests)

	rate := "0.00"
	if reqs > 0 {
		rate = fmt.Sprintf("%.2f", float64(masked)/float64(reqs)*100)
	}

	s := snapshot{
		UptimeSeconds:  time.Since(c.startTime).Seconds(),
		RequestsTotal:  reqs,
		StreamRequests: atomic.LoadInt64(&c.StreamRequests),
		MaskedItems:    atomic.LoadInt64(&c.MaskedItems),
		MaskedRequests: masked,
		UnmaskedItems:  atomic.LoadInt64(&c.UnmaskedItems),
		UpstreamErrors: atomic.LoadInt64(&c.UpstreamErrors),
		VaultEvictions: atomic.LoadInt64(&c.VaultEvictions),
		MaskRate:       rate + "%",
	}

	// Attach vault occupancy if a provider was given.
	// (Sağlayıcı verilmişse vault doluluk bilgisini ekle.)
	if vault != nil {
		vs := vault.Stats()
		s.VaultCurrent = vs.Current
		s.VaultLimit = vs.Limit
		s.VaultHits = vs.TotalHits

		fillPct := 0.0
		if vs.Limit > 0 {
			fillPct = float64(vs.Current) / float64(vs.Limit) * 100
		}
		s.VaultFillPct = fmt.Sprintf("%.2f%%", fillPct)
	}

	return s
}

// ── HTTP handler ──────────────────────────────────────────────────────────────

// Handler returns an http.HandlerFunc for the /metrics endpoint.
// vault is optional (pass nil if you don't need vault occupancy in the output).
// Response format (yanıt formatı): application/json
//
// Example response (örnek yanıt):
//
//	{
//	  "uptime_seconds": 3600.4,
//	  "requests_total": 142,
//	  "masked_items_total": 89,
//	  "mask_rate_pct": "62.68%",
//	  "vault_current": 47,
//	  "vault_limit": 1000,
//	  "vault_fill_pct": "4.70%"
//	  ...
//	}
func (c *Counters) Handler(vault VaultStatsProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(c.Snapshot(vault))
	}
}
