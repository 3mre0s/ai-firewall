// Package metrics provides lightweight, lock-free (kilit gerektirmez) counters
// for operational visibility into the firewall.
//
// All counters use sync/atomic so they are safe to increment from
// concurrent goroutines (eş zamanlı goroutine'ler) without a mutex.
//
// The /metrics HTTP endpoint returns JSON so it works out-of-the-box
// with cURL, Prometheus textfile collector, or any dashboard.
// (/metrics HTTP uç noktası JSON döner; cURL, Prometheus veya herhangi bir
//
//	gösterge paneliyle kutudan çıkar çıkmaz çalışır.)
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

	// BlockedRequests — requests blocked by policy enforcement (vault full, etc.)
	// (Politika uygulaması tarafından engellenen istekler — vault dolu, vb.)
	BlockedRequests int64

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
func (c *Counters) IncBlockedRequests()      { atomic.AddInt64(&c.BlockedRequests, 1) }

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
	UpstreamErrors  int64 `json:"upstream_errors_total"`
	VaultEvictions  int64 `json:"vault_evictions_total"`
	BlockedRequests int64 `json:"blocked_requests_total"`

	// --- Vault occupancy (Vault doluluk) ---
	VaultCurrent int    `json:"vault_current"`           // entries currently stored (mevcut giriş sayısı)
	VaultLimit   int    `json:"vault_limit"`             // configured maximum (yapılandırılmış maksimum)
	VaultFillPct string `json:"vault_fill_pct"`          // occupancy percentage (doluluk yüzdesi)
	VaultHits    int64  `json:"vault_unmask_hits_total"` // cumulative Retrieve() calls (kümülatif Retrieve() çağrıları)
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
		UptimeSeconds:   time.Since(c.startTime).Seconds(),
		RequestsTotal:   reqs,
		StreamRequests:  atomic.LoadInt64(&c.StreamRequests),
		MaskedItems:     atomic.LoadInt64(&c.MaskedItems),
		MaskedRequests:  masked,
		UnmaskedItems:   atomic.LoadInt64(&c.UnmaskedItems),
		UpstreamErrors:  atomic.LoadInt64(&c.UpstreamErrors),
		VaultEvictions:  atomic.LoadInt64(&c.VaultEvictions),
		BlockedRequests: atomic.LoadInt64(&c.BlockedRequests),
		MaskRate:        rate + "%",
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

// HTMLHandler returns an http.HandlerFunc that serves a visual dashboard.
// (Görsel bir gösterge paneli sunan bir http.HandlerFunc döner.)
func (c *Counters) HTMLHandler(vault VaultStatsProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, dashboardHTML)
	}
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Anonmyz — Local Privacy Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: radial-gradient(ellipse at top left, #0f172a 0%, #1e293b 50%, #0b1120 100%);
            color: #e2e8f0;
            padding: 24px;
            min-height: 100vh;
        }
        .container { max-width: 1280px; margin: 0 auto; }
        header {
            display: flex; align-items: center; justify-content: space-between;
            margin-bottom: 32px; padding: 16px 24px;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 16px;
            backdrop-filter: blur(12px);
        }
        .header-left { display: flex; align-items: center; gap: 12px; }
        .header-icon {
            width: 40px; height: 40px;
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            border-radius: 10px;
            display: flex; align-items: center; justify-content: center;
            font-size: 20px;
        }
        .header-text h1 { font-size: 1.3em; font-weight: 600; letter-spacing: -0.02em; }
        .header-text span { font-size: 0.8em; opacity: 0.5; }
        .status-badge {
            display: flex; align-items: center; gap: 8px;
            padding: 8px 16px;
            background: rgba(74,222,128,0.1);
            border: 1px solid rgba(74,222,128,0.2);
            border-radius: 20px;
            font-size: 0.8em; font-weight: 500;
        }
        .status-dot {
            width: 8px; height: 8px; border-radius: 50%;
            animation: pulse 2s infinite;
        }
        .status-dot { background: #4ade80; }
        .section { margin-bottom: 20px; }
        .section-title {
            font-size: 0.8em; text-transform: uppercase; letter-spacing: 1.5px;
            color: rgba(255,255,255,0.4); margin-bottom: 12px; padding-left: 4px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        .card {
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 14px;
            padding: 20px;
            transition: all 0.25s ease;
            position: relative; overflow: hidden;
            animation: fadeIn 0.4s ease forwards;
        }
        .card::before {
            content: ''; position: absolute; top: 0; left: 0;
            width: 100%; height: 100%;
            background: linear-gradient(135deg, rgba(255,255,255,0.05) 0%, transparent 50%);
            pointer-events: none;
        }
        .card:hover {
            border-color: rgba(255,255,255,0.15);
            transform: translateY(-2px);
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }
        .card-header {
            display: flex; align-items: center; gap: 8px; margin-bottom: 12px;
        }
        .card-icon {
            width: 28px; height: 28px; border-radius: 8px;
            display: flex; align-items: center; justify-content: center;
            font-size: 14px;
        }
        .card-icon.blue { background: rgba(59,130,246,0.15); }
        .card-icon.green { background: rgba(74,222,128,0.15); }
        .card-icon.purple { background: rgba(139,92,246,0.15); }
        .card-icon.amber { background: rgba(251,191,36,0.15); }
        .card-icon.red { background: rgba(248,113,113,0.15); }
        .card-icon.teal { background: rgba(45,212,191,0.15); }
        .card-title {
            font-size: 0.8em; font-weight: 500; text-transform: uppercase;
            letter-spacing: 0.5px; color: rgba(255,255,255,0.5);
        }
        .card-value {
            font-size: 2.2em; font-weight: 700;
            line-height: 1.2; letter-spacing: -0.02em;
            transition: color 0.3s ease;
        }
        .card-label {
            font-size: 0.8em; color: rgba(255,255,255,0.4);
            margin-top: 6px;
        }
        .progress-wrap {
            margin-top: 12px; height: 4px;
            background: rgba(255,255,255,0.06);
            border-radius: 2px; overflow: hidden;
        }
        .progress-fill {
            height: 100%; border-radius: 2px;
            transition: width 0.5s ease;
        }
        .progress-fill.blue { background: linear-gradient(90deg, #3b82f6, #60a5fa); }
        .progress-fill.green { background: linear-gradient(90deg, #22c55e, #4ade80); }
        .progress-fill.amber { background: linear-gradient(90deg, #d97706, #fbbf24); }
        .progress-fill.red { background: linear-gradient(90deg, #dc2626, #f87171); }
        .text-good { color: #4ade80; }
        .text-warn { color: #fbbf24; }
        .text-error { color: #f87171; }
        .grid-status { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
        .card-stat { padding: 16px; text-align: center; }
        .card-stat .card-value { font-size: 1.8em; }
        .card-stat .card-title { font-size: 0.7em; margin-bottom: 0; }
		.trace-wrap { overflow-x: auto; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06); border-radius: 14px; }
		.trace-table { width: 100%; border-collapse: collapse; font-size: 0.78em; }
		.trace-table th, .trace-table td { padding: 11px 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.05); white-space: nowrap; }
		.trace-table th { color: rgba(255,255,255,0.42); font-weight: 600; text-transform: uppercase; letter-spacing: .5px; }
		.trace-table td { color: rgba(255,255,255,0.76); }
		.trace-table code { color: #93c5fd; }
		.trace-empty { padding: 20px; color: rgba(255,255,255,0.4); }
        footer {
            display: flex; align-items: center; justify-content: space-between;
            margin-top: 32px; padding: 12px 16px;
            background: rgba(255,255,255,0.02);
            border: 1px solid rgba(255,255,255,0.04);
            border-radius: 10px;
            font-size: 0.8em; color: rgba(255,255,255,0.3);
        }
        .footer-left { display: flex; align-items: center; gap: 8px; }
        .pulse-dot {
            width: 6px; height: 6px; border-radius: 50%; background: #4ade80;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @media (max-width: 640px) {
            body { padding: 12px; }
            header { flex-direction: column; gap: 12px; text-align: center; }
            .grid { grid-template-columns: 1fr 1fr; gap: 12px; }
            .card-value { font-size: 1.6em; }
            footer { flex-direction: column; gap: 8px; text-align: center; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-left">
                <div class="header-icon">🛡</div>
                <div class="header-text">
                    <h1>Anonmyz</h1>
                    <span>Real-time Metrics Dashboard</span>
                </div>
            </div>
            <div class="status-badge">
                <span class="status-dot"></span>
                <span id="healthStatus">Active</span>
            </div>
        </header>

        <div class="section">
            <div class="section-title">Pipeline</div>
            <div class="grid">
                <div class="card"><div class="card-header"><div class="card-icon blue">⏱</div><div class="card-title">Uptime</div></div><div class="card-value" id="uptime">—</div></div>
                <div class="card"><div class="card-header"><div class="card-icon blue">📥</div><div class="card-title">Total Requests</div></div><div class="card-value" id="requests">0</div></div>
                <div class="card"><div class="card-header"><div class="card-icon blue">🔁</div><div class="card-title">Stream Requests</div></div><div class="card-value" id="streams">0</div><div class="card-label">SSE streaming responses</div></div>
                <div class="card"><div class="card-header"><div class="card-icon amber">🎭</div><div class="card-title">Mask Rate</div></div><div class="card-value" id="maskRate">0%</div><div class="progress-wrap"><div class="progress-fill amber" id="maskRateBar" style="width:0%"></div></div></div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Security</div>
            <div class="grid">
                <div class="card"><div class="card-header"><div class="card-icon green">🛡</div><div class="card-title">Masked Items</div></div><div class="card-value text-good" id="maskedItems">0</div><div class="card-label" id="maskedReqs">0 requests affected</div></div>
                <div class="card"><div class="card-header"><div class="card-icon green">↩</div><div class="card-title">Unmasked Items</div></div><div class="card-value" id="unmaskedItems">0</div><div class="card-label">Restored in responses</div></div>
                <div class="card"><div class="card-header"><div class="card-icon purple">🗄</div><div class="card-title">Vault Occupancy</div></div><div class="card-value" id="vaultOccupancy">0%</div><div class="card-label" id="vaultDetails">0 / 0 entries</div><div class="progress-wrap"><div class="progress-fill blue" id="vaultBar" style="width:0%"></div></div></div>
                <div class="card"><div class="card-header"><div class="card-icon teal">🔍</div><div class="card-title">Vault Hits</div></div><div class="card-value" id="vaultHits">0</div><div class="card-label">Unmask lookups</div></div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Status</div>
            <div class="grid grid-status">
                <div class="card card-stat"><div class="card-title">Upstream Errors</div><div class="card-value" id="upstreamErrors">0</div></div>
                <div class="card card-stat"><div class="card-title">Blocked Requests</div><div class="card-value" id="blockedRequests">0</div></div>
                <div class="card card-stat"><div class="card-title">Vault Evictions</div><div class="card-value" id="vaultEvictions">0</div></div>
            </div>
        </div>

		<div class="section">
			<div class="section-title">Local Privacy Trace — newest 8 detections, raw values never retained</div>
			<div class="trace-wrap">
				<table class="trace-table">
					<thead><tr><th>Time</th><th>Request</th><th>Detected</th><th>Placeholder</th><th>Prevented</th><th>Proxy latency</th><th>Stream restore</th></tr></thead>
					<tbody id="traceRows"><tr><td colspan="7" class="trace-empty">No protected requests yet.</td></tr></tbody>
				</table>
			</div>
		</div>

        <footer>
            <div class="footer-left"><span class="pulse-dot"></span><span id="lastUpdate">Loading dashboard...</span></div>
            <span>Anonmyz · local-first DLP</span>
        </footer>
    </div>

    <script>
        function formatUptime(s) {
            var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = Math.floor(s % 60);
            if (h > 0) return h + 'h ' + m + 'm';
            if (m > 0) return m + 'm ' + sec + 's';
            return sec + 's';
        }
        function updateMetrics() {
            fetch('/metrics').then(function(r){return r.json()}).then(function(d){
                document.getElementById('uptime').textContent = formatUptime(d.uptime_seconds);
                document.getElementById('requests').textContent = (d.requests_total||0).toLocaleString();
                document.getElementById('streams').textContent = (d.stream_requests||0).toLocaleString();
                document.getElementById('maskRate').textContent = d.mask_rate_pct||'0%';
                var mp = parseFloat(d.mask_rate_pct)||0;
                document.getElementById('maskRateBar').style.width = mp + '%';
                document.getElementById('maskedItems').textContent = (d.masked_items_total||0).toLocaleString();
                document.getElementById('maskedReqs').textContent = (d.masked_requests_total||0).toLocaleString() + ' requests affected';
                document.getElementById('unmaskedItems').textContent = (d.unmasked_items_total||0).toLocaleString();
                document.getElementById('vaultOccupancy').textContent = d.vault_fill_pct||'0%';
                document.getElementById('vaultDetails').textContent = (d.vault_current||0) + ' / ' + (d.vault_limit||0) + ' entries';
                document.getElementById('vaultBar').style.width = (parseFloat(d.vault_fill_pct)||0) + '%';
                document.getElementById('vaultHits').textContent = (d.vault_unmask_hits_total||0).toLocaleString();
                var ue = d.upstream_errors_total||0;
                var ueEl = document.getElementById('upstreamErrors');
                ueEl.textContent = ue.toLocaleString();
                ueEl.className = 'card-value ' + (ue > 0 ? 'text-error' : 'text-good');
                var br = d.blocked_requests_total||0;
                var brEl = document.getElementById('blockedRequests');
                brEl.textContent = br.toLocaleString();
                brEl.className = 'card-value ' + (br > 0 ? 'text-error' : 'text-good');
                var ve = d.vault_evictions_total||0;
                var veEl = document.getElementById('vaultEvictions');
                veEl.textContent = ve.toLocaleString();
                veEl.className = 'card-value ' + (ve > 0 ? 'text-warn' : 'text-good');
                var healthy = ue === 0 && br === 0;
                document.getElementById('healthStatus').textContent = healthy ? 'Healthy' : 'Warning';
                document.querySelector('.status-dot').style.background = healthy ? '#4ade80' : '#fbbf24';
                document.getElementById('lastUpdate').textContent = 'Updated ' + new Date().toLocaleTimeString();
            }).catch(function(){
                document.getElementById('lastUpdate').textContent = 'Connection lost — retrying...';
            });
        }
		function updateAudit() {
			fetch('/audit').then(function(r){return r.json()}).then(function(d){
				var rows = document.getElementById('traceRows');
				rows.textContent = '';
				var count = 0;
				(d.traces || []).some(function(trace){
					return (trace.detections || []).some(function(det){
						if (count++ >= 8) return true;
						var values = [
							new Date(trace.timestamp).toLocaleTimeString(), trace.request_id,
							det.secret_type, det.placeholder_id,
							det.original_prevented ? 'Yes' : 'No',
							Number(trace.proxy_latency_ms || 0).toFixed(2) + ' ms',
							trace.streaming_restoration
						];
						var tr = document.createElement('tr');
						values.forEach(function(value, index){
							var td = document.createElement('td');
							if (index === 3) { var code = document.createElement('code'); code.textContent = value; td.appendChild(code); }
							else { td.textContent = value; }
							if (index === 4) td.className = det.original_prevented ? 'text-good' : 'text-error';
							tr.appendChild(td);
						});
						rows.appendChild(tr);
						return false;
					});
				});
				if (count === 0) { var tr = document.createElement('tr'), td = document.createElement('td'); td.colSpan = 7; td.className = 'trace-empty'; td.textContent = 'No protected requests yet.'; tr.appendChild(td); rows.appendChild(tr); }
			}).catch(function(){});
		}
        updateMetrics();
		updateAudit();
        setInterval(updateMetrics, 3000);
		setInterval(updateAudit, 3000);
    </script>
</body>
</html>
`
