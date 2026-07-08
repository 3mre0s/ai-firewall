// Load test for the per-user vault registry.
//
// WHY A GO TEST (not a standalone loadtest/ program):
//
//	The requirement is to (a) drive the REAL /v1/check HTTP handler as a black
//	box, (b) read the ADAPTER's Go heap via runtime.ReadMemStats, and (c) inject
//	a clock for the eviction scenario (store.now). A separate OS process could
//	satisfy (a) but not (b) or (c) — ReadMemStats only sees its own process and
//	store.now is unexported. So we host the real handler in-process behind an
//	httptest.Server (real TCP/HTTP over loopback, real handleCheck), which keeps
//	the black-box request path while letting the same process measure the vault
//	heap and set the injectable clock. It lives in package main alongside the
//	other adapter tests, matching the repo's *_test.go convention.
//
// This is a MEASUREMENT run, not a regression gate: it asserts only correctness
// (capacity fail-closed, eviction count), never memory/latency thresholds.
//
// It is skipped by default so `go test ./...` stays fast. Run it explicitly:
//
//	AIFW_LOADTEST=1 go test ./extensions/open-webui/ -run TestLoadVaultRegistry -v -timeout 20m
//
// Add the race detector to check for mutex contention / data races:
//
//	AIFW_LOADTEST=1 go test ./extensions/open-webui/ -run TestLoadVaultRegistry -race -v -timeout 30m
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"text/tabwriter"
	"time"

	"github.com/3mre0s/ai_firewall/config"
)

// loadConfig builds a realistic config for the load harness: the real test
// config, but pinned to the production-default per-user vault size (200) so the
// measured footprint reflects the real default, and silent logging so 40k
// requests don't flood the output.
func loadConfig() *config.Config {
	cfg := config.LoadForTest()
	cfg.VaultSizeLimit = 200
	cfg.LogLevel = "silent"
	return cfg
}

// ── Harness ───────────────────────────────────────────────────────────────────

// loadEnv hosts the real adapter handler behind a loopback HTTP server.
type loadEnv struct {
	srv    *httptest.Server
	engine *engine
	client *http.Client
}

func newLoadEnv(maxUsers int, idleTTL time.Duration) *loadEnv {
	// Reuse the real config + store constructors; only bump the per-user vault
	// size to the production default (LoadForTest uses a tiny 100) for realism.
	cfg := loadConfig()
	st := newUserStore(cfg, idleTTL, maxUsers)
	e := &engine{store: st}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/check", e.handleCheck)
	srv := httptest.NewServer(mux)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        256,
			MaxIdleConnsPerHost: 256,
		},
	}
	return &loadEnv{srv: srv, engine: e, client: client}
}

func (le *loadEnv) close() {
	le.client.CloseIdleConnections()
	le.srv.Close()
}

// send makes one real HTTP /v1/check call and returns its latency + verdict.
func (le *loadEnv) send(user, content, direction string) (time.Duration, int, checkResponse) {
	body, _ := json.Marshal(checkRequest{Content: content, User: user, Direction: direction})
	start := time.Now()
	resp, err := le.client.Post(le.srv.URL+"/v1/check", "application/json", bytes.NewReader(body))
	lat := time.Since(start)
	if err != nil {
		return lat, 0, checkResponse{}
	}
	var cr checkResponse
	_ = json.NewDecoder(resp.Body).Decode(&cr)
	_ = resp.Body.Close()
	return lat, resp.StatusCode, cr
}

// payload is a small, realistic message: one distinct email + one fake token,
// so every user's vault stores two entries — the common real-world case.
func payload(i int) string {
	return fmt.Sprintf(
		"Hi team, please reach me at user%d@example.com — my deploy token is %s, thanks!",
		i, ghToken)
}

// ── Memory sampling ───────────────────────────────────────────────────────────

type memSample struct {
	heapAlloc uint64 // live heap after GC (bytes)
	heapInuse uint64 // heap spans in use (bytes)
	rss       uint64 // OS resident set size (bytes)
	rssOK     bool
}

// sampleMem forces a GC so HeapAlloc reflects the live set, then reads stats.
func sampleMem() memSample {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	rss, ok := readRSS()
	return memSample{heapAlloc: ms.HeapAlloc, heapInuse: ms.HeapInuse, rss: rss, rssOK: ok}
}

// readRSS returns the process resident set size. Only implemented via
// /proc/self/status on Linux; elsewhere (e.g. Windows) it reports unsupported,
// and we fall back to Go-heap numbers. This is deliberately best-effort.
func readRSS() (uint64, bool) {
	if runtime.GOOS != "linux" {
		return 0, false
	}
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line) // "VmRSS: 12345 kB"
			if len(fields) >= 2 {
				if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					return kb * 1024, true
				}
			}
		}
	}
	return 0, false
}

func rssSupportNote() string {
	if runtime.GOOS == "linux" {
		return "OS RSS captured via /proc/self/status."
	}
	return fmt.Sprintf("OS RSS unsupported on %s — Go-heap numbers only.", runtime.GOOS)
}

// ── Latency stats ─────────────────────────────────────────────────────────────

func latencyStats(lat []time.Duration) (avg, p95, p99 time.Duration) {
	if len(lat) == 0 {
		return 0, 0, 0
	}
	s := append([]time.Duration(nil), lat...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	var sum time.Duration
	for _, d := range s {
		sum += d
	}
	return sum / time.Duration(len(s)), percentile(s, 0.95), percentile(s, 0.99)
}

// percentile expects a sorted slice.
func percentile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1)*q + 0.5)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// ── Report ────────────────────────────────────────────────────────────────────

type row struct {
	scenario             string
	users                int
	total, avg, p95, p99 time.Duration
	heapDeltaMB          float64
	perUser              string
	note                 string
}

func mb(b uint64) float64 { return float64(b) / (1024 * 1024) }
func mbd(a, b uint64) float64 {
	return (float64(a) - float64(b)) / (1024 * 1024)
}
func perUserKB(a, b uint64, n int) float64 {
	if n == 0 {
		return 0
	}
	return (float64(a) - float64(b)) / float64(n) / 1024
}

func rd(d time.Duration) string { return d.Round(time.Microsecond).String() }

func printReport(t *testing.T, rows []row, baselineRSS, peakRSS memSample) {
	var b strings.Builder
	b.WriteString("\n════════════════════ Vault Registry Load Test ════════════════════\n")
	b.WriteString(fmt.Sprintf("GOOS=%s  GOARCH=%s  GOMAXPROCS=%d  NumCPU=%d\n",
		runtime.GOOS, runtime.GOARCH, runtime.GOMAXPROCS(0), runtime.NumCPU()))
	b.WriteString("Memory column = Go heap (runtime.MemStats.HeapAlloc after GC), NOT OS RSS.\n")
	b.WriteString(rssSupportNote() + "\n")
	if peakRSS.rssOK && baselineRSS.rssOK {
		b.WriteString(fmt.Sprintf("OS RSS: baseline %.1f MB → peak %.1f MB\n",
			mb(baselineRSS.rss), mb(peakRSS.rss)))
	}
	b.WriteString("\n")

	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SCENARIO\tUSERS\tTOTAL\tAVG\tP95\tP99\tHEAP Δ(MB)\tPER-USER\tNOTE")
	fmt.Fprintln(tw, "--------\t-----\t-----\t---\t---\t---\t---------\t--------\t----")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%+.1f\t%s\t%s\n",
			r.scenario, r.users, rd(r.total), rd(r.avg), rd(r.p95), rd(r.p99),
			r.heapDeltaMB, r.perUser, r.note)
	}
	tw.Flush()
	b.WriteString("\nNote: no memory/latency thresholds are asserted — exploratory measurement.\n")
	b.WriteString("═══════════════════════════════════════════════════════════════════\n")

	// Print to stdout (visible with -v) and also via t.Log.
	fmt.Print(b.String())
	t.Log(b.String())
}

// betweenScenarios releases the previous scenario's memory so the next one
// measures a clean baseline (prevents cross-scenario pollution).
func betweenScenarios() {
	runtime.GC()
	debug.FreeOSMemory()
}

// ── Scenarios ─────────────────────────────────────────────────────────────────

const loadUsers = 10000 // == default VAULT_MAX_USERS

// (a) Steady state: VAULT_MAX_USERS distinct users, one request each, sequential.
func scenarioSteady(t *testing.T) row {
	betweenScenarios()
	le := newLoadEnv(loadUsers, time.Hour)
	defer le.close()

	before := sampleMem()
	lat := make([]time.Duration, 0, loadUsers)
	var errs int
	start := time.Now()
	for i := 0; i < loadUsers; i++ {
		d, code, cr := le.send(fmt.Sprintf("user-%d", i), payload(i), "inlet")
		if code != http.StatusOK || !cr.Allowed {
			errs++
		}
		lat = append(lat, d)
	}
	total := time.Since(start)
	after := sampleMem()

	if errs != 0 {
		t.Errorf("steady: %d requests did not succeed", errs)
	}
	if got := le.engine.store.size(); got != loadUsers {
		t.Errorf("steady: expected %d live vaults, got %d", loadUsers, got)
	}
	avg, p95, p99 := latencyStats(lat)
	return row{
		scenario: "a) steady-seq",
		users:    loadUsers,
		total:    total,
		avg:      avg, p95: p95, p99: p99,
		heapDeltaMB: mbd(after.heapAlloc, before.heapAlloc),
		perUser:     fmt.Sprintf("%.2f KB", perUserKB(after.heapAlloc, before.heapAlloc, loadUsers)),
		note:        "sequential",
	}
}

// (b) Concurrent burst: same users, 100 parallel workers. Run with -race to
// surface mutex contention / data races in the registry.
func scenarioConcurrent(t *testing.T) row {
	betweenScenarios()
	const workers = 100
	le := newLoadEnv(loadUsers, time.Hour)
	defer le.close()

	before := sampleMem()
	lat := make([]time.Duration, loadUsers) // each index written by one goroutine
	var errs int64
	jobs := make(chan int, workers)
	var wg sync.WaitGroup

	start := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				d, code, cr := le.send(fmt.Sprintf("user-%d", i), payload(i), "inlet")
				if code != http.StatusOK || !cr.Allowed {
					atomic.AddInt64(&errs, 1)
				}
				lat[i] = d
			}
		}()
	}
	for i := 0; i < loadUsers; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	total := time.Since(start)
	after := sampleMem()

	if errs != 0 {
		t.Errorf("concurrent: %d requests did not succeed", errs)
	}
	if got := le.engine.store.size(); got != loadUsers {
		t.Errorf("concurrent: expected %d live vaults, got %d", loadUsers, got)
	}
	avg, p95, p99 := latencyStats(lat)
	return row{
		scenario: "b) concurrent",
		users:    loadUsers,
		total:    total,
		avg:      avg, p95: p95, p99: p99,
		heapDeltaMB: mbd(after.heapAlloc, before.heapAlloc),
		perUser:     fmt.Sprintf("%.2f KB", perUserKB(after.heapAlloc, before.heapAlloc, loadUsers)),
		note:        fmt.Sprintf("%d workers (run -race)", workers),
	}
}

// (c) Capacity boundary: push past VAULT_MAX_USERS and confirm fail-closed
// vault_capacity_exceeded under concurrent load.
func scenarioCapacity(t *testing.T) row {
	betweenScenarios()
	const workers = 100
	const total = loadUsers + 500 // 10500 distinct users, cap = 10000
	le := newLoadEnv(loadUsers, time.Hour)
	defer le.close()

	before := sampleMem()
	var admitted, blocked, other int64
	lat := make([]time.Duration, total)
	jobs := make(chan int, workers)
	var wg sync.WaitGroup

	start := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				d, code, cr := le.send(fmt.Sprintf("cap-user-%d", i), payload(i), "inlet")
				switch {
				case code == http.StatusOK && cr.Allowed:
					atomic.AddInt64(&admitted, 1)
				case code == http.StatusOK && cr.Reason == "vault_capacity_exceeded":
					atomic.AddInt64(&blocked, 1)
				default:
					atomic.AddInt64(&other, 1)
				}
				lat[i] = d
			}
		}()
	}
	for i := 0; i < total; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	elapsed := time.Since(start)
	after := sampleMem()

	// Correctness assertions (safe to gate on — not perf thresholds).
	if admitted != loadUsers {
		t.Errorf("capacity: expected %d admitted, got %d", loadUsers, admitted)
	}
	if blocked != total-loadUsers {
		t.Errorf("capacity: expected %d fail-closed, got %d", total-loadUsers, blocked)
	}
	if other != 0 {
		t.Errorf("capacity: %d unexpected responses", other)
	}
	avg, p95, p99 := latencyStats(lat)
	return row{
		scenario: "c) capacity",
		users:    total,
		total:    elapsed,
		avg:      avg, p95: p95, p99: p99,
		heapDeltaMB: mbd(after.heapAlloc, before.heapAlloc),
		perUser:     "-",
		note:        fmt.Sprintf("admitted=%d blocked=%d (fail-closed OK)", admitted, blocked),
	}
}

// (d) Idle eviction under load: fill N users, advance an injected clock past the
// TTL, send one more request, and confirm memory is RECLAIMED (heap drops), not
// just that the map count falls.
func scenarioEviction(t *testing.T) (row, row) {
	betweenScenarios()
	const n = loadUsers
	const idleTTL = time.Minute
	le := newLoadEnv(n+10, idleTTL)
	defer le.close()

	// Inject a controllable clock (race-safe via atomic).
	var clockNanos int64
	atomic.StoreInt64(&clockNanos, time.Now().UnixNano())
	le.engine.store.now = func() time.Time { return time.Unix(0, atomic.LoadInt64(&clockNanos)) }

	baseline := sampleMem()

	// Fill phase: N users at time t0.
	var errs int
	start := time.Now()
	for i := 0; i < n; i++ {
		_, code, cr := le.send(fmt.Sprintf("evict-user-%d", i), payload(i), "inlet")
		if code != http.StatusOK || !cr.Allowed {
			errs++
		}
	}
	fillTotal := time.Since(start)
	peak := sampleMem()
	if errs != 0 {
		t.Errorf("eviction fill: %d requests failed", errs)
	}
	if got := le.engine.store.size(); got != n {
		t.Errorf("eviction: expected %d live vaults after fill, got %d", n, got)
	}

	// Advance clock past the TTL, then send ONE request to trigger the sweep.
	atomic.StoreInt64(&clockNanos, time.Now().Add(idleTTL+time.Minute).UnixNano())
	if _, code, _ := le.send("evict-trigger", payload(-1), "inlet"); code != http.StatusOK {
		t.Errorf("eviction trigger got status %d", code)
	}

	if got := le.engine.store.size(); got != 1 {
		t.Errorf("eviction: expected 1 live vault after sweep, got %d", got)
	}
	after := sampleMem() // sampleMem GCs → freed vaults are collected

	reclaimedMB := mbd(peak.heapAlloc, after.heapAlloc)
	fillRow := row{
		scenario:    "d) evict-fill",
		users:       n,
		total:       fillTotal,
		heapDeltaMB: mbd(peak.heapAlloc, baseline.heapAlloc),
		perUser:     fmt.Sprintf("%.2f KB", perUserKB(peak.heapAlloc, baseline.heapAlloc, n)),
		note:        fmt.Sprintf("filled %d vaults", n),
	}
	afterRow := row{
		scenario:    "d) evict-after",
		users:       1,
		heapDeltaMB: mbd(after.heapAlloc, baseline.heapAlloc),
		perUser:     "-",
		note:        fmt.Sprintf("size %d→1, reclaimed %.1f MB", n, reclaimedMB),
	}
	return fillRow, afterRow
}

// ── Entry point ───────────────────────────────────────────────────────────────

func TestLoadVaultRegistry(t *testing.T) {
	if os.Getenv("AIFW_LOADTEST") == "" {
		t.Skip("set AIFW_LOADTEST=1 to run the vault registry load test")
	}

	baselineRSS := sampleMem()

	var rows []row
	rows = append(rows, scenarioSteady(t))
	rows = append(rows, scenarioConcurrent(t))
	rows = append(rows, scenarioCapacity(t))
	fillRow, afterRow := scenarioEviction(t)
	rows = append(rows, fillRow, afterRow)

	peakRSS := sampleMem()
	printReport(t, rows, baselineRSS, peakRSS)
}
