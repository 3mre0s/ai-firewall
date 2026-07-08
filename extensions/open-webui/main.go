// Command open-webui-check exposes the existing AI Firewall engine to the
// Open WebUI Filter extension (filter.py) over a single HTTP endpoint,
// POST /v1/check.
//
// This binary is a THIN ADAPTER. It contains no detection, masking, or
// decision logic of its own — every decision is delegated to the existing
// engine packages:
//
//	config  — canonical env-var configuration loader
//	vault   — process-lifetime label→original store
//	masker  — Mask / Unmask / Detect over the shared pattern registry
//
// Flow:
//
//	Open WebUI → filter.py → POST /v1/check → masker.{Mask,Unmask,Detect} → JSON
//
// Per-user isolation (adapter layer only):
//
//	The engine's vault is a single label space. To keep one Open WebUI user's
//	masked values from ever being restored in another user's context, this
//	adapter gives every "user" its OWN masker+vault pair (see userStore).
//	The core engine packages are untouched; isolation is achieved purely by
//	routing each request to the caller's own Masker.
//
// The engine is a *masking* firewall: its native action is "mask & allow", and
// it only *blocks* (fail-closed) when a detected value cannot be masked because
// the vault is full — exactly mirroring the proxy's HTTP 507 behaviour. There
// is no content-category blocking and no prompt-injection detector in this
// engine, so this adapter does not invent one.
//
// Run it (FORWARD_API_KEY is required by the shared config loader even though
// this adapter never forwards anywhere — set it to "none"):
//
//	FORWARD_API_KEY=none go run .
//	FIREWALL_PORT=8080 VAULT_IDLE_TTL=30m VAULT_MAX_USERS=10000 FORWARD_API_KEY=none go run .
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/3mre0s/ai_firewall/config"
	"github.com/3mre0s/ai_firewall/masker"
	"github.com/3mre0s/ai_firewall/vault"
)

// ════════════════════════════════════════════════════════════════════════════
// Per-user vault registry (adapter-layer isolation)
// ════════════════════════════════════════════════════════════════════════════

// errVaultCapacity is returned when a new user cannot be admitted because the
// registry is already holding maxUsers distinct vaults.
var errVaultCapacity = errors.New("vault_capacity_exceeded")

// userMasker is one user's isolated engine plus its last-activity timestamp.
type userMasker struct {
	masker     *masker.Masker
	lastAccess time.Time
}

// userStore maps a user identifier to that user's own Masker (backed by its own
// Vault). This is the whole of the isolation mechanism: nothing in the core
// engine changes — each user simply gets a private label space.
//
// Memory is bounded two ways:
//   - TTL eviction: entries idle for longer than idleTTL are dropped lazily on
//     the next access (no background goroutine — simpler, nothing to stop).
//   - Max-users cap: once maxUsers distinct vaults exist, admitting a new user
//     fails CLOSED (see get).
type userStore struct {
	mu       sync.Mutex
	cfg      *config.Config
	users    map[string]*userMasker
	idleTTL  time.Duration
	maxUsers int
	now      func() time.Time // injectable clock for tests
}

func newUserStore(cfg *config.Config, idleTTL time.Duration, maxUsers int) *userStore {
	return &userStore{
		cfg:      cfg,
		users:    make(map[string]*userMasker),
		idleTTL:  idleTTL,
		maxUsers: maxUsers,
		now:      time.Now,
	}
}

// get returns the caller's own Masker, creating it lazily on first use.
//
// On every call it first sweeps expired entries, so idle users release memory
// even without a background worker. If admitting a new user would exceed
// maxUsers, it returns errVaultCapacity — we fail CLOSED: without a vault we
// cannot mask, and forwarding unmasked traffic would defeat the firewall, so we
// refuse rather than leak (consistent with the engine's vault-full behaviour).
func (s *userStore) get(user string) (*masker.Masker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	s.evictExpiredLocked(now)

	if um, ok := s.users[user]; ok {
		um.lastAccess = now
		return um.masker, nil
	}

	if len(s.users) >= s.maxUsers {
		return nil, errVaultCapacity
	}

	m := masker.New(vault.New(s.cfg.VaultSizeLimit), s.cfg)
	s.users[user] = &userMasker{masker: m, lastAccess: now}
	return m, nil
}

// evictExpiredLocked drops entries idle longer than idleTTL. Caller holds mu.
func (s *userStore) evictExpiredLocked(now time.Time) {
	if s.idleTTL <= 0 {
		return
	}
	for user, um := range s.users {
		if now.Sub(um.lastAccess) > s.idleTTL {
			delete(s.users, user)
		}
	}
}

// size reports the number of live user vaults (used by tests).
func (s *userStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.users)
}

// ════════════════════════════════════════════════════════════════════════════
// HTTP adapter
// ════════════════════════════════════════════════════════════════════════════

// engine is the HTTP-facing adapter. All state lives in the per-user store.
type engine struct {
	store *userStore
}

// checkRequest is the JSON body sent by filter.py to /v1/check.
type checkRequest struct {
	// Content is the raw user prompt (inlet) or model reply (outlet) to inspect.
	Content string `json:"content"`
	// User identifies the caller (id/email/name). It selects the isolated vault
	// and is REQUIRED — see handleCheck for the missing-user policy.
	User string `json:"user"`
	// Direction selects the engine path:
	//   "inlet"  (default) — mask sensitive data before it reaches the model.
	//   "outlet"           — restore masked values in the model's reply and
	//                        block if the reply contains a raw, unmasked secret.
	Direction string `json:"direction"`
}

// match is one rule-level detection reported to the caller. It never contains
// the sensitive value itself — only its category and rule name.
type match struct {
	Type  string `json:"type"`            // category, lower-cased, e.g. "pii", "token"
	Rule  string `json:"rule"`            // human-readable rule name, e.g. "E-mail Address"
	Count int    `json:"count,omitempty"` // how many values this rule matched
}

// checkResponse is the verdict returned to filter.py.
//
// Contract:
//   - allowed:          true to permit, false to block.
//   - reason:           machine-readable snake_case code, set only when blocked.
//   - masked_content:   inlet path — content with secrets masked, when changed.
//   - restored_content: outlet path — content with labels restored, when changed.
//   - matches:          always present ([] when nothing was found).
type checkResponse struct {
	Allowed         bool    `json:"allowed"`
	Reason          string  `json:"reason,omitempty"`
	MaskedContent   string  `json:"masked_content,omitempty"`
	RestoredContent string  `json:"restored_content,omitempty"`
	Matches         []match `json:"matches"`
}

// toMatches converts the engine's per-rule detection summaries into the wire
// format, lower-casing the category for machine-friendly consumption. It always
// returns a non-nil slice so the JSON field serialises as [] rather than null.
func toMatches(in []masker.MaskMatch) []match {
	out := make([]match, 0, len(in))
	for _, m := range in {
		out = append(out, match{
			Type:  toLowerType(string(m.Type)),
			Rule:  m.Rule,
			Count: m.Count,
		})
	}
	return out
}

// toLowerType lower-cases a PatternType constant (e.g. "PII" → "pii").
func toLowerType(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// handleCheck routes a /v1/check request to the caller's isolated engine.
func (e *engine) handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req checkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Missing-user policy (chosen: REJECT, not a shared "anonymous" bucket).
	// A security tool must attribute masked data to an owner to isolate it;
	// without an identifier we cannot guarantee that one caller's secrets are
	// not restored into another's context, so we refuse rather than silently
	// pool everyone into one vault. filter.py always sends a "user" (it falls
	// back to "anonymous" for unauthenticated sessions), so this 400 only fires
	// for direct/raw callers that omit it.
	user := strings.TrimSpace(req.User)
	if user == "" {
		writeJSONStatus(w, http.StatusBadRequest, checkResponse{
			Allowed: false,
			Reason:  "missing_user_identifier",
			Matches: []match{},
		})
		return
	}

	m, err := e.store.get(user)
	if err != nil {
		// Registry full — fail CLOSED (block) rather than mask-less passthrough.
		writeJSON(w, checkResponse{
			Allowed: false,
			Reason:  "vault_capacity_exceeded",
			Matches: []match{},
		})
		return
	}

	switch req.Direction {
	case "outlet":
		writeJSON(w, checkOutlet(m, req.Content))
	default: // "inlet" or unspecified
		writeJSON(w, checkInlet(m, req.Content))
	}
}

// checkInlet masks sensitive data on the user → model path using the caller's
// own masker.
//
// The engine's decision here is "mask & allow"; the sole block condition is
// fail-closed: if the vault was full and a detected value could not be masked
// (VaultEvictions > 0), we block rather than let a raw secret through — exactly
// as proxy.ServeHTTP returns HTTP 507.
func checkInlet(m *masker.Masker, content string) checkResponse {
	res := m.Mask(content)
	matches := toMatches(res.Matches)

	if res.VaultEvictions > 0 {
		return checkResponse{
			Allowed: false,
			Reason:  "masking_failed_vault_full",
			Matches: matches,
		}
	}

	resp := checkResponse{Allowed: true, Matches: matches}
	// Only surface masked_content when masking actually changed the text.
	if res.MaskedCount > 0 {
		resp.MaskedContent = res.Text
	}
	return resp
}

// checkOutlet handles the model → user path using the caller's own masker.
//
// Two responsibilities, in order:
//  1. Leak defence — if the reply contains a RAW secret that never went through
//     inlet masking, block it. Vault labels themselves never match a secret
//     pattern, so this only fires on genuine leaks (mirrors the proxy's
//     streaming fail-fast).
//  2. Restoration — replace any vault labels the model echoed back with their
//     original values via THIS user's vault, so the user sees real data. This
//     must happen in the engine: the label→original map lives in the vault and
//     is never exposed to the Python filter.
func checkOutlet(m *masker.Masker, content string) checkResponse {
	if leaks := m.Detect(content); len(leaks) > 0 {
		return checkResponse{
			Allowed: false,
			Reason:  "secret_leak_in_output",
			Matches: toMatches(leaks),
		}
	}

	restored := m.Unmask(content)
	resp := checkResponse{Allowed: true, Matches: []match{}}
	if restored != content {
		resp.RestoredContent = restored
	}
	return resp
}

// writeJSON marshals v as JSON with a 200 status.
func writeJSON(w http.ResponseWriter, v interface{}) {
	writeJSONStatus(w, http.StatusOK, v)
}

// writeJSONStatus marshals v as JSON with the given status code.
func writeJSONStatus(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

// healthHandler is a trivial liveness probe.
func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// ════════════════════════════════════════════════════════════════════════════
// Adapter-only settings (not part of the core config package)
// ════════════════════════════════════════════════════════════════════════════

const (
	defaultIdleTTL  = 30 * time.Minute
	defaultMaxUsers = 10000
)

// adapterSettings reads the two isolation knobs directly from the environment.
// They live here rather than in the config package so the core engine stays
// untouched by this adapter-layer feature.
func adapterSettings() (idleTTL time.Duration, maxUsers int) {
	idleTTL = defaultIdleTTL
	if v := os.Getenv("VAULT_IDLE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			idleTTL = d
		} else {
			log.Printf("[warn] invalid VAULT_IDLE_TTL %q, using default %s", v, defaultIdleTTL)
		}
	}
	maxUsers = defaultMaxUsers
	if v := os.Getenv("VAULT_MAX_USERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxUsers = n
		} else {
			log.Printf("[warn] invalid VAULT_MAX_USERS %q, using default %d", v, defaultMaxUsers)
		}
	}
	return idleTTL, maxUsers
}

func main() {
	log.SetFlags(log.LstdFlags)

	// Reuse the canonical engine configuration loader so this adapter honours
	// the same env vars as the rest of the firewall (MASK_EMAILS, MASK_PATHS,
	// VAULT_SIZE_LIMIT, FIREWALL_PORT, LOG_LEVEL, ...). No config duplication.
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("[fatal] config error: %v\n"+
			"(hint: this adapter never forwards upstream, but the shared config "+
			"loader still requires FORWARD_API_KEY — set FORWARD_API_KEY=none)", err)
	}

	idleTTL, maxUsers := adapterSettings()
	e := &engine{store: newUserStore(cfg, idleTTL, maxUsers)}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/check", e.handleCheck)
	mux.HandleFunc("/health", healthHandler)

	addr := ":" + strconv.Itoa(cfg.ListenPort)
	log.Printf("AI Firewall /v1/check adapter listening on %s "+
		"(mask_emails=%v mask_paths=%v vault_limit=%d idle_ttl=%s max_users=%d)",
		addr, cfg.MaskEmails, cfg.MaskPaths, cfg.VaultSizeLimit, idleTTL, maxUsers)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(fmt.Errorf("server error: %w", err))
	}
}
