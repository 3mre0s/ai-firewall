// Tests for the Open WebUI /v1/check adapter. They exercise the adapter's thin
// glue over the real engine (masker + vault) plus the adapter-layer per-user
// vault isolation — no detection/masking logic is re-implemented here.
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/3mre0s/ai_firewall/config"
	"github.com/3mre0s/ai_firewall/masker"
	"github.com/3mre0s/ai_firewall/vault"
)

// newTestMasker builds a single masker backed by a fresh vault of the given
// size, for tests that exercise the direction handlers directly.
func newTestMasker(t *testing.T, vaultLimit int) *masker.Masker {
	t.Helper()
	cfg := config.LoadForTest()
	return masker.New(vault.New(vaultLimit), cfg)
}

// newTestStore builds a per-user store; each user gets a vault of vaultLimit.
func newTestStore(t *testing.T, vaultLimit int, idleTTL time.Duration, maxUsers int) *userStore {
	t.Helper()
	cfg := config.LoadForTest()
	cfg.VaultSizeLimit = vaultLimit
	return newUserStore(cfg, idleTTL, maxUsers)
}

// A valid-length GitHub PAT (ghp_ + 36 alphanumerics) that the registry masks.
const ghToken = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"

// ── Allowed: benign content passes with no matches ────────────────────────────

func TestInletAllowedNoSecrets(t *testing.T) {
	m := newTestMasker(t, 100)
	resp := checkInlet(m, "what is the weather like today in Ankara?")

	if !resp.Allowed {
		t.Fatalf("expected allowed=true, got false (reason=%q)", resp.Reason)
	}
	if len(resp.Matches) != 0 {
		t.Errorf("expected no matches, got %v", resp.Matches)
	}
	if resp.MaskedContent != "" {
		t.Errorf("expected no masked_content for benign input, got %q", resp.MaskedContent)
	}
}

// ── Masked: PII in the prompt is masked and reported, never leaked ────────────

func TestInletMasksEmail(t *testing.T) {
	m := newTestMasker(t, 100)
	email := "alice@example.com"
	resp := checkInlet(m, "please email me at "+email)

	if !resp.Allowed {
		t.Fatalf("expected allowed=true, got false (reason=%q)", resp.Reason)
	}
	if resp.MaskedContent == "" {
		t.Fatal("expected masked_content to be set")
	}
	if strings.Contains(resp.MaskedContent, email) {
		t.Errorf("masked_content must NOT contain the raw email; got %q", resp.MaskedContent)
	}
	if !hasMatchType(resp.Matches, "pii") {
		t.Errorf("expected a 'pii' match, got %v", resp.Matches)
	}
}

// ── Blocked (fail-closed): vault full → masking cannot complete ───────────────

func TestInletBlockedVaultFull(t *testing.T) {
	// Vault of size 1: the first secret masks, the second cannot be stored,
	// producing a vault eviction — the engine's fail-closed block condition.
	m := newTestMasker(t, 1)
	content := "token one " + ghToken + " and token two gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	resp := checkInlet(m, content)

	if resp.Allowed {
		t.Fatal("expected allowed=false when the vault is full")
	}
	if resp.Reason != "masking_failed_vault_full" {
		t.Errorf("expected reason=masking_failed_vault_full, got %q", resp.Reason)
	}
	if len(resp.Matches) == 0 {
		t.Error("expected matches to report what was detected even when blocked")
	}
}

// ── Blocked: outlet leak — a raw secret in the model reply ────────────────────

func TestOutletBlocksRawSecretLeak(t *testing.T) {
	m := newTestMasker(t, 100)
	resp := checkOutlet(m, "sure, here is the api key: "+ghToken)

	if resp.Allowed {
		t.Fatal("expected allowed=false for a raw secret in model output")
	}
	if resp.Reason != "secret_leak_in_output" {
		t.Errorf("expected reason=secret_leak_in_output, got %q", resp.Reason)
	}
	if !hasMatchType(resp.Matches, "token") {
		t.Errorf("expected a 'token' match, got %v", resp.Matches)
	}
}

// ── Round-trip: mask on inlet, restore on outlet via the SAME vault ───────────

func TestInletOutletRestoreRoundTrip(t *testing.T) {
	m := newTestMasker(t, 100)
	email := "bob@example.com"

	in := checkInlet(m, "reach me at "+email)
	if in.MaskedContent == "" {
		t.Fatal("expected inlet to produce masked_content")
	}

	out := checkOutlet(m, in.MaskedContent)
	if !out.Allowed {
		t.Fatalf("expected outlet allowed=true for label-only content, got reason=%q", out.Reason)
	}
	if out.RestoredContent == "" {
		t.Fatal("expected restored_content to be set")
	}
	if !strings.Contains(out.RestoredContent, email) {
		t.Errorf("expected restored_content to contain the original email, got %q", out.RestoredContent)
	}
	if out.Matches == nil {
		t.Error("expected non-nil (empty) matches slice on the allow path")
	}
}

// ── Per-user isolation: one user's label must NOT restore for another ─────────

func TestPerUserVaultIsolation(t *testing.T) {
	st := newTestStore(t, 100, time.Hour, 10)

	alice, err := st.get("alice")
	if err != nil {
		t.Fatalf("get(alice): %v", err)
	}
	secret := "secret@corp.com"
	in := checkInlet(alice, "mail me at "+secret)
	label := in.MaskedContent
	if label == "" || strings.Contains(label, secret) {
		t.Fatalf("alice inlet did not mask: %q", label)
	}

	// Control: alice CAN restore her own label.
	aliceOut := checkOutlet(alice, label)
	if !strings.Contains(aliceOut.RestoredContent, secret) {
		t.Fatalf("alice should restore her own value; got %q", aliceOut.RestoredContent)
	}

	// Replay alice's EXACT label string through bob's isolated vault.
	bob, err := st.get("bob")
	if err != nil {
		t.Fatalf("get(bob): %v", err)
	}
	bobOut := checkOutlet(bob, label)
	if !bobOut.Allowed {
		t.Fatalf("expected bob outlet allowed=true, got reason=%q", bobOut.Reason)
	}
	if strings.Contains(bobOut.RestoredContent, secret) {
		t.Errorf("ISOLATION BREACH: bob restored alice's value: %q", bobOut.RestoredContent)
	}
	// Bob's vault does not know the label, so nothing is restored (unchanged).
	if bobOut.RestoredContent != "" {
		t.Errorf("expected empty restored_content for unknown label, got %q", bobOut.RestoredContent)
	}
}

// ── Missing user: rejected with 400 + machine-readable reason ─────────────────

func TestMissingUserRejected(t *testing.T) {
	e := &engine{store: newTestStore(t, 100, time.Hour, 10)}

	for _, body := range []string{
		`{"content":"hello","direction":"inlet"}`,              // no user field
		`{"content":"hello","user":"   ","direction":"inlet"}`, // whitespace-only
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body))
		rec := httptest.NewRecorder()
		e.handleCheck(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: expected 400, got %d", body, rec.Code)
		}
		var resp checkResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("body %s: invalid JSON: %v", body, err)
		}
		if resp.Allowed || resp.Reason != "missing_user_identifier" {
			t.Errorf("body %s: expected blocked missing_user_identifier, got %+v", body, resp)
		}
	}
}

// ── TTL eviction: an idle user's vault is dropped on the next access ──────────

func TestTTLEviction(t *testing.T) {
	st := newTestStore(t, 100, 100*time.Millisecond, 10)

	// Deterministic clock — no real sleeping.
	cur := time.Now()
	st.now = func() time.Time { return cur }

	alice, _ := st.get("alice")
	in := checkInlet(alice, "mail me at ghost@corp.com")
	if in.MaskedContent == "" {
		t.Fatal("expected alice to mask")
	}
	if st.size() != 1 {
		t.Fatalf("expected 1 user, got %d", st.size())
	}

	// Advance the clock past the idle TTL, then touch a different user.
	cur = cur.Add(500 * time.Millisecond)
	if _, err := st.get("bob"); err != nil {
		t.Fatalf("get(bob): %v", err)
	}

	// Alice must have been evicted (bob remains) → size stays 1.
	if st.size() != 1 {
		t.Errorf("expected alice evicted leaving 1 user, got %d", st.size())
	}

	// Re-getting alice yields a FRESH vault: her old label no longer restores.
	alice2, _ := st.get("alice")
	out := checkOutlet(alice2, in.MaskedContent)
	if strings.Contains(out.RestoredContent, "ghost@corp.com") {
		t.Errorf("evicted vault should not restore old label; got %q", out.RestoredContent)
	}
}

// ── Capacity: admitting a new user past the cap fails closed ──────────────────

func TestVaultCapacityExceeded(t *testing.T) {
	st := newTestStore(t, 100, time.Hour, 1) // room for exactly one user

	if _, err := st.get("alice"); err != nil {
		t.Fatalf("first user should be admitted: %v", err)
	}
	if _, err := st.get("bob"); err == nil {
		t.Fatal("expected errVaultCapacity for the second user")
	}
	// An existing user is still served even when at capacity.
	if _, err := st.get("alice"); err != nil {
		t.Errorf("existing user should still be served at capacity: %v", err)
	}

	// End-to-end: the HTTP layer surfaces the machine-readable reason.
	e := &engine{store: st}
	req := httptest.NewRequest(http.MethodPost, "/v1/check",
		strings.NewReader(`{"content":"hi","user":"carol","direction":"inlet"}`))
	rec := httptest.NewRecorder()
	e.handleCheck(rec, req)
	var resp checkResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Allowed || resp.Reason != "vault_capacity_exceeded" {
		t.Errorf("expected vault_capacity_exceeded block, got %+v", resp)
	}
}

// ── HTTP contract: the endpoint returns "matches":[] (not null) ───────────────

func TestHandleCheckHTTPContract(t *testing.T) {
	e := &engine{store: newTestStore(t, 100, time.Hour, 10)}
	req := httptest.NewRequest(http.MethodPost, "/v1/check",
		strings.NewReader(`{"content":"a perfectly normal sentence","user":"dave","direction":"inlet"}`))
	rec := httptest.NewRecorder()
	e.handleCheck(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"matches":[]`) {
		t.Errorf("expected matches to serialise as [], got body: %s", rec.Body.String())
	}
	var resp checkResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected allowed=true, got false (reason=%q)", resp.Reason)
	}
}

func TestHandleCheckRejectsGET(t *testing.T) {
	e := &engine{store: newTestStore(t, 100, time.Hour, 10)}
	req := httptest.NewRequest(http.MethodGet, "/v1/check", nil)
	rec := httptest.NewRecorder()
	e.handleCheck(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", rec.Code)
	}
}

// hasMatchType reports whether any match carries the given lower-cased category.
func hasMatchType(matches []match, typ string) bool {
	for _, m := range matches {
		if m.Type == typ {
			return true
		}
	}
	return false
}
