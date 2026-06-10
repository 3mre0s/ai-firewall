package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockVaultStatsProvider implements VaultStatsProvider for testing.
type mockVaultStatsProvider struct {
	current   int
	limit     int
	totalHits int64
}

func (m *mockVaultStatsProvider) Stats() VaultStats {
	return VaultStats{
		Current:   m.current,
		Limit:     m.limit,
		TotalHits: m.totalHits,
	}
}

func TestCountersIncrement(t *testing.T) {
	t.Parallel()

	c := &Counters{}

	c.IncRequests()
	c.IncStreamRequests()
	c.IncMaskedItems(3)
	c.IncMaskedRequests()
	c.IncUnmaskedItems(2)
	c.IncUpstreamErrors()
	c.IncVaultEvictions()

	snap := c.Snapshot(nil)

	if snap.RequestsTotal != 1 {
		t.Errorf("expected RequestsTotal to be 1, got %d", snap.RequestsTotal)
	}
	if snap.StreamRequests != 1 {
		t.Errorf("expected StreamRequests to be 1, got %d", snap.StreamRequests)
	}
	if snap.MaskedItems != 3 {
		t.Errorf("expected MaskedItems to be 3, got %d", snap.MaskedItems)
	}
	if snap.MaskedRequests != 1 {
		t.Errorf("expected MaskedRequests to be 1, got %d", snap.MaskedRequests)
	}
	if snap.UnmaskedItems != 2 {
		t.Errorf("expected UnmaskedItems to be 2, got %d", snap.UnmaskedItems)
	}
	if snap.UpstreamErrors != 1 {
		t.Errorf("expected UpstreamErrors to be 1, got %d", snap.UpstreamErrors)
	}
	if snap.VaultEvictions != 1 {
		t.Errorf("expected VaultEvictions to be 1, got %d", snap.VaultEvictions)
	}
	if snap.MaskRate != "100.00%" {
		t.Errorf("expected MaskRate to be 100.00%%, got %s", snap.MaskRate)
	}
}

func TestSnapshotWithVault(t *testing.T) {
	t.Parallel()

	c := &Counters{}
	c.IncRequests()
	c.IncRequests()       // 2 requests
	c.IncMaskedRequests() // 1 masked request -> 50% mask rate

	mockVault := &mockVaultStatsProvider{
		current:   5,
		limit:     10,
		totalHits: 42,
	}

	snap := c.Snapshot(mockVault)

	if snap.MaskRate != "50.00%" {
		t.Errorf("expected MaskRate to be 50.00%%, got %s", snap.MaskRate)
	}
	if snap.VaultCurrent != 5 {
		t.Errorf("expected VaultCurrent to be 5, got %d", snap.VaultCurrent)
	}
	if snap.VaultLimit != 10 {
		t.Errorf("expected VaultLimit to be 10, got %d", snap.VaultLimit)
	}
	if snap.VaultFillPct != "50.00%" {
		t.Errorf("expected VaultFillPct to be 50.00%%, got %s", snap.VaultFillPct)
	}
	if snap.VaultHits != 42 {
		t.Errorf("expected VaultHits to be 42, got %d", snap.VaultHits)
	}
}

func TestMetricsHandler(t *testing.T) {
	t.Parallel()

	c := &Counters{}
	c.IncRequests()

	mockVault := &mockVaultStatsProvider{
		current:   2,
		limit:     100,
		totalHits: 3,
	}

	handler := c.Handler(mockVault)
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("handler returned wrong content type: got %v want %v", contentType, "application/json")
	}

	var data map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &data)
	if err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	// Verify key fields
	if reqs, ok := data["requests_total"].(float64); !ok || reqs != 1 {
		t.Errorf("expected requests_total to be 1, got %v", data["requests_total"])
	}
	if current, ok := data["vault_current"].(float64); !ok || current != 2 {
		t.Errorf("expected vault_current to be 2, got %v", data["vault_current"])
	}
	if limit, ok := data["vault_limit"].(float64); !ok || limit != 100 {
		t.Errorf("expected vault_limit to be 100, got %v", data["vault_limit"])
	}
	if fill, ok := data["vault_fill_pct"].(string); !ok || fill != "2.00%" {
		t.Errorf("expected vault_fill_pct to be 2.00%%, got %v", data["vault_fill_pct"])
	}
}
