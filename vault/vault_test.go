package vault

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestVaultRejectsDuplicateLabel(t *testing.T) {
	t.Parallel()

	v := New(10)
	if err := v.Store("[[LABEL_1]]", "first"); err != nil {
		t.Fatalf("first store failed: %v", err)
	}
	if err := v.Store("[[LABEL_1]]", "second"); !errors.Is(err, ErrLabelExists) {
		t.Fatalf("expected ErrLabelExists, got %v", err)
	}

	value, found := v.Retrieve("[[LABEL_1]]")
	if !found || value != "first" {
		t.Fatalf("duplicate store changed original value: found=%v value=%q", found, value)
	}
}

func TestVaultStoreAndRetrieve(t *testing.T) {
	t.Parallel()

	v := New(10)

	err := v.Store("[[LABEL_1]]", "secret_value_1")
	if err != nil {
		t.Fatalf("unexpected error on store: %v", err)
	}

	val, found := v.Retrieve("[[LABEL_1]]")
	if !found {
		t.Fatalf("expected to find label")
	}
	if val != "secret_value_1" {
		t.Errorf("expected value 'secret_value_1', got %q", val)
	}

	_, found = v.Retrieve("[[LABEL_UNKNOWN]]")
	if found {
		t.Errorf("expected not to find unknown label")
	}
}

func TestVaultLimit(t *testing.T) {
	t.Parallel()

	v := New(2)

	if err := v.Store("[[LABEL_1]]", "val1"); err != nil {
		t.Fatalf("store 1 failed: %v", err)
	}
	if err := v.Store("[[LABEL_2]]", "val2"); err != nil {
		t.Fatalf("store 2 failed: %v", err)
	}

	err := v.Store("[[LABEL_3]]", "val3")
	if err == nil {
		t.Errorf("expected error when storing beyond limit")
	}
}

func TestVaultReset(t *testing.T) {
	t.Parallel()

	v := New(10)
	v.Store("[[LABEL_1]]", "val1")
	v.Reset()

	stats := v.Stats()
	if stats.Current != 0 {
		t.Errorf("expected 0 entries after reset, got %d", stats.Current)
	}

	_, found := v.Retrieve("[[LABEL_1]]")
	if found {
		t.Errorf("expected label to be gone after reset")
	}
}

func TestVaultStatsAndHits(t *testing.T) {
	t.Parallel()

	v := New(10)
	v.Store("[[LABEL_1]]", "val1")
	v.Store("[[LABEL_2]]", "val2")

	v.Retrieve("[[LABEL_1]]")
	v.Retrieve("[[LABEL_1]]")
	v.Retrieve("[[LABEL_2]]")

	stats := v.Stats()
	if stats.Current != 2 {
		t.Errorf("expected current = 2, got %d", stats.Current)
	}
	if stats.Limit != 10 {
		t.Errorf("expected limit = 10, got %d", stats.Limit)
	}
	if stats.TotalHits != 3 {
		t.Errorf("expected total hits = 3, got %d", stats.TotalHits)
	}
}

func TestVaultConcurrency(t *testing.T) {
	t.Parallel()

	v := New(1000)
	const numGoroutines = 50
	const opsPerGoroutine = 20

	var wg sync.WaitGroup

	// Concurrently store
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(gID int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				label := fmt.Sprintf("[[LABEL_%d_%d]]", gID, j)
				val := fmt.Sprintf("val_%d_%d", gID, j)
				v.Store(label, val)
			}
		}(i)
	}
	wg.Wait()

	// Concurrently retrieve and test stats
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(gID int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				label := fmt.Sprintf("[[LABEL_%d_%d]]", gID, j)
				expected := fmt.Sprintf("val_%d_%d", gID, j)
				val, found := v.Retrieve(label)
				if !found || val != expected {
					t.Errorf("concurrency mismatch for %s: got %q (found=%v) want %q", label, val, found, expected)
				}
			}
		}(i)
	}
	wg.Wait()

	stats := v.Stats()
	expectedEntries := numGoroutines * opsPerGoroutine
	if stats.Current != expectedEntries {
		t.Errorf("expected %d entries, got %d", expectedEntries, stats.Current)
	}
	if stats.TotalHits != int64(expectedEntries) {
		t.Errorf("expected %d hits, got %d", expectedEntries, stats.TotalHits)
	}
}
