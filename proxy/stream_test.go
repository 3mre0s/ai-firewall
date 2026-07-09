package proxy

import (
	"strings"
	"testing"

	"github.com/3mre0s/ai_firewall/config"
	"github.com/3mre0s/ai_firewall/masker"
	"github.com/3mre0s/ai_firewall/vault"
)

// newTestMaskerWithVault creates a Masker and returns both, so the test can
// inspect the vault directly.
func newTestMaskerWithVault(vaultLimit int) (*masker.Masker, *vault.Vault) {
	v := vault.New(vaultLimit)
	cfg := config.LoadForTest()
	return masker.New(v, cfg), v
}

// TestStreamProcessorSplitChunk verifies that the streamProcessor correctly
// handles vault labels that are split across two consecutive network chunks.
//
// Scenario (senaryo):
//
//	chunk1: "Here is the value: [[SECRET_"
//	chunk2: "A4F0C8B2D9E1F203445566778899AABB]] — use wisely."
//
// The label [[SECRET_A4F0C8B2D9E1F203445566778899AABB]] must be fully unmasked
// in the output. Labels are 32 hex digits — the format emitted by generateLabel.
// (Etiket çıktıda tam olarak maskelenmemiş olmalı. Etiketler 32 onaltılık
// basamaktır — generateLabel'ın ürettiği biçim.)
func TestStreamProcessorSplitChunk(t *testing.T) {
	t.Parallel()

	m, v := newTestMaskerWithVault(1000)
	original := "super-secret-value-42"

	// Manually plant a label in the vault.
	// (Etiketi vault'a elle yerleştir.)
	label := "[[SECRET_A4F0C8B2D9E1F203445566778899AABB]]"
	if err := v.Store(label, original); err != nil {
		t.Fatalf("vault.Store: %v", err)
	}

	proc := NewStreamProcessor(m)

	chunk1 := []byte("Here is the value: [[SECRET_")
	chunk2 := []byte("A4F0C8B2D9E1F203445566778899AABB]] — use wisely.")

	out1 := proc.Process(chunk1)
	out2 := proc.Process(chunk2)
	tail := proc.Flush()

	combined := out1 + out2 + tail

	if strings.Contains(combined, label) {
		t.Errorf("[FAIL] split-chunk: label %q was not unmasked in combined output\n"+
			"  combined: %q", label, combined)
	}
	if !strings.Contains(combined, original) {
		t.Errorf("[FAIL] split-chunk: original value %q missing from combined output\n"+
			"  combined: %q", original, combined)
	}
	if !strings.Contains(combined, "Here is the value:") {
		t.Errorf("[FAIL] split-chunk: surrounding context was corrupted\n"+
			"  combined: %q", combined)
	}
}

// TestStreamProcessorMultipleSplits tests a chain of labels, some crossing
// chunk boundaries, some within a single chunk.
// (Bazıları chunk sınırlarını aşan, bazıları tek chunk içinde kalan
//
//	bir etiket zincirini test eder.)
func TestStreamProcessorMultipleSplits(t *testing.T) {
	t.Parallel()

	m, v := newTestMaskerWithVault(1000)
	labels := map[string]string{
		"[[LABEL_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA]]": "value-alpha",
		"[[LABEL_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB]]": "value-beta",
		"[[LABEL_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC]]": "value-gamma",
	}
	for lbl, val := range labels {
		if err := v.Store(lbl, val); err != nil {
			t.Fatalf("vault.Store(%q): %v", lbl, err)
		}
	}

	// Build an SSE-like response with labels at various positions.
	// Then split it at arbitrary byte positions to simulate network chunking.
	// (Etiketlerin çeşitli konumlarda olduğu SSE benzeri bir yanıt oluştur.
	//  Ardından ağ parçalamasını simüle etmek için rastgele bayt konumlarında böl.)
	full := "start [[LABEL_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA]] middle " +
		"[[LABEL_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB]] end " +
		"[[LABEL_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC]] done"

	// Split at byte 20 (inside label A) and 60 (inside label B) to guarantee
	// cross-boundary labels.
	// (Sınır ötesi etiketleri garanti etmek için 20. baytta (A etiketinin içi)
	//  ve 60. baytta (B etiketinin içi) böl.)
	proc := NewStreamProcessor(m)
	parts := [][]byte{
		[]byte(full[:20]),
		[]byte(full[20:60]),
		[]byte(full[60:]),
	}

	var sb strings.Builder
	for _, p := range parts {
		sb.WriteString(proc.Process(p))
	}
	sb.WriteString(proc.Flush())
	result := sb.String()

	for lbl, val := range labels {
		if strings.Contains(result, lbl) {
			t.Errorf("[FAIL] multi-split: label %q not unmasked in result: %q", lbl, result)
		}
		if !strings.Contains(result, val) {
			t.Errorf("[FAIL] multi-split: value %q missing from result: %q", val, result)
		}
	}
}

// TestStreamProcessorNoLabels verifies that plain text without any labels
// passes through unchanged.
// (Hiçbir etiket içermeyen düz metnin değişmeden geçtiğini doğrular.)
func TestStreamProcessorNoLabels(t *testing.T) {
	t.Parallel()

	cfg := config.LoadForTest()
	v := vault.New(1000)
	m := masker.New(v, cfg)
	proc := NewStreamProcessor(m)

	plain := "This is a perfectly normal SSE stream with no labels at all."
	out := proc.Process([]byte(plain))
	tail := proc.Flush()

	if got := out + tail; got != plain {
		t.Errorf("[FAIL] no-labels: got %q, want %q", got, plain)
	}
}
