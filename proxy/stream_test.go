package proxy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/3mre0s/ai-firewall/config"
	"github.com/3mre0s/ai-firewall/masker"
	"github.com/3mre0s/ai-firewall/vault"
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
//	chunk2: "A4F0C8B2]] — use wisely."
//
// The label [[SECRET_A4F0C8B2]] must be fully unmasked in the output.
// (Etiket [[SECRET_A4F0C8B2]] çıktıda tam olarak maskelenmemiş olmalı.)
func TestStreamProcessorSplitChunk(t *testing.T) {
	t.Parallel()

	m, v := newTestMaskerWithVault(1000)
	original := "super-secret-value-42"

	// Manually plant a label in the vault.
	// (Etiketi vault'a elle yerleştir.)
	label := "[[SECRET_A4F0C8B2]]"
	if err := v.Store(label, original); err != nil {
		t.Fatalf("vault.Store: %v", err)
	}

	proc := NewStreamProcessor(m)

	chunk1 := []byte("Here is the value: [[SECRET_")
	chunk2 := []byte("A4F0C8B2]] — use wisely.")

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
		"[[LABEL_AAAAAAAA]]": "value-alpha",
		"[[LABEL_BBBBBBBB]]": "value-beta",
		"[[LABEL_CCCCCCCC]]": "value-gamma",
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
	full := "start [[LABEL_AAAAAAAA]] middle [[LABEL_BBBBBBBB]] end [[LABEL_CCCCCCCC]] done"

	// Split at byte 15 and 45 to guarantee cross-boundary labels.
	// (Sınır ötesi etiketleri garanti etmek için 15. ve 45. baytta böl.)
	proc := NewStreamProcessor(m)
	parts := [][]byte{
		[]byte(full[:15]),
		[]byte(full[15:45]),
		[]byte(full[45:]),
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

func TestStreamProcessorRestoresPlaceholderAtEveryBoundary(t *testing.T) {
	m, _ := newTestMaskerWithVault(10)
	secret := "ghp_FAKEBOUNDARY000000000000000000000000"
	result := m.Mask(secret)
	if len(result.Detections) != 1 {
		t.Fatalf("detections = %#v", result.Detections)
	}
	label := result.Detections[0].PlaceholderID
	want := "prefix " + secret + " suffix"

	for boundary := 1; boundary < len(label); boundary++ {
		t.Run(fmt.Sprintf("byte_%d", boundary), func(t *testing.T) {
			processor := NewStreamProcessor(m)
			var got strings.Builder
			got.WriteString(processor.Process([]byte("prefix " + label[:boundary])))
			got.WriteString(processor.Process([]byte(label[boundary:] + " suffix")))
			got.WriteString(processor.Flush())
			if processor.LeakDetected() {
				t.Fatal("placeholder split was classified as a leak")
			}
			if processor.RestoredCount() != 1 {
				t.Fatalf("RestoredCount = %d, want 1", processor.RestoredCount())
			}
			if got.String() != want {
				t.Fatalf("restored stream = %q, want %q", got.String(), want)
			}
		})
	}
}
