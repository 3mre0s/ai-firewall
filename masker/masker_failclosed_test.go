// Fail-closed behaviour tests for label generation.
//
// A crypto/rand failure must never produce a deterministic label: that would
// make every secret share one label, corrupting the vault and Unmask output.
// Instead Mask() must leave the value unmasked AND report it via
// VaultEvictions so the proxy blocks the request (507) rather than forwarding
// plaintext secrets upstream.
//
// (crypto/rand hatası asla deterministik bir etiket üretmemelidir: bu, her
// sırrın aynı etiketi paylaşmasına, vault'un ve Unmask çıktısının bozulmasına
// yol açar. Bunun yerine Mask() değeri maskesiz bırakmalı VE VaultEvictions
// üzerinden bildirmelidir; böylece proxy, düz metin sırları iletmek yerine
// isteği 507 ile engeller.)
package masker

import (
	"errors"
	"strings"
	"testing"
)

// failRandRead replaces the package-level randRead hook for the duration of
// the test, simulating total entropy failure. The test must NOT call
// t.Parallel(): it mutates package-global state.
// (Test süresince paket düzeyindeki randRead kancasını değiştirerek tam entropi
// arızasını simüle eder. Test t.Parallel() çağırmamalıdır: paket-geneli durumu
// değiştirir.)
func failRandRead(t *testing.T) {
	t.Helper()
	orig := randRead
	randRead = func(b []byte) (int, error) {
		return 0, errors.New("simulated entropy failure")
	}
	t.Cleanup(func() { randRead = orig })
}

func TestGenerateLabel_RandFailureReturnsError(t *testing.T) {
	failRandRead(t)

	label, err := generateLabel("SECRET")
	if err == nil {
		t.Fatalf("expected error on entropy failure, got label %q", label)
	}
	if label != "" {
		t.Fatalf("expected empty label on entropy failure, got %q", label)
	}
}

func TestMask_RandFailureFailsClosed(t *testing.T) {
	failRandRead(t)

	m := newTestMasker(100)
	input := "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"

	result := m.Mask(input)

	// The secret must remain in the text (it could not be masked)...
	// (Sır metinde kalmalı — maskelenemedi...)
	if !strings.Contains(result.Text, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij") {
		t.Errorf("secret unexpectedly altered without a valid label: %q", result.Text)
	}
	// ...and no deterministic fallback label may appear.
	// (...ve deterministik bir yedek etiket görünmemeli.)
	if strings.Contains(result.Text, "DEADC0DE") || strings.Contains(result.Text, "[[") {
		t.Errorf("deterministic/partial label leaked into output: %q", result.Text)
	}
	// ...and the failure must be reported so the caller blocks the request.
	// (...ve çağıranın isteği engellemesi için hata raporlanmalı.)
	if result.VaultEvictions == 0 {
		t.Error("expected VaultEvictions > 0 so the proxy blocks the request (fail-closed)")
	}
	if result.MaskedCount != 0 {
		t.Errorf("expected MaskedCount == 0, got %d", result.MaskedCount)
	}
}
