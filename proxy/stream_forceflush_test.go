package proxy

import (
	"strings"
	"testing"
)

// TestStreamProcessorForceFlushNoSecretLeak verifies the security-critical
// invariant of the force-flush path: when the rolling buffer exceeds
// maxStreamBufBytes while a label is still incomplete, the buffer is flushed
// WITHOUT the real secret ever appearing in the output. Only the inert,
// half-formed placeholder skeleton ("[[SECRET_") may leak — never the value.
//
// (Force-flush yolunun güvenlik açısından kritik değişmezini doğrular:
//
//	rolling buffer, bir etiket henüz tamamlanmamışken maxStreamBufBytes'ı
//	aşarsa, buffer GERÇEK SIR çıktıya hiç çıkmadan flush edilir. Yalnızca
//	etkisiz, yarım placeholder iskeleti sızabilir — asla gerçek değer.)
func TestStreamProcessorForceFlushNoSecretLeak(t *testing.T) {
	t.Parallel()

	m, v := newTestMaskerWithVault(1000)
	secret := "super-secret-value-42"
	label := "[[SECRET_A4F0C8B2]]"
	if err := v.Store(label, secret); err != nil {
		t.Fatalf("vault.Store: %v", err)
	}

	proc := NewStreamProcessor(m)

	var out strings.Builder
	// 1) Yarım etiket başlangıcı buffer'a girer ("[[SECRET_" ama "]]" yok).
	//    (A half-open label enters the buffer.)
	out.WriteString(proc.Process([]byte("value here: [[SECRET_")))

	// 2) Etiketi TAMAMLAMADAN maxStreamBufBytes'ı aşan büyük bir gövde akar.
	//    Bu, force-flush dalını tetikler.
	big := strings.Repeat("X", maxStreamBufBytes+64*1024)
	out.WriteString(proc.Process([]byte(big)))

	// 3) Akış sonu.
	out.WriteString(proc.Flush())
	result := out.String()

	// KRİTİK değişmez: gerçek sır değeri çıktıya ASLA sızmamalı.
	if strings.Contains(result, secret) {
		t.Errorf("[FAIL] force-flush: real secret %q leaked into client output", secret)
	}

	// Force-flush dalının gerçekten tetiklendiğini doğrula.
	if len(result) < maxStreamBufBytes {
		t.Errorf("[FAIL] force-flush: expected flushed output >= %d bytes, got %d "+
			"(force-flush branch may not have triggered)", maxStreamBufBytes, len(result))
	}
}

// TestStreamProcessorForceFlushThenComplete verifies that after a force-flush
// drops a half-formed label, the processor recovers cleanly and continues to
// correctly unmask subsequent, fully-formed labels.
//
// (Force-flush yarım bir etiketi düşürdükten sonra işlemcinin temiz biçimde
//
//	toparlandığını ve sonraki TAM etiketleri doğru çözmeye devam ettiğini
//	doğrular.)
func TestStreamProcessorForceFlushThenComplete(t *testing.T) {
	t.Parallel()

	m, v := newTestMaskerWithVault(1000)
	good := "recoverable-value-99"
	goodLabel := "[[SECRET_BBBBBBBB]]"
	if err := v.Store(goodLabel, good); err != nil {
		t.Fatalf("vault.Store: %v", err)
	}

	proc := NewStreamProcessor(m)

	var out strings.Builder
	// Force-flush'ı tetikle: yarım etiket + dev gövde.
	out.WriteString(proc.Process([]byte("start [[SECRET_")))
	out.WriteString(proc.Process([]byte(strings.Repeat("Y", maxStreamBufBytes+1024))))

	// Akış toparlanır ve SONRA tam bir etiket gelir.
	out.WriteString(proc.Process([]byte(" then a clean " + goodLabel + " here")))
	out.WriteString(proc.Flush())
	result := out.String()

	// Force-flush sonrası gelen tam etiket doğru çözülmeli.
	if !strings.Contains(result, good) {
		t.Errorf("[FAIL] post-force-flush recovery: value %q not unmasked; "+
			"processor did not recover. tail=%q", good, lastN(result, 80))
	}
	if strings.Contains(result, goodLabel) {
		t.Errorf("[FAIL] post-force-flush recovery: label %q left unresolved", goodLabel)
	}
}

// lastN returns up to the last n bytes of s, for compact failure messages.
func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}
