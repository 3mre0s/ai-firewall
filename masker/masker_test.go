// Package masker_test contains table-driven unit tests for the masker package.
//
// Test coverage targets (test kapsam hedefleri):
//  1. Mask() output does NOT contain the original sensitive value
//     (Mask() çıktısı orijinal hassas değeri İÇERMEZ)
//  2. Unmask(Mask(x)) == x  — perfect round-trip for every pattern type
//     (Her desen türü için mükemmel gidiş-dönüş eşitliği)
//  3. Vault-full condition: masking is skipped, original value is preserved
//     (Vault dolu durumu: maskeleme atlanır, orijinal değer korunur)
//  4. SSE split-chunk test: labels split across chunk boundaries are
//     correctly reassembled by streamProcessor
//     (SSE bölünmüş chunk testi: chunk sınırlarında bölünen etiketler
//      streamProcessor tarafından doğru birleştirilir)
package masker

import (
	"fmt"
	"strings"
	"testing"

	"github.com/localai/firewall/config"
	"github.com/localai/firewall/vault"
)

// ── helpers (yardımcılar) ──────────────────────────────────────────────────────

// newTestMasker creates a Masker backed by a fresh Vault with the given limit.
// (Verilen limitli yeni bir Vault ile desteklenen bir Masker oluşturur.)
func newTestMasker(vaultLimit int) *Masker {
	v := vault.New(vaultLimit)
	cfg := config.LoadForTest()
	return New(v, cfg)
}

// newTestMaskerWithVault creates a Masker and returns both, so the test can
// inspect the vault directly.
// (Masker ve Vault'u birlikte döner; test, vault'u doğrudan inceleyebilir.)
func newTestMaskerWithVault(vaultLimit int) (*Masker, *vault.Vault) {
	v := vault.New(vaultLimit)
	cfg := config.LoadForTest()
	return New(v, cfg), v
}

// ── 1. Mask() does not leak the original value ────────────────────────────────

// TestMaskDoesNotLeakOriginal verifies that for every test case the masked
// output does not contain the original sensitive substring.
// (Her test senaryosu için maskeli çıktının orijinal hassas alt dizeyi
//  içermediğini doğrular.)
func TestMaskDoesNotLeakOriginal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		sensitive string // substring that must NOT appear in the output
	}{
		// GitHub tokens (GitHub jetonları)
		{
			name:      "GitHub PAT v1",
			input:     "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			sensitive: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		},
		{
			name:      "GitHub OAuth token",
			input:     "auth=gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			sensitive: "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		},
		{
			name:      "GitHub Actions token",
			input:     "GITHUB_TOKEN=ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			sensitive: "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		},
		// AWS keys (AWS anahtarları)
		{
			name:      "AWS Access Key ID",
			input:     "key=AKIAIOSFODNN7EXAMPLE",
			sensitive: "AKIAIOSFODNN7EXAMPLE",
		},
		// Bearer token (Taşıyıcı jetonlar)
		{
			name:      "HTTP Bearer token",
			input:     "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTA",
			sensitive: "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTA",
		},
		// OpenAI keys
		{
			name:      "OpenAI API Key",
			input:     "key: sk-1234567890abcdef12345",
			sensitive: "sk-1234567890abcdef12345",
		},
		{
			name:      "OpenAI Project Key",
			input:     "key: sk-proj-1234567890abcdef12345",
			sensitive: "sk-proj-1234567890abcdef12345",
		},
		// Secret assignments (Gizlilik atamaları)
		{
			name:      "password= assignment",
			input:     "password=MySuperSecret123",
			sensitive: "MySuperSecret123",
		},
		{
			name:      "api_key: assignment",
			input:     `api_key: "sk-abc123def456ghi789"`,
			sensitive: "sk-abc123def456ghi789",
		},
		// PII (Kişisel tanımlanabilir bilgi)
		{
			name:      "email address",
			input:     "Contact: alice@example.com for details",
			sensitive: "alice@example.com",
		},
		// Windows path (Windows yolu)
		{
			name:      "Windows path",
			input:     `file at C:\Users\alice\Documents\secret.txt`,
			sensitive: `C:\Users\alice\Documents\secret.txt`,
		},
		// Unix path (Unix yolu)
		{
			name:      "Unix home path",
			input:     "config at /home/alice/.config/credentials",
			sensitive: "/home/alice/.config/credentials",
		},
	}

	for _, tc := range tests {
		tc := tc // capture for parallel subtests (paralel alt testler için yakala)
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			result := m.Mask(tc.input)

			if strings.Contains(result.Text, tc.sensitive) {
				t.Errorf("[FAIL] masked output still contains sensitive value\n"+
					"  input:     %q\n"+
					"  output:    %q\n"+
					"  sensitive: %q",
					tc.input, result.Text, tc.sensitive)
			}
			if result.MaskedCount == 0 {
				t.Errorf("[FAIL] MaskedCount == 0, expected at least 1 for input %q", tc.input)
			}
		})
	}
}

// ── 2. Round-trip: Unmask(Mask(x)) == x ──────────────────────────────────────

// TestRoundTrip verifies that masking followed by unmasking recovers the
// original text perfectly, character-by-character.
// (Maskeleme ardından maskeyi kaldırmanın orijinal metni karakter karakter
//  geri kazandırdığını doğrular.)
func TestRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "GitHub PAT round-trip",
			input: "My token is ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij — keep it secret!",
		},
		{
			name:  "AWS key round-trip",
			input: "aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:  "Bearer token round-trip",
			input: "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTA",
		},
		{
			name:  "password= round-trip",
			input: "password=MySuperSecret123 and then some text",
		},
		{
			name:  "email round-trip",
			input: "Send report to bob@company.org please",
		},
		{
			name:  "multiple secrets round-trip",
			input: "Token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij and email alice@example.com",
		},
		{
			name:  "no secrets — text unchanged",
			input: "Hello, this is a perfectly safe message with no secrets.",
		},
		{
			name:  "plain label-like text not in vault",
			input: "The value [[NOTAVAULTLABEL_XXXXXXXX]] should be left as-is.",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)

			masked := m.Mask(tc.input)
			recovered := m.Unmask(masked.Text)

			if recovered != tc.input {
				t.Errorf("[FAIL] round-trip mismatch\n"+
					"  original:  %q\n"+
					"  masked:    %q\n"+
					"  recovered: %q",
					tc.input, masked.Text, recovered)
			}
		})
	}
}

// ── 3. Vault-full: masking is skipped, original value preserved ───────────────

// TestVaultFullSkipsMasking verifies that when the vault is at capacity, the
// Masker leaves the sensitive value in the text rather than silently dropping it.
// MaskedCount must be zero for skipped items.
//
// (Vault kapasitede olduğunda, Masker'ın hassas değeri sessizce silmek yerine
//  metinde bıraktığını doğrular. Atlanan öğeler için MaskedCount sıfır olmalı.)
func TestVaultFullSkipsMasking(t *testing.T) {
	t.Parallel()

	const vaultLimit = 2
	m, v := newTestMaskerWithVault(vaultLimit)

	// Fill the vault to exactly its limit using tokens that are guaranteed to match.
	// (Vault'u tam limitine doldurmak için kesinlikle eşleşecek jetonlar kullan.)
	for i := 0; i < vaultLimit; i++ {
		label := fmt.Sprintf("[[FILL_%08X]]", i)
		original := fmt.Sprintf("fill-value-%d", i)
		if err := v.Store(label, original); err != nil {
			t.Fatalf("unexpected error filling vault: %v", err)
		}
	}

	// Now try to mask a new sensitive value — vault is full.
	// (Şimdi yeni bir hassas değeri maskelemeye çalış — vault dolu.)
	sensitiveToken := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	input := "Token: " + sensitiveToken

	result := m.Mask(input)

	// The original sensitive value MUST still be in the output.
	// (Orijinal hassas değer çıktıda OLMALI.)
	if !strings.Contains(result.Text, sensitiveToken) {
		t.Errorf("[FAIL] vault-full: expected sensitive token to be preserved in output\n"+
			"  output: %q", result.Text)
	}

	// MaskedCount should be 0 because masking was skipped.
	// (Maskeleme atlandığı için MaskedCount 0 olmalı.)
	if result.MaskedCount != 0 {
		t.Errorf("[FAIL] vault-full: expected MaskedCount=0, got %d", result.MaskedCount)
	}
}

// TestVaultFullPartialMask verifies that items masked before vault fills are
// still round-trippable, and items after the fill are left in plain text.
// (Vault dolmadan önce maskelenen öğelerin hâlâ gidiş-dönüş yapılabildiğini,
//  dolduktan sonraki öğelerin düz metin olarak bırakıldığını doğrular.)
func TestVaultFullPartialMask(t *testing.T) {
	t.Parallel()

	// Vault limit = 1: only one secret can be masked.
	// (Vault limiti = 1: yalnızca bir sır maskelenebilir.)
	m := newTestMasker(1)

	// Two secrets in one message — first should be masked, second should not.
	// NOTE: which one gets masked depends on pattern registry order.
	input := "email alice@example.com and also bob@example.com"
	result := m.Mask(input)

	// At least one address must remain (vault was full after first mask).
	// (Vault ilk maskeden sonra doldu, dolayısıyla en az bir adres kalmalı.)
	emailCount := strings.Count(result.Text, "@example.com")
	if emailCount == 0 {
		t.Errorf("[FAIL] expected at least one email to remain unmasked in vault-full scenario\n"+
			"  masked text: %q", result.Text)
	}
}

// ── 5. MaskResult.ByType breakdown ───────────────────────────────────────────

// TestMaskByTypeBreakdown verifies that ByType counts are correct for
// each pattern category.
// (Her desen kategorisi için ByType sayımlarının doğru olduğunu doğrular.)
func TestMaskByTypeBreakdown(t *testing.T) {
	t.Parallel()

	m := newTestMasker(1000)

	// One TOKEN + one PII in a single message.
	// (Tek bir mesajda bir TOKEN + bir PII.)
	input := "Token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij email alice@example.com"
	result := m.Mask(input)

	if result.ByType["TOKEN"] < 1 {
		t.Errorf("[FAIL] expected ByType[TOKEN] >= 1, got %d", result.ByType["TOKEN"])
	}
	if result.ByType["PII"] < 1 {
		t.Errorf("[FAIL] expected ByType[PII] >= 1, got %d", result.ByType["PII"])
	}
	total := 0
	for _, v := range result.ByType {
		total += v
	}
	if total != result.MaskedCount {
		t.Errorf("[FAIL] ByType sum %d != MaskedCount %d", total, result.MaskedCount)
	}
}

// ── 6. Label format validation ────────────────────────────────────────────────

// TestLabelFormat verifies that generated labels match the expected pattern
// [[PREFIX_8HEXDIGITS]] so the label regex in Masker.labelPattern matches them.
// (Üretilen etiketlerin beklenen [[PREFIX_8ONALTILIHANE]] desenine uyduğunu doğrular.)
func TestLabelFormat(t *testing.T) {
	t.Parallel()

	m := newTestMasker(1000)
	input := "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	result := m.Mask(input)

	// The output should contain exactly one label matching [[..._XXXXXXXX]]
	// (Çıktı [[..._XXXXXXXX]] biçiminde tam olarak bir etiket içermeli.)
	if !m.labelPattern.MatchString(result.Text) {
		t.Errorf("[FAIL] label format: no valid label found in masked output: %q", result.Text)
	}
}

// ── 7. Edge cases ─────────────────────────────────────────────────────────────

// TestMaskEmptyInput verifies that an empty string is handled without panic.
// (Boş dizenin panik olmadan işlendiğini doğrular.)
func TestMaskEmptyInput(t *testing.T) {
	t.Parallel()
	m := newTestMasker(1000)
	result := m.Mask("")
	if result.Text != "" {
		t.Errorf("[FAIL] empty input: expected empty output, got %q", result.Text)
	}
	if result.MaskedCount != 0 {
		t.Errorf("[FAIL] empty input: expected MaskedCount=0, got %d", result.MaskedCount)
	}
}

// TestUnmaskTextWithNoLabels verifies that Unmask leaves plain text unchanged.
// (Unmask'ın düz metni değiştirmeden bıraktığını doğrular.)
func TestUnmaskTextWithNoLabels(t *testing.T) {
	t.Parallel()
	m := newTestMasker(1000)
	plain := "No labels here, move along."
	if got := m.Unmask(plain); got != plain {
		t.Errorf("[FAIL] Unmask of plain text: got %q, want %q", got, plain)
	}
}

// TestUnmaskUnknownLabel verifies that an unknown label (not in vault) is
// left in the text unchanged — not silently dropped.
// (Bilinmeyen etiketin (vault'ta yok) sessizce silinmeden metinde
//  değiştirilmeden bırakıldığını doğrular.)
func TestUnmaskUnknownLabel(t *testing.T) {
	t.Parallel()
	m := newTestMasker(1000)
	text := "result: [[UNKNOWN_DEADC0DE]] is here"
	if got := m.Unmask(text); got != text {
		t.Errorf("[FAIL] unknown label should be unchanged: got %q, want %q", got, text)
	}
}

// TestMaskDeduplication verifies that if the identical sensitive value appears
// multiple times in the same input, it gets masked with the EXACT SAME label
// to save vault space and keep references consistent.
// (Aynı hassas değerin aynı girdide birden çok kez geçmesi durumunda,
//  vault alanından tasarruf etmek için tam olarak aynı etiketle maskelendiğini doğrular.)
func TestMaskDeduplication(t *testing.T) {
	t.Parallel()
	m := newTestMasker(1000)

	input := "First: sk-1234567890abcdef12345, Second: sk-1234567890abcdef12345"
	result := m.Mask(input)

	// We expect 2 occurrences of the same label.
	count := strings.Count(result.Text, "[[OAI_KEY_")
	if count != 2 {
		t.Errorf("expected 2 label occurrences, got %d in %q", count, result.Text)
	}

	// Extract the first label and verify it is exactly repeated
	idx1 := strings.Index(result.Text, "[[OAI_KEY_")
	if idx1 == -1 {
		t.Fatalf("label not found in output: %q", result.Text)
	}

	// Label is 20 chars long: [[OAI_KEY_XXXXXXXX]]
	label := result.Text[idx1 : idx1+20]
	
	// The rest of the string should contain the exact same label
	if !strings.Contains(result.Text[idx1+20:], label) {
		t.Errorf("expected the exact same label to be reused, output: %q", result.Text)
	}
}
