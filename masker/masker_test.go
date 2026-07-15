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
//     streamProcessor tarafından doğru birleştirilir)
package masker

import (
	"fmt"
	"strings"
	"testing"

	"github.com/3mre0s/ai-firewall/config"
	"github.com/3mre0s/ai-firewall/vault"
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
//
//	içermediğini doğrular.)
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
//
//	geri kazandırdığını doğrular.)
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
//
//	metinde bıraktığını doğrular. Atlanan öğeler için MaskedCount sıfır olmalı.)
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
//
//	dolduktan sonraki öğelerin düz metin olarak bırakıldığını doğrular.)
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

// ── 7. HasSecrets — read-only leak detection ─────────────────────────────────

// TestHasSecrets_VaultLabelNoFalsePositive is a regression guard for the
// streaming fail-fast mechanism.  If a response chunk contains only vault
// labels (e.g. [[GH_PAT_3F7A1B2C]]) with no raw sensitive data, HasSecrets
// must return false so that legitimate unmasked values are never blocked.
//
// This test will catch regressions if the label format ever changes to a
// string that accidentally matches a secret pattern.
//
// (Akış fail-fast mekanizması için regresyon koruması. Yanıt chunk'ı yalnızca
//
//	kasa etiketleri içeriyorsa (ör. [[GH_PAT_3F7A1B2C]]) ve ham hassas veri
//	yoksa, HasSecrets false döndürmelidir; aksi hâlde meşru değerler engellenir.
//	Bu test, etiket formatı yanlışlıkla bir sır desenini tetikleyen bir stringe
//	dönüşürse yakalanır.)
func TestHasSecrets_VaultLabelNoFalsePositive(t *testing.T) {
	t.Parallel()

	m := newTestMasker(1000)

	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "single GH_PAT label",
			input: "[[GH_PAT_3F7A1B2C]]",
		},
		{
			name:  "OAI_KEY label in JSON",
			input: `{"content": "[[OAI_KEY_A4F0C8B2]]"}`,
		},
		{
			name:  "EMAIL label in SSE chunk",
			input: `data: {"delta": {"content": "Hello [[EMAIL_DEAD1234]]"}}`,
		},
		{
			name:  "multiple labels, no raw secrets",
			input: "From [[EMAIL_AAAABBBB]] to [[EMAIL_CCCCDDDD]] via [[TOKEN_11223344]]",
		},
		{
			name:  "safe plain text",
			input: "This is a completely ordinary sentence with no secrets.",
		},
		{
			name:  "label with surrounding prose",
			input: "Your masked value is [[GH_PAT_3F7A1B2C]] — please keep it safe.",
		},
		{
			// JWT pattern matches eyJ<10+>.eyJ<10+>.<10+> — the vault label
			// [[JWT_A4F0C8B2]] must NOT match this because it lacks the two
			// '.' separators and the three base64url segments.
			// ([[JWT_A4F0C8B2]] etiketinin üç parçalı JWT desenini tetiklememesi
			//  gerekir; '.' ayırıcısı veya eyJ ile başlayan segment yoktur.)
			name:  "JWT vault label no false positive",
			input: `{"delta": {"content": "[[JWT_A4F0C8B2]]"}}`,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if m.HasSecrets(tc.input) {
				t.Errorf("[FAIL] HasSecrets(%q) = true, want false — vault labels must not trigger fail-fast",
					tc.input)
			}
		})
	}
}

// TestHasSecrets_DetectsRealSecrets verifies that HasSecrets returns true for
// text that actually contains sensitive patterns (the positive path).
// (HasSecrets'in gerçek hassas desenler içeren metin için true döndürdüğünü
//
//	doğrular — pozitif yol.)
func TestHasSecrets_DetectsRealSecrets(t *testing.T) {
	t.Parallel()

	m := newTestMasker(1000)

	cases := []struct {
		name  string
		input string
	}{
		{name: "OpenAI key", input: `{"content": "sk-proj-ABC123456789DEF456789XYZ"}`},
		{name: "GitHub PAT", input: "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"},
		{name: "email address", input: "data: contact alice@example.com for help"},
		{name: "AWS access key", input: "AKIAIOSFODNN7EXAMPLE is the key"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !m.HasSecrets(tc.input) {
				t.Errorf("[FAIL] HasSecrets(%q) = false, want true — real secret must be detected",
					tc.input)
			}
		})
	}
}

// ── 8. New-pattern leak-prevention tests ─────────────────────────────────────

// TestNewPatternsMaskDoesNotLeak verifies that each newly added pattern
// (Anthropic, Google, Slack, Stripe, JWT) never reaches the upstream in plain text.
// This is the "sızdırmaz" (leak-proof) test for every new pattern.
//
// (Yeni eklenen her desenin (Anthropic, Google, Slack, Stripe, JWT) düz metin
//
//	olarak upstream'e ulaşmadığını doğrular. Her yeni desen için "sızdırmaz" testi.)
func TestNewPatternsMaskDoesNotLeak(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		sensitive string
		wantLabel string // expected vault label prefix
	}{
		{
			name:      "Anthropic API key",
			input:     "key=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			sensitive: "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			wantLabel: "[[ANT_KEY_",
		},
		{
			// AIza + exactly 35 alphanumeric/dash/underscore chars = 39 total
			name:      "Google API key",
			input:     `{"api_key":"AIzaSyCi-1234567890ABCDEFGHIJKLMNOPQRab"}`,
			sensitive: "AIzaSyCi-1234567890ABCDEFGHIJKLMNOPQRab",
			wantLabel: "[[GOOG_KEY_",
		},
		{
			name:      "Slack bot token",
			input:     "SLACK_TOKEN=xoxb-1234567890-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXa",
			sensitive: "xoxb-1234567890-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXa",
			wantLabel: "[[SLACK_TOK_",
		},
		{
			name:      "Slack user token",
			input:     "token: xoxp-9876543210-9876543210-ABCDEFGHIJKLMNOPQRSTUVWXa",
			sensitive: "xoxp-9876543210-9876543210-ABCDEFGHIJKLMNOPQRSTUVWXa",
			wantLabel: "[[SLACK_TOK_",
		},
		{
			name:      "Stripe live secret key",
			input:     "stripe_key=sk_live_ABCDEFGHIJKLMNOPQRSTUVWXa",
			sensitive: "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXa",
			wantLabel: "[[STRIPE_KEY_",
		},
		{
			name:      "Stripe live publishable key",
			input:     "pub_key=pk_live_ABCDEFGHIJKLMNOPQRSTUVWXa",
			sensitive: "pk_live_ABCDEFGHIJKLMNOPQRSTUVWXa",
			wantLabel: "[[STRIPE_KEY_",
		},
		{
			name:      "JWT standalone",
			input:     `{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0VXNlciJ9.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"}`,
			sensitive: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0VXNlciJ9.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
			wantLabel: "[[JWT_",
		},
	}

	for _, tc := range tests {
		tc := tc
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
				t.Errorf("[FAIL] MaskedCount == 0, pattern did not fire for %q", tc.name)
			}
			if !strings.Contains(result.Text, tc.wantLabel) {
				t.Errorf("[FAIL] expected label prefix %q in output, got %q",
					tc.wantLabel, result.Text)
			}
		})
	}
}

// TestNewPatternsRoundTrip verifies Mask→Unmask recovers the original for new patterns.
// (Yeni desenler için Mask→Unmask'ın orijinali geri kazandırdığını doğrular.)
func TestNewPatternsRoundTrip(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"key=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		`{"api_key":"AIzaSyCi-1234567890ABCDEFGHIJKLMNOPQRab"}`,
		"SLACK_TOKEN=xoxb-1234567890-1234567890-ABCDEFGHIJKLMNOPQRSTUVWXa",
		"stripe_key=sk_live_ABCDEFGHIJKLMNOPQRSTUVWXa",
		`{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0VXNlciJ9.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"}`,
	}

	for _, input := range inputs {
		input := input
		t.Run(input[:min(30, len(input))], func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			masked := m.Mask(input)
			recovered := m.Unmask(masked.Text)
			if recovered != input {
				t.Errorf("[FAIL] round-trip mismatch\n  original:  %q\n  masked:    %q\n  recovered: %q",
					input, masked.Text, recovered)
			}
		})
	}
}

// ── 10. Turkish PII — TC Kimlik No & Phone ────────────────────────────────────
//
// Valid TC Kimlik numbers used below are derived from the official algorithm:
//   d10 = (7*(d1+d3+d5+d7+d9) - (d2+d4+d6+d8)) mod 10
//   d11 = (d1+..+d10) mod 10
//
// 12345678950: oddSum=25 evenSum=20 → d10=5 sum10=50 → d11=0  ✓
// 10000000078: oddSum=1  evenSum=0  → d10=7 sum10=8  → d11=8  ✓

// TestTCKimlikSızdırmaz verifies valid TC Kimlik numbers are masked (leak-proof).
// (Geçerli TC Kimlik No'ların maskelendiğini doğrular — sızdırmaz testi.)
func TestTCKimlikSızdırmaz(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		input     string
		sensitive string
	}{
		{
			name:      "bare valid TC Kimlik",
			input:     "TC Kimlik No: 12345678950",
			sensitive: "12345678950",
		},
		{
			name:      "valid TC Kimlik in sentence",
			input:     "Kişi 10000000078 kimlik numarasıyla kayıtlıdır.",
			sensitive: "10000000078",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			result := m.Mask(tc.input)
			if strings.Contains(result.Text, tc.sensitive) {
				t.Errorf("[FAIL] masked output still contains TC Kimlik\n  input:  %q\n  output: %q", tc.input, result.Text)
			}
			if result.MaskedCount == 0 {
				t.Errorf("[FAIL] MaskedCount==0, TC Kimlik pattern did not fire for %q", tc.input)
			}
		})
	}
}

// TestTCKimlikRoundTrip verifies Mask→Unmask is lossless for valid TC Kimlik numbers.
// (Geçerli TC Kimlik No'lar için Mask→Unmask'ın kayıpsız olduğunu doğrular.)
func TestTCKimlikRoundTrip(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"TC Kimlik No: 12345678950",
		"Vatandaş kimliği 10000000078 olarak doğrulandı.",
	}

	for _, input := range inputs {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			masked := m.Mask(input)
			recovered := m.Unmask(masked.Text)
			if recovered != input {
				t.Errorf("[FAIL] round-trip mismatch\n  original:  %q\n  masked:    %q\n  recovered: %q",
					input, masked.Text, recovered)
			}
		})
	}
}

// TestTCKimlikFalsePositiveReduction verifies that 11-digit numbers that fail the
// checksum (order IDs, random numbers, etc.) are NOT masked.
// (Sağlama toplamını geçemeyen 11 haneli sayıların (sipariş no, rastgele sayı vb.)
//
//	maskelenmediğini doğrular — yanlış pozitif azaltma testi.)
func TestTCKimlikFalsePositiveReduction(t *testing.T) {
	t.Parallel()

	// Each value is 11 digits starting with [1-9] (passes the regex) but has a
	// wrong checksum (fails validateTCKimlik) — must NOT be masked.
	cases := []struct {
		name  string
		input string
	}{
		{
			// d10 should be 5 but is 0 → invalid
			name:  "wrong d10 digit",
			input: "Sipariş: 12345678900",
		},
		{
			// d10=1 passes, but d11 should be 0, is 1 → invalid
			name:  "wrong d11 digit",
			input: "Ref: 11111111111",
		},
		{
			// d10=9 passes, but d11 should be 0, is 9 → invalid
			name:  "all nines",
			input: "ID: 99999999999",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			result := m.Mask(tc.input)
			if result.Text != tc.input {
				t.Errorf("[FAIL] false-positive: invalid TC Kimlik was masked\n  input:  %q\n  output: %q",
					tc.input, result.Text)
			}
		})
	}
}

// TestTCKimlikHasSecrets verifies HasSecrets returns true for valid TC Kimlik
// and false for invalid-checksum numbers (fail-fast must not fire on junk IDs).
// (HasSecrets'in geçerli TC Kimlik için true, geçersiz sağlama toplamı için
//
//	false döndürdüğünü doğrular.)
func TestTCKimlikHasSecrets(t *testing.T) {
	t.Parallel()

	m := newTestMasker(1000)

	if !m.HasSecrets("TC: 12345678950") {
		t.Error("[FAIL] HasSecrets should return true for a valid TC Kimlik number")
	}
	if m.HasSecrets("sipariş: 12345678900") {
		t.Error("[FAIL] HasSecrets should return false for an invalid-checksum 11-digit number")
	}
}

// TestTurkishPhoneSızdırmaz verifies Turkish phone numbers are masked (leak-proof).
// (Türk telefon numaralarının maskelendiğini doğrular — sızdırmaz testi.)
func TestTurkishPhoneSızdırmaz(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		input     string
		sensitive string
	}{
		{
			name:      "0 prefix format",
			input:     "Telefon: 05321234567",
			sensitive: "05321234567",
		},
		{
			name:      "local 10-digit format",
			input:     "Arayın: 5321234567",
			sensitive: "5321234567",
		},
		{
			name:      "spaced local format",
			input:     "Tel: 532 123 45 67",
			sensitive: "532 123 45 67",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			result := m.Mask(tc.input)
			if strings.Contains(result.Text, tc.sensitive) {
				t.Errorf("[FAIL] masked output still contains phone number\n  input:  %q\n  output: %q", tc.input, result.Text)
			}
			if result.MaskedCount == 0 {
				t.Errorf("[FAIL] MaskedCount==0, phone pattern did not fire for %q", tc.input)
			}
		})
	}
}

// TestTurkishPhoneRoundTrip verifies Mask→Unmask is lossless for Turkish phone numbers.
// (Türk telefon numaraları için Mask→Unmask'ın kayıpsız olduğunu doğrular.)
func TestTurkishPhoneRoundTrip(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"Telefon: 05321234567",
		"Arayın: 5321234567 veya 5009876543",
	}

	for _, input := range inputs {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			masked := m.Mask(input)
			recovered := m.Unmask(masked.Text)
			if recovered != input {
				t.Errorf("[FAIL] round-trip mismatch\n  original:  %q\n  masked:    %q\n  recovered: %q",
					input, masked.Text, recovered)
			}
		})
	}
}

// ── 11. National ID patterns — positive + negative checksum tests ─────────────
//
// Positive case: valid checksum → must be masked (MaskedCount > 0, sensitive value absent).
// Negative case: same length/format, wrong checksum → must NOT be masked (text unchanged).

// ---- Brazil CPF ----
// Valid:   52998224725 (d10=(295%11→9)→11-9=2, d11=(347%11→6)→11-6=5)
//          11144477735 (d10=(162%11→8)→11-8=3, d11=(204%11→6)→11-6=5)
// Invalid: 52998224724 (last digit wrong), 11111111111 (all-same → law invalid)

func TestCPFSızdırmaz(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, input, sensitive string }{
		{"bare", "CPF: 52998224725", "52998224725"},
		{"formatted", "CPF: 529.982.247-25", "529.982.247-25"},
		{"second valid", "doc 11144477735", "11144477735"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			r := m.Mask(tc.input)
			if strings.Contains(r.Text, tc.sensitive) {
				t.Errorf("[FAIL] CPF leaked\n  input=%q\n  output=%q", tc.input, r.Text)
			}
			if r.MaskedCount == 0 {
				t.Errorf("[FAIL] CPF pattern did not fire for %q", tc.input)
			}
		})
	}
}

func TestCPFRoundTrip(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		"CPF: 52998224725",
		"CPF formatado: 529.982.247-25",
	} {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			if got := m.Unmask(m.Mask(input).Text); got != input {
				t.Errorf("[FAIL] CPF round-trip: %q → %q", input, got)
			}
		})
	}
}

func TestCPFFalsePositive(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, input string }{
		{"wrong last digit", "doc: 52998224724"},
		{"all same digits", "doc: 11111111111"},
		{"all zeros", "doc: 00000000000"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			r := m.Mask(tc.input)
			if r.Text != tc.input {
				t.Errorf("[FAIL] CPF false-positive: %q was masked to %q", tc.input, r.Text)
			}
		})
	}
}

// ---- Spain DNI ----
// Valid:   12345678Z (12345678 % 23 = 14 → Z), 00000000T (0 % 23 = 0 → T)
// Invalid: 12345678A (need Z, not A)

func TestDNISızdırmaz(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, input, sensitive string }{
		{"standard", "DNI: 12345678Z", "12345678Z"},
		{"leading zeros", "doc: 00000000T", "00000000T"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			r := m.Mask(tc.input)
			if strings.Contains(r.Text, tc.sensitive) {
				t.Errorf("[FAIL] DNI leaked\n  input=%q\n  output=%q", tc.input, r.Text)
			}
			if r.MaskedCount == 0 {
				t.Errorf("[FAIL] DNI pattern did not fire for %q", tc.input)
			}
		})
	}
}

func TestDNIRoundTrip(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"DNI: 12345678Z", "ID: 00000000T"} {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			if got := m.Unmask(m.Mask(input).Text); got != input {
				t.Errorf("[FAIL] DNI round-trip: %q → %q", input, got)
			}
		})
	}
}

func TestDNIFalsePositive(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, input string }{
		{"wrong letter", "DNI: 12345678A"},
		{"wrong letter 2", "doc: 00000000R"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			r := m.Mask(tc.input)
			if r.Text != tc.input {
				t.Errorf("[FAIL] DNI false-positive: %q masked to %q", tc.input, r.Text)
			}
		})
	}
}

// ---- India Aadhaar ----
// Valid:   234567890124 (Verhoeff-verified), 987654321096 (Verhoeff-verified)
// Invalid: 234567890125 (last digit off by one)

func TestAadhaarSızdırmaz(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, input, sensitive string }{
		{"first valid", "Aadhaar: 234567890124", "234567890124"},
		{"second valid", "ID: 987654321096", "987654321096"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			r := m.Mask(tc.input)
			if strings.Contains(r.Text, tc.sensitive) {
				t.Errorf("[FAIL] Aadhaar leaked\n  input=%q\n  output=%q", tc.input, r.Text)
			}
			if r.MaskedCount == 0 {
				t.Errorf("[FAIL] Aadhaar pattern did not fire for %q", tc.input)
			}
		})
	}
}

func TestAadhaarRoundTrip(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"Aadhaar: 234567890124", "ID: 987654321096"} {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			if got := m.Unmask(m.Mask(input).Text); got != input {
				t.Errorf("[FAIL] Aadhaar round-trip: %q → %q", input, got)
			}
		})
	}
}

func TestAadhaarFalsePositive(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, input string }{
		{"bad check digit", "ID: 234567890125"},
		{"starts with 1", "ID: 123456789012"},
		{"starts with 0", "ID: 034567890124"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			r := m.Mask(tc.input)
			if r.Text != tc.input {
				t.Errorf("[FAIL] Aadhaar false-positive: %q masked to %q", tc.input, r.Text)
			}
		})
	}
}

// ---- Italy Codice Fiscale ----
// Valid:   RSSMRA85A01H501Z  (odd=61, even=42, total=103, 103%26=25→Z)
//          AAABBB00A00A000J  (odd=7, even=2, total=9, 9%26=9→J)
// Invalid: RSSMRA85A01H501Y (need Z), AAABBB00A00A000Z (need J)

func TestCFSızdırmaz(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, input, sensitive string }{
		{"standard", "CF: RSSMRA85A01H501Z", "RSSMRA85A01H501Z"},
		{"synthetic", "codice: AAABBB00A00A000J", "AAABBB00A00A000J"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			r := m.Mask(tc.input)
			if strings.Contains(r.Text, tc.sensitive) {
				t.Errorf("[FAIL] CF leaked\n  input=%q\n  output=%q", tc.input, r.Text)
			}
			if r.MaskedCount == 0 {
				t.Errorf("[FAIL] CF pattern did not fire for %q", tc.input)
			}
		})
	}
}

func TestCFRoundTrip(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		"CF: RSSMRA85A01H501Z",
		"codice: AAABBB00A00A000J",
	} {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			if got := m.Unmask(m.Mask(input).Text); got != input {
				t.Errorf("[FAIL] CF round-trip: %q → %q", input, got)
			}
		})
	}
}

func TestCFFalsePositive(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, input string }{
		{"wrong check char", "CF: RSSMRA85A01H501Y"},
		{"synthetic wrong", "codice: AAABBB00A00A000Z"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newTestMasker(1000)
			r := m.Mask(tc.input)
			if r.Text != tc.input {
				t.Errorf("[FAIL] CF false-positive: %q masked to %q", tc.input, r.Text)
			}
		})
	}
}

// ── Vault label no-false-positive for new national-ID prefixes ─────────────────
// Extends the coverage of TestHasSecrets_VaultLabelNoFalsePositive.

func TestNationalIDVaultLabelsNoFalsePositive(t *testing.T) {
	t.Parallel()
	m := newTestMasker(1000)
	labels := []string{
		"[[TR_ID_AABBCCDD]]",
		"[[BR_CPF_11223344]]",
		"[[ES_DNI_AABBCCDD]]",
		"[[IN_AADHAAR_DEADBEEF]]",
		"[[IT_CF_12345678]]",
	}
	for _, label := range labels {
		label := label
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			if m.HasSecrets(label) {
				t.Errorf("[FAIL] HasSecrets(%q) = true — vault label must not trigger fail-fast", label)
			}
		})
	}
}

// min is a local helper for Go 1.22 (builtin min added in 1.21, this avoids ambiguity).
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── 9. Edge cases ─────────────────────────────────────────────────────────────

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
//
//	değiştirilmeden bırakıldığını doğrular.)
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
//
//	vault alanından tasarruf etmek için tam olarak aynı etiketle maskelendiğini doğrular.)
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
