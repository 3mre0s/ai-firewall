// Package masker is the core engine of the firewall.
// It has exactly two public operations:
//
//	Mask(text)   — find sensitive data → store in Vault → return sanitised text
//	Unmask(text) — find vault labels   → restore originals → return clean text
//
// Both operations work on raw strings (the serialised HTTP body) so they are
// completely agnostic of JSON structure or AI provider.
// (Her iki işlem de ham dizeler üzerinde çalışır; bu nedenle JSON yapısından
//
//	veya AI sağlayıcısından tamamen bağımsızdır.)
package masker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/3mre0s/ai_firewall/config"
	"github.com/3mre0s/ai_firewall/metrics"
	"github.com/3mre0s/ai_firewall/patterns"
	"github.com/3mre0s/ai_firewall/vault"
)

// Masker wires together the pattern registry, the vault, and the config.
// (Desen kaydı, vault ve yapılandırmayı birbirine bağlar.)
// One Masker instance is safe to use from multiple goroutines (iş parçacıkları)
// because the Vault is already thread-safe (iş parçacığı güvenli) and all
// other fields here are read-only after construction.
type Masker struct {
	vault        *vault.Vault
	cfg          *config.Config
	labelPattern *regexp.Regexp // matches any label emitted by generateLabel
}

// New creates a Masker backed by the given Vault and Config.
// (Verilen Vault ve Config ile desteklenen bir Masker oluşturur.)
func New(v *vault.Vault, cfg *config.Config) *Masker {
	return &Masker{
		vault: v,
		cfg:   cfg,
		// Matches: [[PREFIX_32HEXDIGITS]].
		// (Örneğin [[GH_PAT_3F7A1B2C]] biçimindeki etiketleri eşleştirir.)
		labelPattern: regexp.MustCompile(`\[\[[A-Z_]+_[0-9A-F]{32}\]\]`),
	}
}

// NewScope returns an isolated masker for a single request/response lifetime.
// A provider sees the placeholders sent upstream; keeping labels process-wide
// would let a placeholder from one request restore a secret in another.
func (m *Masker) NewScope() *Masker {
	return New(vault.New(m.cfg.VaultSizeLimit), m.cfg)
}

// Reset clears all secrets retained by this masker scope.
func (m *Masker) Reset() {
	m.vault.Reset()
}

// ── Label generation (Etiket üretme) ─────────────────────────────────────────

// randRead fills b with cryptographically secure random bytes. It is a package
// variable so tests can simulate entropy failure — modern Go aborts the process
// inside crypto/rand.Read itself, which cannot be triggered safely in a test.
// (b'yi kriptografik olarak güvenli rastgele baytlarla doldurur. Paket değişkeni
// olmasının nedeni testlerin entropi hatasını simüle edebilmesidir — modern Go,
// crypto/rand.Read içinde süreci sonlandırır ve bu bir testte güvenle tetiklenemez.)
var randRead = rand.Read

// generateLabel returns a unique, bracket-delimited placeholder.
// 16 random bytes → 32 hex digits, so collisions are negligible in practice.
// (16 rastgele bayt → 32 onaltılık basamak → çarpışma olasılığı ihmal edilebilir.)
//
// A crypto/rand failure is returned as an error: a deterministic fallback label
// would be shared by every secret, causing vault collisions and wrong values
// being restored on Unmask. Callers treat the error like vault-full and the
// request is blocked instead of forwarded (fail-closed).
// (crypto/rand hatası, hata olarak döndürülür: deterministik bir yedek etiket
//
//	her sır için aynı olur, vault çakışmalarına ve Unmask'ta yanlış değerlerin
//	geri yüklenmesine yol açar. Çağıranlar hatayı vault-dolu gibi ele alır ve
//	istek iletilmek yerine engellenir — fail-closed.)
//
// Example output: [[SECRET_A4F0C8B2D9E1F203445566778899AABB]]
func generateLabel(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := randRead(b); err != nil {
		return "", fmt.Errorf("generating label: %w", err)
	}
	return fmt.Sprintf("[[%s_%s]]", prefix, strings.ToUpper(hex.EncodeToString(b))), nil
}

func (m *Masker) storeWithFreshLabel(prefix, original string) (string, error) {
	for range 8 {
		label, err := generateLabel(prefix)
		if err != nil {
			return "", err
		}
		if err := m.vault.Store(label, original); err != nil {
			if errors.Is(err, vault.ErrLabelExists) {
				continue
			}
			return "", err
		}
		return label, nil
	}
	return "", vault.ErrLabelExists
}

// ── MaskResult (Maskeleme Sonucu) ─────────────────────────────────────────────

// MaskMatch is a per-rule detection summary. One entry is produced for every
// pattern in the registry that matched at least one value in the input,
// including values that were detected but could NOT be masked because the
// vault was full (fail-closed). It lets callers report exactly which rules
// fired without exposing the sensitive values themselves.
//
// (Kural bazlı tespit özeti. Girdide en az bir değer eşleşen her desen için
//
//	bir giriş üretilir; vault dolu olduğu için maskelenemeyen (fail-closed)
//	değerler de dahildir. Hassas değerleri ifşa etmeden hangi kuralların
//	tetiklendiğini bildirmeyi sağlar.)
type MaskMatch struct {
	Type  patterns.PatternType // category, e.g. PII / TOKEN (kategori)
	Rule  string               // human-readable pattern name (desen adı)
	Count int                  // how many values this rule matched (kaç değer eşleşti)
}

// MaskResult is returned by Mask() and carries the sanitised text plus
// a summary of what was found — useful for structured logging (yapısal loglama).
type MaskResult struct {
	Text           string                       // sanitised text ready to send upstream (hedefe gönderilmeye hazır temizlenmiş metin)
	MaskedCount    int                          // total number of values that were replaced (değiştirilen toplam değer sayısı)
	ByType         map[patterns.PatternType]int // breakdown by category (kategoriye göre dağılım)
	VaultEvictions int
	// Matches lists, per rule, what was detected (rule bazlı ne tespit edildiği).
	// Purely additive metadata; existing callers can ignore it.
	Matches []MaskMatch
}

// ── Mask (Maskeleme) ──────────────────────────────────────────────────────────

// Mask scans text against every pattern in the registry.
// For each match it:
//  1. generates a unique label,
//  2. stores original → label in the Vault,
//  3. replaces the sensitive value in the text with the label.
//
// If the Vault is full it logs a warning and leaves the value in the text
// rather than silently dropping data.
//
// (Metni kayıttaki her desene karşı tarar.
//
//	Her eşleşme için:
//	 1. Benzersiz bir etiket üretir,
//	 2. orijinal → etiketi Vault'a kaydeder,
//	 3. metindeki hassas değeri etiketle değiştirir.
//	Vault doluysa, veriyi sessizce silmek yerine bir uyarı loglar
//	ve değeri metinde bırakır.)
func (m *Masker) Mask(text string) MaskResult {
	result := MaskResult{
		Text:   text,
		ByType: make(map[patterns.PatternType]int),
	}

	// Local cache to reuse labels for identical sensitive values within this request.
	// (Bu istekteki aynı hassas değerler için etiketleri yeniden kullanmak üzere yerel önbellek.)
	seen := make(map[string]string)

	for _, p := range patterns.Registry {
		// Honour per-category config switches (kategori bazlı yapılandırma anahtarlarını dikkate al)
		if p.Type == patterns.TypePath && !m.cfg.MaskPaths {
			continue
		}
		if p.Type == patterns.TypePII && !m.cfg.MaskEmails {
			continue
		}

		// Snapshot counters so we can attribute exactly what THIS pattern found.
		// (Bu desenin tam olarak neyi bulduğunu ilişkilendirmek için sayaçları
		//  önceden yakala.)
		beforeMasked := result.MaskedCount
		beforeEvicted := result.VaultEvictions

		if p.GroupIndex > 0 {
			result.Text = m.maskGroup(result.Text, p, &result, seen)
		} else {
			result.Text = m.maskFull(result.Text, p, &result, seen)
		}

		// Record a per-rule match entry when this pattern detected anything,
		// counting both masked values and vault-evicted (detected-but-unmasked)
		// ones so blocked requests still report what was found.
		// (Bu desen bir şey tespit ettiyse kural bazlı bir giriş kaydet;
		//  maskelenen ve vault-dolu nedeniyle maskelenemeyen değerleri birlikte
		//  say ki bloklanan istekler de neyin bulunduğunu bildirsin.)
		masked := result.MaskedCount - beforeMasked
		evicted := result.VaultEvictions - beforeEvicted
		if masked+evicted > 0 {
			result.Matches = append(result.Matches, MaskMatch{
				Type:  p.Type,
				Rule:  p.Name,
				Count: masked + evicted,
			})
		}
	}

	return result
}

// maskFull replaces the entire regex match with a single label.
// (Tüm regex eşleşmesini tek bir etiketle değiştirir.)
func (m *Masker) maskFull(text string, p patterns.SensitivePattern, r *MaskResult, seen map[string]string) string {
	return p.Regex.ReplaceAllStringFunc(text, func(match string) string {
		if p.Validate != nil && !p.Validate(match) {
			return match // failed checksum / semantic validation — leave as-is
		}
		if existingLabel, ok := seen[match]; ok {
			r.MaskedCount++
			r.ByType[p.Type]++
			return existingLabel
		}

		label, err := m.storeWithFreshLabel(p.Prefix, match)
		if err != nil {
			log.Printf("[WARN] masking failed (maskeleme başarısız) — %s left unmasked, request will be blocked: %v", p.Name, err)
			metrics.Global.IncVaultEvictions()
			r.VaultEvictions++
			return match
		}
		seen[match] = label
		r.MaskedCount++
		r.ByType[p.Type]++
		return label
	})
}

// maskGroup replaces only capture group N within the full match,
// keeping surrounding context (e.g., the keyword "Bearer") intact.
//
// (Yalnızca tam eşleşme içindeki N yakalama grubunu değiştirir;
//
//	çevreleyen bağlamı (örn. "Bearer" anahtar kelimesi) korur.)
func (m *Masker) maskGroup(text string, p patterns.SensitivePattern, r *MaskResult, seen map[string]string) string {
	return p.Regex.ReplaceAllStringFunc(text, func(match string) string {
		subs := p.Regex.FindStringSubmatch(match)
		if len(subs) <= p.GroupIndex {
			return match // pattern matched but group absent — leave as-is (grup yok — olduğu gibi bırak)
		}

		value := subs[p.GroupIndex]

		if p.Validate != nil && !p.Validate(value) {
			return match // failed checksum / semantic validation — leave as-is
		}
		if existingLabel, ok := seen[value]; ok {
			r.MaskedCount++
			r.ByType[p.Type]++
			return strings.Replace(match, value, existingLabel, 1)
		}

		label, err := m.storeWithFreshLabel(p.Prefix, value)
		if err != nil {
			log.Printf("[WARN] masking failed (maskeleme başarısız) — %s left unmasked, request will be blocked: %v", p.Name, err)
			metrics.Global.IncVaultEvictions()
			r.VaultEvictions++
			return match
		}
		seen[value] = label
		r.MaskedCount++
		r.ByType[p.Type]++

		// Replace only the first occurrence of value inside match.
		// Since the regex already guarantees value is inside match, this is safe.
		// (Eşleşme içindeki değerin yalnızca ilk tekrarını değiştir.
		//  Regex, değerin eşleşme içinde olduğunu zaten garanti eder; bu nedenle güvenlidir.)
		return strings.Replace(match, value, label, 1)
	})
}

// ── HasSecrets (Sır Tespiti) ──────────────────────────────────────────────────

// HasSecrets reports whether text contains any sensitive-data pattern that would
// be masked by Mask().  Unlike Mask, this is a pure read — it does not modify the
// Vault or any other state.  Used by the streaming fail-fast mechanism.
//
// (Mask() tarafından maskelenecek hassas veri desenleri içeriyorsa true döner.
//
//	Mask'ın aksine Vault'u veya herhangi bir durumu değiştirmez — salt okunur
//	bir kontrol. Akış fail-fast mekanizması tarafından kullanılır.)
func (m *Masker) HasSecrets(text string) bool {
	for _, p := range patterns.Registry {
		if p.Type == patterns.TypePath && !m.cfg.MaskPaths {
			continue
		}
		if p.Type == patterns.TypePII && !m.cfg.MaskEmails {
			continue
		}
		if p.Validate == nil {
			if p.Regex.MatchString(text) {
				return true
			}
			continue
		}
		// Pattern has a semantic validator — check each match individually.
		if p.GroupIndex > 0 {
			for _, subs := range p.Regex.FindAllStringSubmatch(text, -1) {
				if len(subs) > p.GroupIndex && p.Validate(subs[p.GroupIndex]) {
					return true
				}
			}
		} else {
			for _, match := range p.Regex.FindAllString(text, -1) {
				if p.Validate(match) {
					return true
				}
			}
		}
	}
	return false
}

// ── Detect (Salt-okunur Tespit) ───────────────────────────────────────────────

// Detect performs a read-only scan of text and reports which rules matched,
// WITHOUT touching the vault or mutating any state. It applies the same
// category toggles and semantic validators as Mask/HasSecrets.
//
// Use it on paths where masking must NOT occur but a per-rule breakdown of what
// was found is still needed — e.g. inspecting model output for raw secrets that
// were never routed through masking (a genuine leak). Vault labels emitted by
// Mask never match any secret pattern, so they are not reported here.
//
// (Metni salt-okunur tarar ve hangi kuralların eşleştiğini bildirir; vault'a
//
//	dokunmaz, durumu değiştirmez. Mask/HasSecrets ile aynı kategori anahtarlarını
//	ve doğrulayıcıları uygular. Maskelemenin yapılMAMASI gereken ama neyin
//	bulunduğunun kural bazlı dökümüne ihtiyaç duyulan yollarda kullanılır.)
func (m *Masker) Detect(text string) []MaskMatch {
	var matches []MaskMatch
	for _, p := range patterns.Registry {
		if p.Type == patterns.TypePath && !m.cfg.MaskPaths {
			continue
		}
		if p.Type == patterns.TypePII && !m.cfg.MaskEmails {
			continue
		}

		count := 0
		if p.GroupIndex > 0 {
			for _, subs := range p.Regex.FindAllStringSubmatch(text, -1) {
				if len(subs) <= p.GroupIndex {
					continue
				}
				if p.Validate != nil && !p.Validate(subs[p.GroupIndex]) {
					continue
				}
				count++
			}
		} else {
			for _, match := range p.Regex.FindAllString(text, -1) {
				if p.Validate != nil && !p.Validate(match) {
					continue
				}
				count++
			}
		}

		if count > 0 {
			matches = append(matches, MaskMatch{Type: p.Type, Rule: p.Name, Count: count})
		}
	}
	return matches
}

// ── Unmask (Maskeyi Kaldırma) ─────────────────────────────────────────────────

// Unmask scans text for any vault label and replaces each with its stored
// original value.  Labels not present in the vault are left unchanged
// (they may belong to a different session or be spurious text).
//
// (Metni herhangi bir kasa etiketi için tarar ve her birini saklanan
//
//	orijinal değeriyle değiştirir. Kasada bulunmayan etiketler değiştirilmeden
//	bırakılır — farklı bir oturuma ait veya sahte metin olabilirler.)
func (m *Masker) Unmask(text string) string {
	return m.labelPattern.ReplaceAllStringFunc(text, func(label string) string {
		if original, ok := m.vault.Retrieve(label); ok {
			return original
		}
		// Unknown label: return it unchanged to avoid corrupting the response.
		// (Bilinmeyen etiket: yanıtı bozmamak için değiştirmeden döndür.)
		return label
	})
}
