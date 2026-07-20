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
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/3mre0s/ai-firewall/config"
	"github.com/3mre0s/ai-firewall/metrics"
	"github.com/3mre0s/ai-firewall/patterns"
	"github.com/3mre0s/ai-firewall/vault"
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
		// Matches: [[PREFIX_8HEXDIGITS]]  e.g. [[GH_PAT_3F7A1B2C]]
		// (Örneğin [[GH_PAT_3F7A1B2C]] biçimindeki etiketleri eşleştirir.)
		labelPattern: regexp.MustCompile(`\[\[[A-Z_]+_[0-9A-F]{8}\]\]`),
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

// generateLabel returns a unique, bracket-delimited placeholder.
// 4 random bytes → 8 hex digits → collision probability ≈ 1 in 4 billion.
// (4 rastgele bayt → 8 onaltılık basamak → çarpışma olasılığı ≈ 4 milyarda 1.)
//
// Example output: [[SECRET_A4F0C8B2]]
func generateLabel(prefix string) string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is extremely rare; use a deterministic fallback
		// so we never return an empty string.
		// (crypto/rand hatası son derece nadirdir; asla boş dize dönmemek için
		//  deterministik bir yedek kullanılır.)
		b = []byte{0xDE, 0xAD, 0xC0, 0xDE}
	}
	return fmt.Sprintf("[[%s_%s]]", prefix, strings.ToUpper(hex.EncodeToString(b)))
}

// ── MaskResult (Maskeleme Sonucu) ─────────────────────────────────────────────

// MaskResult is returned by Mask() and carries the sanitised text plus
// a summary of what was found — useful for structured logging (yapısal loglama).
type MaskResult struct {
	Text           string                       // sanitised text ready to send upstream (hedefe gönderilmeye hazır temizlenmiş metin)
	MaskedCount    int                          // total number of values that were replaced (değiştirilen toplam değer sayısı)
	ByType         map[patterns.PatternType]int // breakdown by category (kategoriye göre dağılım)
	Detections     []Detection                  // privacy-safe metadata; never contains the matched value
	VaultEvictions int
}

// Detection is safe to expose in local audit records. The original value is
// used only while Mask is running and is cleared before the result returns.
type Detection struct {
	Name              string
	Type              patterns.PatternType
	PlaceholderID     string
	OriginalPrevented bool
	original          string
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

		if p.GroupIndex > 0 {
			result.Text = m.maskGroup(result.Text, p, &result, seen)
		} else {
			result.Text = m.maskFull(result.Text, p, &result, seen)
		}
	}

	for i := range result.Detections {
		result.Detections[i].OriginalPrevented =
			!strings.Contains(result.Text, result.Detections[i].original)
		result.Detections[i].original = ""
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
			r.Detections = append(r.Detections, Detection{
				Name: p.Name, Type: p.Type, PlaceholderID: existingLabel, original: match,
			})
			return existingLabel
		}

		label := generateLabel(p.Prefix)
		if err := m.vault.Store(label, match); err != nil {
			log.Printf("[WARN] vault full (kasa dolu) — %s left unmasked: %v", p.Name, err)
			metrics.Global.IncVaultEvictions()
			r.VaultEvictions++
			return match
		}
		seen[match] = label
		r.MaskedCount++
		r.ByType[p.Type]++
		r.Detections = append(r.Detections, Detection{
			Name: p.Name, Type: p.Type, PlaceholderID: label, original: match,
		})
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
		// A more specific pattern may already have replaced this value. Never
		// wrap one Anonmyz placeholder inside another: a single response pass
		// must be sufficient to restore the original value.
		if m.labelPattern.MatchString(value) {
			return match
		}

		if p.Validate != nil && !p.Validate(value) {
			return match // failed checksum / semantic validation — leave as-is
		}
		if existingLabel, ok := seen[value]; ok {
			r.MaskedCount++
			r.ByType[p.Type]++
			r.Detections = append(r.Detections, Detection{
				Name: p.Name, Type: p.Type, PlaceholderID: existingLabel, original: value,
			})
			return strings.Replace(match, value, existingLabel, 1)
		}

		label := generateLabel(p.Prefix)

		if err := m.vault.Store(label, value); err != nil {
			log.Printf("[WARN] vault full (kasa dolu) — %s left unmasked: %v", p.Name, err)
			metrics.Global.IncVaultEvictions()
			r.VaultEvictions++
			return match
		}
		seen[value] = label
		r.MaskedCount++
		r.ByType[p.Type]++
		r.Detections = append(r.Detections, Detection{
			Name: p.Name, Type: p.Type, PlaceholderID: label, original: value,
		})

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

// ContainsOriginal reports whether text contains a raw sensitive value that
// this request scope previously replaced. Unlike HasSecrets, it does not flag
// unrelated secret-shaped model output or workspace paths.
func (m *Masker) ContainsOriginal(text string) bool {
	return m.vault.ContainsOriginal(text)
}

// HasCredentialSecrets reports credential-like output independently of the
// request vault. Paths and PII are excluded here because model response
// envelopes can legitimately contain workspace metadata; exact request values
// in those categories are still caught by ContainsOriginal.
func (m *Masker) HasCredentialSecrets(text string) bool {
	for _, p := range patterns.Registry {
		if p.Type == patterns.TypePath || p.Type == patterns.TypePII {
			continue
		}
		if p.Validate == nil {
			if p.Regex.MatchString(text) {
				return true
			}
			continue
		}
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
	unmasked, _ := m.UnmaskWithCount(text)
	return unmasked
}

// UnmaskWithCount restores known placeholders and reports how many
// replacements were made. It is used by the audit trail without exposing any
// secret value.
func (m *Masker) UnmaskWithCount(text string) (string, int) {
	restored := 0
	unmasked := m.labelPattern.ReplaceAllStringFunc(text, func(label string) string {
		if original, ok := m.vault.Retrieve(label); ok {
			restored++
			return original
		}
		// Unknown label: return it unchanged to avoid corrupting the response.
		// (Bilinmeyen etiket: yanıtı bozmamak için değiştirmeden döndür.)
		return label
	})
	return unmasked, restored
}
