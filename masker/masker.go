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

	"github.com/localai/firewall/config"
	"github.com/localai/firewall/metrics"
	"github.com/localai/firewall/patterns"
	"github.com/localai/firewall/vault"
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
	VaultEvictions int
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

	return result
}

// maskFull replaces the entire regex match with a single label.
// (Tüm regex eşleşmesini tek bir etiketle değiştirir.)
func (m *Masker) maskFull(text string, p patterns.SensitivePattern, r *MaskResult, seen map[string]string) string {
	return p.Regex.ReplaceAllStringFunc(text, func(match string) string {
		if existingLabel, ok := seen[match]; ok {
			r.MaskedCount++
			r.ByType[p.Type]++
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

		if existingLabel, ok := seen[value]; ok {
			r.MaskedCount++
			r.ByType[p.Type]++
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

		// Replace only the first occurrence of value inside match.
		// Since the regex already guarantees value is inside match, this is safe.
		// (Eşleşme içindeki değerin yalnızca ilk tekrarını değiştir.
		//  Regex, değerin eşleşme içinde olduğunu zaten garanti eder; bu nedenle güvenlidir.)
		return strings.Replace(match, value, label, 1)
	})
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
