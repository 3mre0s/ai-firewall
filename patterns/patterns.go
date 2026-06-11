// Package patterns holds every compiled (derlenmiş) regex that the Masker uses
// to detect sensitive data.  Patterns are grouped by PatternType so that the
// Masker can toggle categories on or off via Config.
//
// Adding a new rule (yeni kural eklemek):
//  1. Define a new PatternType constant if needed.
//  2. Append a SensitivePattern to Registry.
//  3. Set GroupIndex > 0 only when a surrounding context is needed to
//     identify the secret but should NOT itself be replaced.
//     (Gizliliği tanımlamak için çevreleyen bağlam gerektiğinde ancak
//      o bağlamın kendisi değiştirilmemesi gerektiğinde GroupIndex > 0 ayarlayın.)
package patterns

import "regexp"

// PatternType categorises the kind of sensitive data being protected.
// (Korunan hassas veri türünü kategorize eder.)
type PatternType string

const (
	TypeToken  PatternType = "TOKEN"  // API/OAuth tokens (API/OAuth anahtarları)
	TypeKey    PatternType = "KEY"    // Cryptographic keys (kriptografik anahtarlar)
	TypePath   PatternType = "PATH"   // File-system paths (dosya sistemi yolları)
	TypeSecret PatternType = "SECRET" // Passwords & env-var secrets (şifreler ve çevre değişkeni gizlilikleri)
	TypePII    PatternType = "PII"    // Personally Identifiable Information (Kişisel Tanımlanabilir Bilgi)
)

// SensitivePattern pairs a compiled regex with the metadata needed to mask a match.
// (Derlenmiş bir regex'i, bir eşleşmeyi maskelemek için gereken meta veriyle eşleştirir.)
type SensitivePattern struct {
	Name   string         // human-readable description (insan tarafından okunabilir açıklama)
	Type   PatternType    // category used for config toggles (yapılandırma geçişleri için kategori)
	Regex  *regexp.Regexp // pre-compiled — zero allocation on each match (önceden derlenmiş — her eşleşmede sıfır tahsis)
	Prefix string         // vault label prefix, e.g. "GH_TOKEN" → [[GH_TOKEN_A1B2C3D4]]

	// GroupIndex: when > 0, only capture group N is stored and replaced,
	// leaving the surrounding text (keywords, quotes, etc.) untouched.
	// (0'dan büyük olduğunda, yalnızca N numaralı yakalama grubu saklanır
	//  ve değiştirilir; çevreleyen metin (anahtar kelimeler, tırnaklar vb.) dokunulmadan bırakılır.)
	GroupIndex int
}

// Registry is the ordered list of all patterns the Masker applies.
// Order matters: more specific patterns should come before broad ones.
// (Masker'ın uyguladığı tüm desenlerin sıralı listesi.
//  Sıra önemlidir: daha spesifik desenler geniş olanlardan önce gelmeli.)
var Registry = []SensitivePattern{

	// ── Tokens & API Keys (Anahtarlar ve API Jetonları) ───────────────────────

	{
		Name:   "OpenAI API Key",
		Type:   TypeToken,
		Regex:  regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9\-_]{20,}\b`),
		Prefix: "OAI_KEY",
	},
	{
		Name:   "GitHub Personal Access Token v1",
		Type:   TypeToken,
		Regex:  regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`),
		Prefix: "GH_PAT",
	},
	{
		Name:   "GitHub OAuth App Token",
		Type:   TypeToken,
		Regex:  regexp.MustCompile(`\bgho_[A-Za-z0-9]{36}\b`),
		Prefix: "GH_OAT",
	},
	{
		Name:   "GitHub Actions / Installation Token",
		Type:   TypeToken,
		Regex:  regexp.MustCompile(`\bghs_[A-Za-z0-9]{36}\b`),
		Prefix: "GH_ACT",
	},
	{
		Name:   "GitLab Personal Access Token",
		Type:   TypeToken,
		Regex:  regexp.MustCompile(`\bglpat-[A-Za-z0-9\-_]{20,}\b`),
		Prefix: "GL_PAT",
	},
	{
		Name:   "AWS Access Key ID (Erişim Anahtarı Kimliği)",
		Type:   TypeKey,
		Regex:  regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		Prefix: "AWS_AK",
	},
	{
		Name:       "AWS Secret Access Key",
		Type:       TypeKey,
		Regex:      regexp.MustCompile(`(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key["'\s:=]+([A-Za-z0-9/+=]{40})\b`),
		Prefix:     "AWS_SK",
		GroupIndex: 1,
	},
	{
		// Matches: Authorization: Bearer <token>
		// Only the token value is replaced, the "Bearer" keyword stays.
		// (Yalnızca token değeri değiştirilir, "Bearer" anahtar kelimesi kalır.)
		Name:       "HTTP Bearer Token",
		Type:       TypeToken,
		Regex:      regexp.MustCompile(`(?i)\bBearer\s+([A-Za-z0-9\-_\.]{20,})\b`),
		Prefix:     "BEARER",
		GroupIndex: 1,
	},

	// ── SSH / TLS Private Keys (Özel Anahtarlar) ─────────────────────────────

	{
		// Matches full PEM blocks (tam PEM bloklarını eşleştirir):
		// -----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----
		Name:   "PEM Private Key Block",
		Type:   TypeKey,
		Regex:  regexp.MustCompile(`-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]{10,}?-----END (?:[A-Z]+ )?PRIVATE KEY-----`),
		Prefix: "PEM_KEY",
	},

	// ── Environment Variable Secrets (Çevre Değişkeni Gizlilikleri) ──────────

	{
		// Matches: PASSWORD=mysecret  /  api_key: "abc123"  /  TOKEN='xyz'
		// Only the value after the separator is masked, not the key name.
		// (Ayırıcıdan sonraki değer maskelenir, anahtar adı değil.)
		Name:       "Inline Secret Assignment (Satır İçi Gizlilik Ataması)",
		Type:       TypeSecret,
		Regex:      regexp.MustCompile(`(?i)(?:password|passwd|secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token)\s*[=:]\s*["']?([^\s"'&<>\n]{8,64})["']?`),
		Prefix:     "SECRET",
		GroupIndex: 1,
	},
	{
		// Matches: export DB_PASS=hunter2  /  set TOKEN=abc
		// (export/set komutlarındaki atamaları yakalar)
		Name:       "Shell Export / Set Command",
		Type:       TypeSecret,
		Regex:      regexp.MustCompile(`(?i)(?:export|set)\s+[A-Z][A-Z0-9_]*=["']?([^\s"'\n]{8,})["']?`),
		Prefix:     "ENV_VAL",
		GroupIndex: 1,
	},

	// ── File-System Paths (Dosya Sistemi Yolları) ─────────────────────────────

	{
		// Unix absolute paths starting from common root dirs.
		// A minimum depth of 3 segments avoids false positives like "/usr" alone.
		// (Minimum 3 segment derinliği, "/usr" gibi yanlış pozitifleri önler.)
		Name:       "Unix Absolute Path (Unix Mutlak Yol)",
		Type:       TypePath,
		Regex:      regexp.MustCompile(`(?:^|[\s"'` + "`" + `])((?:/(?:home|root|Users|var|etc|opt|srv|mnt|tmp))[^\s"'` + "`" + `\n]{4,})`),
		Prefix:     "UNIX_PATH",
		GroupIndex: 1,
	},
	{
		// Windows absolute paths: C:\Users\alice\project
		// (Windows mutlak yolları)
		Name:   "Windows Absolute Path (Windows Mutlak Yol)",
		Type:   TypePath,
		Regex:  regexp.MustCompile(`[A-Za-z]:\\(?:[^\\/:\*\?"<>|\n]+\\)+[^\\/:\*\?"<>|\n]*`),
		Prefix: "WIN_PATH",
	},

	// ── PII — Personally Identifiable Information (Kişisel Tanımlanabilir Bilgi) ─

	{
		Name:   "E-mail Address (E-posta Adresi)",
		Type:   TypePII,
		Regex:  regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}\b`),
		Prefix: "EMAIL",
	},
	{
		// Matches credit card numbers with optional spaces/dashes between groups.
		// Covers Visa (13-19 digits), Mastercard (16), Amex (15), Discover (16-19).
		// (Gruplar arasında isteğe bağlı boşluk/tire ile kredi kartı numaralarını eşleştirir.)
		Name:   "Credit Card Number (Kredi Kartı Numarası)",
		Type:   TypePII,
		Regex:  regexp.MustCompile(`\b(?:\d{4}[\s\-]?){3}\d{1,4}\b`),
		Prefix: "CC",
	},
	{
		// Turkish IBAN: TR + 2 check digits + 22 account digits (total 26 chars).
		// (Türk IBAN'ı: TR + 2 kontrol hanesi + 22 hesap hanesi, toplam 26 karakter.)
		Name:   "Turkish IBAN",
		Type:   TypePII,
		Regex:  regexp.MustCompile(`\bTR\d{24}\b`),
		Prefix: "IBAN_TR",
	},
	{
		// International IBAN: 2 letter country code + 2 check digits + up to 30 alphanumeric.
		// (Uluslararası IBAN: 2 harf ülke kodu + 2 kontrol hanesi + 30 alfanümerik.)
		Name:   "IBAN",
		Type:   TypePII,
		Regex:  regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b`),
		Prefix: "IBAN",
	},
	{
		// Turkish National ID (TC Kimlik No): 11 digits, first digit cannot be 0.
		// Note: Full checksum validation is not feasible in regex.
		// (Türk Kimlik Numarası: 11 hane, ilk hane 0 olamaz. Tam sağlama doğrulaması regex'te uygulanamaz.)
		Name:   "Turkish National ID (TC Kimlik No)",
		Type:   TypePII,
		Regex:  regexp.MustCompile(`\b[1-9]\d{10}\b`),
		Prefix: "TC_ID",
	},
	{
		// Turkish phone numbers: +90 xxx xxx xx xx, 0xxx xxx xx xx, etc.
		// Handles various formats with optional country code, parens, spaces.
		// (Türk telefon numaraları: isteğe bağlı ülke kodu, parantez, boşluk ile çeşitli formatları destekler.)
		Name:   "Turkish Phone Number (Türk Telefon Numarası)",
		Type:   TypePII,
		Regex:  regexp.MustCompile(`\b(?:\+90|0)?[\s\(]?[1-9]\d{2}[\s\)]?\d{3}[\s]?\d{2}[\s]?\d{2}\b`),
		Prefix: "PHONE_TR",
	},
}
