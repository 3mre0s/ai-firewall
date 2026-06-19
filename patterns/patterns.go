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

	// Validate is an optional post-regex filter. When non-nil it is called with
	// the candidate string (the full match for GroupIndex==0, or the captured
	// group for GroupIndex>0).  Returning false skips masking for that match.
	// Use this for checksum-based rules that cannot be expressed in regex alone.
	//
	// (İsteğe bağlı post-regex filtresi. Sağlandığında, aday dizeyle çağrılır
	//  (GroupIndex==0 için tam eşleşme, GroupIndex>0 için yakalama grubu).
	//  false döndürmek o eşleşme için maskelemeyi atlar.)
	Validate func(string) bool
}

// validateLuhn implements the Luhn checksum used by credit card numbers.
// s may contain spaces or dashes between digit groups; these are stripped
// before validation. Rejects plain decimal numbers (timestamps, byte counts,
// schema constants like 9007199254740991) that happen to fall into 13-19
// digit groups of 4 but aren't valid card numbers.
// (s, hane grupları arasında boşluk veya tire içerebilir; bunlar doğrulamadan
//  önce ayıklanır. Kredi kartı numarası OLMAYAN ama 4'lü gruplar halinde
//  13-19 haneye denk gelen düz ondalık sayıları (zaman damgaları, bayt
//  sayıları, 9007199254740991 gibi şema sabitleri) eler.)
func validateLuhn(s string) bool {
	d := make([]int, 0, 19)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '-' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		d = append(d, int(c-'0'))
	}
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		v := d[i]
		if double {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
		double = !double
	}
	return sum%10 == 0
}

// ── National ID checksum validators (Ulusal Kimlik sağlama doğrulayıcıları) ────

// validateCPF implements the Brazilian CPF two-check-digit weighted mod-11 algorithm.
// s may be the raw 11-digit string or the formatted form (000.000.000-00);
// dots and dashes are stripped before validation.
func validateCPF(s string) bool {
	// Strip formatting separators.
	d := make([]int, 0, 11)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' || c == '-' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		d = append(d, int(c-'0'))
	}
	if len(d) != 11 {
		return false
	}
	// All-same-digit CPFs are explicitly invalid by Brazilian law.
	allSame := true
	for i := 1; i < 11; i++ {
		if d[i] != d[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return false
	}
	// First check digit.
	sum := 0
	for i := 0; i < 9; i++ {
		sum += d[i] * (10 - i)
	}
	r := sum % 11
	want10 := 0
	if r >= 2 {
		want10 = 11 - r
	}
	if want10 != d[9] {
		return false
	}
	// Second check digit.
	sum = 0
	for i := 0; i < 10; i++ {
		sum += d[i] * (11 - i)
	}
	r = sum % 11
	want11 := 0
	if r >= 2 {
		want11 = 11 - r
	}
	return want11 == d[10]
}

// dniLetters is the official 23-character control-letter table for Spanish DNI.
const dniLetters = "TRWAGMYFPDXBNJZSQVHLCKE"

// validateDNI checks the Spanish DNI control letter (8 digits + 1 letter).
// s must be exactly 9 bytes: 8 ASCII digits followed by an uppercase letter.
func validateDNI(s string) bool {
	if len(s) != 9 {
		return false
	}
	num := 0
	for i := 0; i < 8; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		num = num*10 + int(c-'0')
	}
	letter := s[8]
	if letter >= 'a' && letter <= 'z' {
		letter -= 32 // normalise to upper
	}
	return letter == dniLetters[num%23]
}

// Verhoeff tables for Aadhaar validation.
var (
	verhoeffD = [10][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
		{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
		{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
		{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
		{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
		{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
		{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
		{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	verhoeffP = [8][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
		{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
		{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
		{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
		{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
		{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
	}
)

// validateAadhaar checks a 12-digit Indian Aadhaar number using the Verhoeff algorithm.
// First digit must be 2-9; all characters must be ASCII digits.
func validateAadhaar(s string) bool {
	if len(s) != 12 {
		return false
	}
	digits := [12]int{}
	for i := 0; i < 12; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		digits[i] = int(c - '0')
	}
	if digits[0] < 2 {
		return false
	}
	c := 0
	for i := 0; i < 12; i++ {
		c = verhoeffD[c][verhoeffP[i%8][digits[11-i]]]
	}
	return c == 0
}

// cfOddVals maps characters to their odd-position values per the Italian CF spec
// (DM 23 dicembre 1976). Index 0-9 for digits, index 10-35 for letters A-Z.
var cfOddVals = [36]int{
	// digits 0-9
	1, 0, 5, 7, 9, 13, 15, 17, 19, 21,
	// letters A-Z (index 10=A, 11=B, … 35=Z)
	1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23,
}

// validateCodiceFiscale validates an Italian Codice Fiscale check character.
// s must be exactly 16 characters matching [A-Za-z0-9]{6}\d{2}[A-Za-z]\d{2}[A-Za-z]\d{3}[A-Za-z].
func validateCodiceFiscale(s string) bool {
	if len(s) != 16 {
		return false
	}
	sum := 0
	for i := 0; i < 15; i++ {
		ch := s[i]
		// Normalise to uppercase.
		if ch >= 'a' && ch <= 'z' {
			ch -= 32
		}
		var val int
		if ch >= '0' && ch <= '9' {
			val = int(ch - '0') // 0-9 for even positions; use cfOddVals index for odd
			if i%2 == 0 { // 0-indexed even = 1-indexed odd position
				val = cfOddVals[int(ch-'0')]
			}
		} else if ch >= 'A' && ch <= 'Z' {
			idx := int(ch-'A') + 10
			if i%2 == 0 { // odd position (1-indexed)
				val = cfOddVals[idx]
			} else { // even position (1-indexed): A=0 … Z=25
				val = int(ch - 'A')
			}
		} else {
			return false
		}
		sum += val
	}
	check := s[15]
	if check >= 'a' && check <= 'z' {
		check -= 32
	}
	if check < 'A' || check > 'Z' {
		return false
	}
	return int(check-'A') == sum%26
}

// validateTCKimlik implements the official Turkish National ID checksum algorithm.
// Rules (1-indexed digits d1..d11):
//
//	d10 = (7*(d1+d3+d5+d7+d9) - (d2+d4+d6+d8)) mod 10
//	d11 = (d1+d2+...+d10)                        mod 10
//
// (Resmi Türk TC Kimlik sağlama toplamı algoritması.
//
//	d10 = (7*(d1+d3+d5+d7+d9) - (d2+d4+d6+d8)) mod 10
//	d11 = (d1+..+d10) mod 10)
func validateTCKimlik(s string) bool {
	if len(s) != 11 {
		return false
	}
	digits := [11]int{}
	for i := 0; i < 11; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		digits[i] = int(c - '0')
	}
	if digits[0] == 0 {
		return false
	}
	oddSum := digits[0] + digits[2] + digits[4] + digits[6] + digits[8]
	evenSum := digits[1] + digits[3] + digits[5] + digits[7]
	d10 := (7*oddSum - evenSum) % 10
	if d10 < 0 {
		d10 += 10
	}
	if d10 != digits[9] {
		return false
	}
	sum10 := 0
	for i := 0; i < 10; i++ {
		sum10 += digits[i]
	}
	return sum10%10 == digits[10]
}

// Registry is the ordered list of all patterns the Masker applies.
// Order matters: more specific patterns should come before broad ones.
// (Masker'ın uyguladığı tüm desenlerin sıralı listesi.
//  Sıra önemlidir: daha spesifik desenler geniş olanlardan önce gelmeli.)
var Registry = []SensitivePattern{

	// ── Tokens & API Keys (Anahtarlar ve API Jetonları) ───────────────────────

	{
		// Anthropic API key: sk-ant-<type>-<random>
		// Must come BEFORE the generic OpenAI sk- pattern to get the correct label.
		// (Anthropic API anahtarı: doğru etiketi almak için genel OpenAI sk- deseninden ÖNCE gelmeli.)
		Name:   "Anthropic API Key",
		Type:   TypeToken,
		Regex:  regexp.MustCompile(`\bsk-ant-[A-Za-z0-9\-_]{20,}\b`),
		Prefix: "ANT_KEY",
	},
	{
		Name:   "OpenAI API Key",
		Type:   TypeToken,
		Regex:  regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9\-_]{20,}\b`),
		Prefix: "OAI_KEY",
	},
	{
		// Google API key: AIza followed by 35 alphanumeric/dash/underscore chars.
		// (Google API anahtarı: AIza ile başlayıp 35 alfanümerik/tire/alt çizgi karakter.)
		Name:   "Google API Key",
		Type:   TypeToken,
		Regex:  regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
		Prefix: "GOOG_KEY",
	},
	{
		// Slack tokens: xoxb- (bot), xoxp- (user), xoxa- (app), xoxs- (session).
		// (Slack jetonları: xoxb- (bot), xoxp- (kullanıcı), xoxa- (uygulama), xoxs- (oturum).)
		Name:   "Slack Token",
		Type:   TypeToken,
		Regex:  regexp.MustCompile(`\bxox[bpas]-[A-Za-z0-9\-]{20,}\b`),
		Prefix: "SLACK_TOK",
	},
	{
		// Stripe live-mode keys: sk_live_... (secret) and pk_live_... (publishable).
		// Test keys (sk_test_) are also matched to catch accidental exposure.
		// (Stripe canlı mod anahtarları: sk_live_... (gizli) ve pk_live_... (yayımlanabilir).
		//  Test anahtarları da (sk_test_) kazara ifşayı yakalamak için eşleştirilir.)
		Name:   "Stripe API Key",
		Type:   TypeToken,
		Regex:  regexp.MustCompile(`\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b`),
		Prefix: "STRIPE_KEY",
	},
	{
		// Standalone JWT (3-part base64url without a "Bearer" prefix).
		// The Bearer Token pattern above already handles "Bearer eyJ..." — this
		// catches raw JWTs embedded directly in JSON body fields.
		// Header and payload both start with eyJ (base64url of '{"').
		// (Standalone JWT — "Bearer" öneki olmadan, doğrudan JSON alanında gömülü.
		//  Üstteki Bearer Token deseni "Bearer eyJ..." yi zaten yakalıyor; bu desen
		//  JSON gövdesine doğrudan gömülü ham JWT'leri yakalar.)
		Name:   "JWT (standalone)",
		Type:   TypeToken,
		Regex:  regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`),
		Prefix: "JWT",
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
		// The drive letter must stand alone (preceded by start-of-string or a
		// non-alphanumeric character) — otherwise this matches the tail of an
		// ordinary word followed by a JSON-escaped colon/backslash sequence,
		// e.g. "output:\n{" inside a JSON string, corrupting the JSON.
		// (Windows mutlak yolları. Sürücü harfi tek başına durmalı (dizinin
		//  başında veya alfanümerik olmayan bir karakterden sonra) — aksi
		//  halde bu, sıradan bir kelimenin sonu ile JSON kaçışlı iki nokta/
		//  ters eğik çizgi dizisini eşleştirir, örn. bir JSON dizesi içindeki
		//  "output:\n{", JSON'u bozar.)
		Name:       "Windows Absolute Path (Windows Mutlak Yol)",
		Type:       TypePath,
		Regex:      regexp.MustCompile(`(?:^|[^A-Za-z0-9])([A-Za-z]:\\(?:[^\\/:\*\?"<>|\n]+\\)+[^\\/:\*\?"<>|\n]*)`),
		Prefix:     "WIN_PATH",
		GroupIndex: 1,
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
		Name:     "Credit Card Number (Kredi Kartı Numarası)",
		Type:     TypePII,
		Regex:    regexp.MustCompile(`\b(?:\d{4}[\s\-]?){3}\d{1,4}\b`),
		Prefix:   "CC",
		Validate: validateLuhn,
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
		// Turkish National ID (TC Kimlik No): 11 digits, first digit 1-9.
		// Regex narrows to [1-9]\d{10}; validateTCKimlik enforces the official
		// two-step checksum, eliminating false positives (order IDs, timestamps…).
		// (TC Kimlik No: ilk hane 1-9, 11 hane. validateTCKimlik resmi iki aşamalı
		//  sağlama toplamını uygular; sipariş no, zaman damgası gibi yanlış pozitifleri
		//  ortadan kaldırır.)
		Name:     "Turkish National ID (TC Kimlik No)",
		Type:     TypePII,
		Regex:    regexp.MustCompile(`\b[1-9]\d{10}\b`),
		Prefix:   "TR_ID",
		Validate: validateTCKimlik,
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

	// ── National ID numbers (Ulusal Kimlik Numaraları) ───────────────────────

	{
		// Brazilian CPF: 11 digits, optional formatting (000.000.000-00).
		// All-same-digit CPFs (e.g. 11111111111) are invalid by law.
		// Regex matches both formatted and bare forms; validator runs the
		// two-step weighted mod-11 checksum.
		Name:     "Brazilian CPF",
		Type:     TypePII,
		Regex:    regexp.MustCompile(`\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b`),
		Prefix:   "BR_CPF",
		Validate: validateCPF,
	},
	{
		// Spanish DNI: 8 digits followed immediately by one control letter.
		// Letter = "TRWAGMYFPDXBNJZSQVHLCKE"[number % 23].
		Name:     "Spanish DNI",
		Type:     TypePII,
		Regex:    regexp.MustCompile(`\b\d{8}[TRWAGMYFPDXBNJZSQVHLCKE]\b`),
		Prefix:   "ES_DNI",
		Validate: validateDNI,
	},
	{
		// Indian Aadhaar: 12 digits, first digit 2-9.
		// Validated with the Verhoeff dihedral-group checksum algorithm.
		Name:     "Indian Aadhaar",
		Type:     TypePII,
		Regex:    regexp.MustCompile(`\b[2-9]\d{11}\b`),
		Prefix:   "IN_AADHAAR",
		Validate: validateAadhaar,
	},
	{
		// Italian Codice Fiscale: 16 chars — 6 letters + 2 digits + letter +
		// 2 digits + letter + 3 digits + control letter.
		// Control char: (sum of odd-position special values + even-position
		// alphanumeric values) % 26 → A-Z.
		Name:     "Italian Codice Fiscale",
		Type:     TypePII,
		Regex:    regexp.MustCompile(`(?i)\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b`),
		Prefix:   "IT_CF",
		Validate: validateCodiceFiscale,
	},
}
