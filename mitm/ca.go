// Package mitm implements a transparent Man-in-the-Middle proxy that intercepts
// TLS connections to known AI providers, enabling the firewall to mask/unmask
// sensitive data in transit.
//
// (Bilinen AI sağlayıcılarına yapılan TLS bağlantılarını yakalayan şeffaf bir
//
//	Ortadaki Adam (MITM) proxy'si uygular. Güvenlik duvarının aktarım sırasında
//	hassas verileri maskelemesini/maskesini kaldırmasını sağlar.)
package mitm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ════════════════════════════════════════════════════════════════════════════
// CA — Certificate Authority (Sertifika Otoritesi)
// ════════════════════════════════════════════════════════════════════════════

// CA holds the root certificate authority used for signing leaf certificates.
// It is safe for concurrent use from multiple goroutines.
//
// (Yaprak sertifikaları imzalamak için kullanılan kök sertifika otoritesini tutar.
//
//	Birden fazla goroutine'den eşzamanlı kullanım için güvenlidir.)
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte

	// leafCache stores generated leaf certificates per hostname.
	// sync.Map provides lock-free reads for the hot path (concurrent TLS handshakes).
	// (Ana bilgisayar adı başına üretilen yaprak sertifikalarını depolar.
	//  sync.Map, sıcak yol (eşzamanlı TLS el sıkışmaları) için kilitsiz okumalar sağlar.)
	leafCache sync.Map // hostname → *leafCacheEntry
}

// leafCacheEntry wraps a cached leaf certificate with its expiry time.
// (Önbelleğe alınmış bir yaprak sertifikasını son kullanma zamanıyla sarar.)
type leafCacheEntry struct {
	cert    *tls.Certificate
	expires time.Time
}

const (
	caValidityYears   = 10
	leafValidityHours = 24
	caCommonName      = "AI Firewall CA"
	caOrganization    = "AI Firewall"
)

// ════════════════════════════════════════════════════════════════════════════
// LoadOrCreateCA (CA Yükle veya Oluştur)
// ════════════════════════════════════════════════════════════════════════════

// LoadOrCreateCA loads an existing CA certificate and key from disk,
// or generates a new ECDSA P-256 CA if the files don't exist.
// The CA is persisted to certPath and keyPath for reuse across restarts.
//
// (Mevcut bir CA sertifikasını ve anahtarını diskten yükler veya dosyalar
//
//	yoksa yeni bir ECDSA P-256 CA oluşturur. CA, yeniden başlatmalarda
//	kullanılmak üzere certPath ve keyPath'e kaydedilir.)
func LoadOrCreateCA(certPath, keyPath string) (*CA, error) {
	// Try to load existing CA from disk.
	// (Diskten mevcut CA'yı yüklemeyi dene.)
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return loadCA(certPath, keyPath)
		}
	}

	// Generate new CA.
	// (Yeni CA oluştur.)
	return generateAndSaveCA(certPath, keyPath)
}

// loadCA reads an existing CA certificate and key from PEM files.
// Supports both plain and passphrase-encrypted key files (backward-compatible).
// Set AI_FIREWALL_CA_PASSPHRASE to load an encrypted key.
//
// (PEM dosyalarından mevcut bir CA sertifikasını ve anahtarını okur.
//
//	Hem düz hem de passphrase ile şifrelenmiş anahtar dosyalarını destekler.
//	Şifreli anahtarı yüklemek için AI_FIREWALL_CA_PASSPHRASE ayarlayın.)
func loadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA cert: %w", err)
	}

	keyFileBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("invalid CA cert PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyFileBytes)
	if keyBlock == nil {
		return nil, fmt.Errorf("invalid CA key PEM")
	}

	// Resolve the raw DER bytes — handling both encrypted and plain key files.
	// (Hem şifreli hem de düz anahtar dosyalarını işleyerek ham DER baytlarını çöz.)
	var keyDER []byte
	switch keyBlock.Type {
	case "ENCRYPTED EC PRIVATE KEY":
		passphrase := os.Getenv("AI_FIREWALL_CA_PASSPHRASE")
		if passphrase == "" {
			return nil, fmt.Errorf(
				"CA key is encrypted but AI_FIREWALL_CA_PASSPHRASE is not set")
		}
		keyDER, err = decryptKeyDER(keyBlock, passphrase)
		if err != nil {
			return nil, fmt.Errorf("decrypting CA key — wrong passphrase?: %w", err)
		}
		log.Printf("[mitm][info] 🔑 CA key decrypted successfully")
	case "EC PRIVATE KEY":
		if passphrase := os.Getenv("AI_FIREWALL_CA_PASSPHRASE"); passphrase != "" {
			log.Printf("[mitm][warn] ⚠️  AI_FIREWALL_CA_PASSPHRASE is set but the CA key " +
				"on disk is unencrypted. Delete the key file and restart to re-generate " +
				"with passphrase protection.")
		}
		keyDER = keyBlock.Bytes
	default:
		return nil, fmt.Errorf("unknown CA key PEM block type %q", keyBlock.Type)
	}

	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("parsing CA key: %w", err)
	}

	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

// ════════════════════════════════════════════════════════════════════════════
// CA Generation (CA Üretimi)
// ════════════════════════════════════════════════════════════════════════════

// generateAndSaveCA creates a new self-signed ECDSA P-256 CA and saves it to disk.
// (Yeni bir öz-imzalı ECDSA P-256 CA oluşturur ve diske kaydeder.)
func generateAndSaveCA(certPath, keyPath string) (*CA, error) {
	// Generate ECDSA P-256 key pair.
	// P-256 is 3-10x faster than RSA-2048 for TLS handshakes, and is the
	// default curve for modern TLS implementations.
	// (P-256, TLS el sıkışmaları için RSA-2048'den 3-10 kat daha hızlıdır
	//  ve modern TLS uygulamaları için varsayılan eğridir.)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}

	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   caCommonName,
			Organization: []string{caOrganization},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour), // 1 hour grace for clock skew (saat sapması için 1 saat tolerans)
		NotAfter:              time.Now().AddDate(caValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing generated CA cert: %w", err)
	}

	// Encode to PEM.
	// (PEM olarak kodla.)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling CA key: %w", err)
	}

	// Encrypt the private key if AI_FIREWALL_CA_PASSPHRASE is set.
	// Without a passphrase the key is stored as a plain 0600 PEM file and a warning is logged.
	// (AI_FIREWALL_CA_PASSPHRASE ayarlanmışsa özel anahtarı şifrele.
	//  Passphrase yoksa anahtar düz 0600 PEM olarak kaydedilir ve uyarı loglanır.)
	var keyPEM []byte
	if passphrase := os.Getenv("AI_FIREWALL_CA_PASSPHRASE"); passphrase != "" {
		keyPEM, err = encryptKeyPEM(keyDER, passphrase)
		if err != nil {
			return nil, fmt.Errorf("encrypting CA key: %w", err)
		}
		log.Printf("[mitm][info] 🔑 CA key encrypted with AES-256-GCM")
	} else {
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		log.Printf("[mitm][warn] ⚠️  WARNING: CA private key written WITHOUT encryption.")
		log.Printf("[mitm][warn]     The key can sign certificates for ANY domain on this machine.")
		log.Printf("[mitm][warn]     To protect it, set a passphrase and regenerate:")
		log.Printf("[mitm][warn]       export AI_FIREWALL_CA_PASSPHRASE=\"<strong-passphrase>\"")
		log.Printf("[mitm][warn]     Stored at: %s", keyPath)
	}

	// Ensure directory exists.
	// (Dizinin var olduğundan emin ol.)
	certDir := filepath.Dir(certPath)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("creating cert directory: %w", err)
	}

	// Write a .gitignore that excludes everything in this directory, so the CA
	// key and cert are never accidentally committed to version control.
	// (Dizindeki her şeyi hariç tutan .gitignore yaz; CA anahtarı ve sertifikasının
	//  yanlışlıkla sürüm kontrolüne eklenmesini önler.)
	gitignorePath := filepath.Join(certDir, ".gitignore")
	if _, err := os.Stat(gitignorePath); os.IsNotExist(err) {
		_ = os.WriteFile(gitignorePath, []byte("*\n"), 0644)
	}

	// Write files with restrictive permissions.
	// Cert is world-readable (clients may need it); key is owner-only.
	// (Sertifika herkese açık okunabilir (istemcilere gerekebilir); anahtar yalnızca sahibe açık.)
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("writing CA cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("writing CA key: %w", err)
	}

	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

// ════════════════════════════════════════════════════════════════════════════
// Leaf Certificate (Yaprak Sertifika)
// ════════════════════════════════════════════════════════════════════════════

// LeafCert returns a TLS certificate for the given hostname, using a cached
// version if available and not expired. Leaf certificates are valid for 24 hours.
//
// (Verilen ana bilgisayar adı için bir TLS sertifikası döner; varsa ve
//
//	süresi dolmamışsa önbelleğe alınmış sürümü kullanır.
//	Yaprak sertifikalar 24 saat geçerlidir.)
func (ca *CA) LeafCert(hostname string) (*tls.Certificate, error) {
	// Check cache first (hot path — lock-free read via sync.Map).
	// (Önce önbelleği kontrol et (sıcak yol — sync.Map ile kilitsiz okuma).)
	if cached, ok := ca.leafCache.Load(hostname); ok {
		entry := cached.(*leafCacheEntry)
		if time.Now().Before(entry.expires) {
			return entry.cert, nil
		}
		// Expired — generate a new one below.
		// (Süresi doldu — aşağıda yeni bir tane oluştur.)
		ca.leafCache.Delete(hostname)
	}

	// Generate a new leaf certificate signed by this CA.
	// (Bu CA tarafından imzalanmış yeni bir yaprak sertifika oluştur.)
	cert, err := ca.generateLeaf(hostname)
	if err != nil {
		return nil, err
	}

	// Cache it for subsequent requests to the same host.
	// (Aynı ana bilgisayara yapılan sonraki istekler için önbelleğe al.)
	ca.leafCache.Store(hostname, &leafCacheEntry{
		cert:    cert,
		expires: time.Now().Add(leafValidityHours * time.Hour),
	})

	return cert, nil
}

// generateLeaf creates a leaf certificate for hostname, signed by this CA.
// The certificate includes the hostname as a Subject Alternative Name (SAN).
//
// (Hostname için bu CA tarafından imzalanmış bir yaprak sertifika oluşturur.
//
//	Sertifika, hostname'i Konu Alternatif Adı (SAN) olarak içerir.)
func (ca *CA) generateLeaf(hostname string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating leaf key for %s: %w", hostname, err)
	}

	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{caOrganization},
		},
		DNSNames:  []string{hostname},
		NotBefore: time.Now().Add(-5 * time.Minute), // small grace for clock skew (saat sapması için küçük tolerans)
		NotAfter:  time.Now().Add(leafValidityHours * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("signing leaf cert for %s: %w", hostname, err)
	}

	// Return TLS certificate with the full chain: [leaf, CA].
	// (Tam zincirle TLS sertifikası döndür: [yaprak, CA].)
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER, ca.cert.Raw},
		PrivateKey:  key,
	}

	return tlsCert, nil
}

// ════════════════════════════════════════════════════════════════════════════
// Helpers (Yardımcı Fonksiyonlar)
// ════════════════════════════════════════════════════════════════════════════

// CertPEM returns the CA certificate in PEM format.
// Used by install.go to write the certificate to the system trust store.
//
// (CA sertifikasını PEM formatında döner.
//
//	install.go tarafından sertifikayı sistem güven deposuna yazmak için kullanılır.)
func (ca *CA) CertPEM() []byte {
	return ca.certPEM
}

// randomSerialNumber generates a cryptographically random 128-bit serial number
// for X.509 certificates, as required by RFC 5280 §4.1.2.2.
//
// (X.509 sertifikaları için kriptografik olarak rastgele 128-bit seri numarası
//
//	üretir, RFC 5280 §4.1.2.2 gereksinimine uygun.)
func randomSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}
	return serialNumber, nil
}

// ════════════════════════════════════════════════════════════════════════════
// Key Encryption Helpers (Anahtar Şifreleme Yardımcıları)
// ════════════════════════════════════════════════════════════════════════════

// encryptKeyPEM encrypts DER-encoded EC private key bytes with AES-256-GCM.
// The 32-byte cipher key is derived from the passphrase via SHA-256.
// The 12-byte random nonce is prepended to the ciphertext inside the PEM block.
// Returns a PEM block of type "ENCRYPTED EC PRIVATE KEY".
//
// SECURITY TRADE-OFF: SHA-256(passphrase) is a raw hash, not a password-based
// key derivation function (KDF). It provides no brute-force resistance against
// offline dictionary attacks. For stronger protection — especially if the CA key
// file may be exposed — replace this with a proper KDF such as scrypt or Argon2id
// (golang.org/x/crypto/scrypt or golang.org/x/crypto/argon2). This is an
// accepted trade-off for a local CA key: the key file itself is 0600 and the
// passphrase is delivered via environment variable, not stored on disk.
//
// (DER kodlu EC özel anahtar baytlarını AES-256-GCM ile şifreler.
//
//	32 baytlık şifre anahtarı passphrase'den SHA-256 ile türetilir.
//	12 baytlık rastgele nonce, PEM bloğu içinde şifreli metnin başına eklenir.
//	"ENCRYPTED EC PRIVATE KEY" türünde PEM bloğu döner.
//
//	GÜVENLİK TRADE-OFF: SHA-256(passphrase) ham bir özetleme işlemidir; parola
//	tabanlı anahtar türetme işlevi (KDF) değildir. Çevrimdışı sözlük saldırılarına
//	karşı kaba-kuvvet direnci sağlamaz. Daha güçlü koruma için scrypt veya
//	Argon2id kullanılabilir. Yerel CA anahtarı için kabul edilebilir bir
//	trade-off'tur: anahtar dosyası 0600 izinlidir ve passphrase ortam değişkeniyle
//	iletilir, diske yazılmaz.)
func encryptKeyPEM(keyDER []byte, passphrase string) ([]byte, error) {
	h := sha256.Sum256([]byte(passphrase))

	block, err := aes.NewCipher(h[:])
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// Prepend nonce to ciphertext so decryption can recover it.
	// (Nonce'ı şifreli metnin başına ekle; çözümlemede kurtarılabilmesi için.)
	sealed := gcm.Seal(nonce, nonce, keyDER, nil)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED EC PRIVATE KEY",
		Bytes: sealed,
	}), nil
}

// decryptKeyDER decrypts an "ENCRYPTED EC PRIVATE KEY" PEM block back to DER bytes.
// The cipher key is derived from the passphrase the same way as encryptKeyPEM.
//
// (Bir "ENCRYPTED EC PRIVATE KEY" PEM bloğunu tekrar DER baytlarına çözer.
//
//	Şifre anahtarı, encryptKeyPEM ile aynı şekilde passphrase'den türetilir.)
func decryptKeyDER(block *pem.Block, passphrase string) ([]byte, error) {
	h := sha256.Sum256([]byte(passphrase))

	c, err := aes.NewCipher(h[:])
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	if len(block.Bytes) < gcm.NonceSize() {
		return nil, fmt.Errorf("encrypted key data too short")
	}

	nonce, ciphertext := block.Bytes[:gcm.NonceSize()], block.Bytes[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed — wrong passphrase?: %w", err)
	}
	return plain, nil
}
