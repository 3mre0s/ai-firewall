package mitm

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestCAKeyRoundTripWithPassphrase writes the CA key encrypted (when
// AI_FIREWALL_CA_PASSPHRASE is set), then loads it back and verifies
// the private key is byte-for-byte identical.
//
// (AI_FIREWALL_CA_PASSPHRASE ayarlandığında CA anahtarının şifreli yazıldığını,
//
//	ardından geri yüklendiğinde özel anahtarın birebir aynı olduğunu doğrular.)
func TestCAKeyRoundTripWithPassphrase(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	t.Setenv("AI_FIREWALL_CA_PASSPHRASE", "test-passphrase-round-trip-123")

	// Generate and save.
	// (Oluştur ve kaydet.)
	ca1, err := LoadOrCreateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateCA (generate): %v", err)
	}

	// Key file must use the encrypted PEM block type, not plain-text.
	// (Anahtar dosyası düz metin değil şifreli PEM blok türünü kullanmalı.)
	keyRaw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("reading key file: %v", err)
	}
	if bytes.Contains(keyRaw, []byte("BEGIN EC PRIVATE KEY\n")) {
		t.Error("key file contains a plain-text PEM block — expected encrypted block when passphrase is set")
	}
	if !bytes.Contains(keyRaw, []byte("BEGIN ENCRYPTED EC PRIVATE KEY")) {
		t.Errorf("key file does not contain an encrypted PEM block; got:\n%s", keyRaw)
	}

	// Load back using the same passphrase.
	// (Aynı passphrase ile geri yükle.)
	ca2, err := LoadOrCreateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateCA (load): %v", err)
	}

	// Certificate PEM must be identical (same public identity).
	// (Sertifika PEM aynı olmalı — aynı genel kimlik.)
	if !bytes.Equal(ca1.certPEM, ca2.certPEM) {
		t.Error("certPEM mismatch after encrypted round-trip")
	}

	// Private key scalar D must be identical — this proves the same key was recovered.
	// (Özel anahtar skaleri D aynı olmalı — aynı anahtarın kurtarıldığını kanıtlar.)
	if ca1.key.D.Cmp(ca2.key.D) != 0 {
		t.Error("private key D mismatch after encrypted round-trip — decryption produced a different key")
	}
}

// TestCAKeyRoundTripNoPassphrase verifies backward-compatible plain-key storage
// when no passphrase is set.
//
// (Passphrase ayarlanmadığında geriye-uyumlu düz anahtar depolamayı doğrular.)
func TestCAKeyRoundTripNoPassphrase(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	t.Setenv("AI_FIREWALL_CA_PASSPHRASE", "")

	ca1, err := LoadOrCreateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateCA (generate): %v", err)
	}

	// Key file must NOT be encrypted when passphrase is absent.
	// (Passphrase yokken anahtar dosyası şifrelenmemiş olmalı.)
	keyRaw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("reading key file: %v", err)
	}
	if bytes.Contains(keyRaw, []byte("ENCRYPTED")) {
		t.Error("key file should be unencrypted when AI_FIREWALL_CA_PASSPHRASE is not set")
	}
	if !bytes.Contains(keyRaw, []byte("BEGIN EC PRIVATE KEY")) {
		t.Errorf("expected plain EC PRIVATE KEY PEM block; got:\n%s", keyRaw)
	}

	ca2, err := LoadOrCreateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateCA (load): %v", err)
	}

	if !bytes.Equal(ca1.certPEM, ca2.certPEM) {
		t.Error("certPEM mismatch after plain round-trip")
	}
	if ca1.key.D.Cmp(ca2.key.D) != 0 {
		t.Error("private key D mismatch after plain round-trip")
	}
}

// TestCAKeyWrongPassphraseReturnsError verifies that loading an encrypted key
// with the wrong passphrase returns an error rather than silently producing a bad key.
//
// (Şifreli anahtarın yanlış passphrase ile yüklenmesinin hatalı anahtar üretmek
//
//	yerine hata döndürdüğünü doğrular.)
func TestCAKeyWrongPassphraseReturnsError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	t.Setenv("AI_FIREWALL_CA_PASSPHRASE", "correct-passphrase")
	if _, err := LoadOrCreateCA(certPath, keyPath); err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Switch to wrong passphrase and attempt to load.
	// (Yanlış passphrase ile yüklemeyi dene.)
	t.Setenv("AI_FIREWALL_CA_PASSPHRASE", "wrong-passphrase")
	_, err := loadCA(certPath, keyPath)
	if err == nil {
		t.Error("expected error when loading with wrong passphrase, got nil")
	}
}

// TestCAKeyEncryptedRequiresPassphrase verifies that loading an encrypted key
// without setting AI_FIREWALL_CA_PASSPHRASE returns a descriptive error.
//
// (AI_FIREWALL_CA_PASSPHRASE ayarlanmadan şifreli anahtar yüklenmeye
//
//	çalışıldığında açıklayıcı bir hata döndürüldüğünü doğrular.)
func TestCAKeyEncryptedRequiresPassphrase(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	t.Setenv("AI_FIREWALL_CA_PASSPHRASE", "some-passphrase")
	if _, err := LoadOrCreateCA(certPath, keyPath); err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Clear passphrase and attempt to load the encrypted key.
	// (Passphrase'i temizle ve şifreli anahtarı yüklemeyi dene.)
	t.Setenv("AI_FIREWALL_CA_PASSPHRASE", "")
	_, err := loadCA(certPath, keyPath)
	if err == nil {
		t.Error("expected error when passphrase env var is unset for an encrypted key, got nil")
	}
}
