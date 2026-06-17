package mitm

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
)

// ════════════════════════════════════════════════════════════════════════════
// CA Trust Store Installation (CA Güven Deposu Yüklemesi)
// ════════════════════════════════════════════════════════════════════════════

// InstallCA installs the CA certificate at certPath into the operating system's
// trusted root certificate store. This allows clients to trust the MITM proxy's
// leaf certificates without manual configuration.
//
// Requires elevated privileges (sudo on macOS/Linux, Administrator on Windows).
// Returns a clear error with manual instructions if it fails due to permissions.
//
// (certPath'teki CA sertifikasını işletim sisteminin güvenilir kök sertifika
//
//	deposuna yükler. Bu, istemcilerin MITM proxy'sinin yaprak sertifikalarına
//	elle yapılandırma olmadan güvenmesini sağlar.
//	Yükseltilmiş ayrıcalıklar gerektirir (macOS/Linux'ta sudo, Windows'ta Yönetici).
//	İzin nedeniyle başarısız olursa elle talimatlar içeren açık bir hata döner.)
func InstallCA(certPath string) error {
	switch runtime.GOOS {
	case "darwin":
		return installDarwin(certPath)
	case "linux":
		return installLinux(certPath)
	case "windows":
		return installWindows(certPath)
	default:
		return fmt.Errorf("unsupported OS for CA installation: %s\n"+
			"Please manually install the CA certificate at: %s", runtime.GOOS, certPath)
	}
}

// CheckInstalled checks whether the AI Firewall CA is already installed
// in the system trust store. Returns false if the check fails for any reason.
//
// (AI Firewall CA'sının sistem güven deposuna zaten yüklenip yüklenmediğini
//
//	kontrol eder. Herhangi bir nedenle kontrol başarısız olursa false döner.)
func CheckInstalled() bool {
	switch runtime.GOOS {
	case "darwin":
		return checkDarwin()
	case "linux":
		return checkLinux()
	case "windows":
		return checkWindows()
	default:
		return false
	}
}

// ════════════════════════════════════════════════════════════════════════════
// macOS — System Keychain (Sistem Anahtarlığı)
// ════════════════════════════════════════════════════════════════════════════

func installDarwin(certPath string) error {
	log.Printf("[mitm][info] installing CA to macOS System Keychain...")

	// security add-trusted-cert adds a certificate to the system keychain
	// and marks it as a trusted root CA.
	// -d: add to admin trust settings domain
	// -r trustRoot: mark as a trusted root certificate
	// -k: specify the target keychain
	cmd := exec.Command("security", "add-trusted-cert",
		"-d",
		"-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain",
		certPath,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("macOS CA installation failed: %v\n"+
			"Output: %s\n"+
			"Run with sudo:\n"+
			"  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s",
			err, output, certPath)
	}

	log.Printf("[mitm][info] ✅ CA installed to macOS System Keychain")
	return nil
}

func checkDarwin() bool {
	cmd := exec.Command("security", "find-certificate",
		"-c", caCommonName,
		"/Library/Keychains/System.keychain",
	)
	return cmd.Run() == nil
}

// ════════════════════════════════════════════════════════════════════════════
// Linux — /usr/local/share/ca-certificates
// ════════════════════════════════════════════════════════════════════════════

const (
	linuxCertDir  = "/usr/local/share/ca-certificates"
	linuxCertFile = "ai-firewall.crt"
)

func installLinux(certPath string) error {
	log.Printf("[mitm][info] installing CA to Linux trust store...")

	targetPath := linuxCertDir + "/" + linuxCertFile

	// Step 1: Copy cert to the system CA certificates directory.
	// (Adım 1: Sertifikayı sistem CA sertifikaları dizinine kopyala.)
	cpCmd := exec.Command("cp", certPath, targetPath)
	if output, err := cpCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("copying CA cert failed: %v\n"+
			"Output: %s\n"+
			"Run with sudo:\n"+
			"  sudo cp %s %s && sudo update-ca-certificates",
			err, output, certPath, targetPath)
	}

	// Step 2: Update the system CA bundle to include the new cert.
	// (Adım 2: Yeni sertifikayı dahil etmek için sistem CA paketini güncelle.)
	updateCmd := exec.Command("update-ca-certificates")
	if output, err := updateCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("update-ca-certificates failed: %v\n"+
			"Output: %s\n"+
			"Run with sudo:\n"+
			"  sudo update-ca-certificates",
			err, output)
	}

	log.Printf("[mitm][info] ✅ CA installed to Linux trust store")
	return nil
}

func checkLinux() bool {
	targetPath := linuxCertDir + "/" + linuxCertFile
	// Use stat to check if the cert file exists in the system directory.
	// exec.Command("test", "-f", ...) may not work in all environments.
	cmd := exec.Command("stat", targetPath)
	return cmd.Run() == nil
}

// ════════════════════════════════════════════════════════════════════════════
// Windows — certutil (Sertifika Yardımcı Programı)
// ════════════════════════════════════════════════════════════════════════════

func installWindows(certPath string) error {
	log.Printf("[mitm][info] installing CA to Windows trust store...")

	// certutil -addstore adds a certificate to a specified certificate store.
	// -f: force overwrite if already present
	// "ROOT": the Trusted Root Certification Authorities store
	cmd := exec.Command("certutil", "-addstore", "-f", "ROOT", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Windows CA installation failed: %v\n"+
			"Output: %s\n"+
			"Run as Administrator:\n"+
			"  certutil -addstore -f ROOT %s",
			err, output, certPath)
	}

	log.Printf("[mitm][info] ✅ CA installed to Windows trust store")
	return nil
}

func checkWindows() bool {
	// certutil -verifystore checks if a certificate exists in the specified store.
	cmd := exec.Command("certutil", "-verifystore", "ROOT", caCommonName)
	return cmd.Run() == nil
}

// ════════════════════════════════════════════════════════════════════════════
// CA Trust Store Removal (CA Güven Deposundan Kaldırma)
// ════════════════════════════════════════════════════════════════════════════

// osCmd is a minimal command specification: a program name and its arguments.
// Keeping it separate from exec.Command lets tests inspect the intended invocation
// without actually executing anything.
//
// (Program adı ve argümanlarından oluşan minimal komut tanımı.
//
//	exec.Command'dan ayrı tutulması, testlerin gerçekten çalıştırmadan
//	amaçlanan çağrıyı incelemesini sağlar.)
type osCmd struct {
	prog string
	args []string
}

// UninstallCA removes the AI Firewall CA certificate from the operating
// system's trusted root certificate store.
//
// Requires elevated privileges (sudo on macOS/Linux, Administrator on Windows).
// Returns a clear error with manual instructions if it fails due to permissions.
//
// (AI Firewall CA sertifikasını işletim sisteminin güvenilir kök sertifika
// deposundan kaldırır. Yükseltilmiş ayrıcalıklar gerektirir (macOS/Linux'ta
// sudo, Windows'ta Yönetici). İzin nedeniyle başarısız olursa elle talimatlar
// içeren açık bir hata döner.)
func UninstallCA(certPath string) error {
	switch runtime.GOOS {
	case "darwin":
		return uninstallDarwin(certPath)
	case "linux":
		return uninstallLinux(certPath)
	case "windows":
		return uninstallWindows(certPath)
	default:
		return fmt.Errorf("unsupported OS for CA removal: %s\n"+
			"Please manually remove the certificate with CN=%q from your system trust store.",
			runtime.GOOS, caCommonName)
	}
}

// ── macOS — System Keychain removal (Sistem Anahtarlığından Kaldırma) ────────

// darwinUninstallCmds returns the OS command specifications for removing the
// AI Firewall CA from the macOS System Keychain. Separated from execution so
// unit tests can verify arguments without running the command.
//
// (macOS Sistem Anahtarlığından CA'yı kaldırmak için OS komut tanımlarını döner.
// Birim testlerinin komutu çalıştırmadan argümanları doğrulayabilmesi için
// yürütmeden ayrılmıştır.)
func darwinUninstallCmds() []osCmd {
	return []osCmd{
		{
			prog: "security",
			args: []string{
				"delete-certificate",
				"-c", caCommonName,
				"/Library/Keychains/System.keychain",
			},
		},
	}
}

func uninstallDarwin(_ string) error {
	log.Printf("[mitm][info] removing CA from macOS System Keychain...")

	for _, s := range darwinUninstallCmds() {
		output, err := exec.Command(s.prog, s.args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("macOS CA removal failed: %v\n"+
				"Output: %s\n"+
				"Run with sudo:\n"+
				"  sudo security delete-certificate -c %q /Library/Keychains/System.keychain",
				err, output, caCommonName)
		}
	}

	log.Printf("[mitm][info] ✅ CA removed from macOS System Keychain")
	return nil
}

// ── Linux — /usr/local/share/ca-certificates removal ─────────────────────────

// linuxUninstallCmds returns the OS command specifications for removing the
// AI Firewall CA from the Linux system trust store.
//
// (Linux sistem güven deposundan CA'yı kaldırmak için OS komut tanımlarını döner.)
func linuxUninstallCmds() []osCmd {
	targetPath := linuxCertDir + "/" + linuxCertFile
	return []osCmd{
		{prog: "rm", args: []string{"-f", targetPath}},
		{prog: "update-ca-certificates", args: nil},
	}
}

func uninstallLinux(_ string) error {
	log.Printf("[mitm][info] removing CA from Linux trust store...")

	targetPath := linuxCertDir + "/" + linuxCertFile

	rmCmd := exec.Command("rm", "-f", targetPath)
	if output, err := rmCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("removing CA cert failed: %v\n"+
			"Output: %s\n"+
			"Run with sudo:\n"+
			"  sudo rm -f %s && sudo update-ca-certificates",
			err, output, targetPath)
	}

	updateCmd := exec.Command("update-ca-certificates")
	if output, err := updateCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("update-ca-certificates failed after removal: %v\n"+
			"Output: %s\n"+
			"Run with sudo:\n"+
			"  sudo update-ca-certificates",
			err, output)
	}

	log.Printf("[mitm][info] ✅ CA removed from Linux trust store")
	return nil
}

// ── Windows — certutil ROOT store removal ─────────────────────────────────────

// windowsUninstallCmds returns the OS command specification for removing the
// AI Firewall CA from the Windows ROOT certificate store.
//
// (Windows ROOT sertifika deposundan CA'yı kaldırmak için OS komut tanımını döner.)
func windowsUninstallCmds() []osCmd {
	return []osCmd{
		{prog: "certutil", args: []string{"-delstore", "ROOT", caCommonName}},
	}
}

func uninstallWindows(_ string) error {
	log.Printf("[mitm][info] removing CA from Windows trust store...")

	for _, s := range windowsUninstallCmds() {
		output, err := exec.Command(s.prog, s.args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("Windows CA removal failed: %v\n"+
				"Output: %s\n"+
				"Run as Administrator:\n"+
				"  certutil -delstore ROOT %q",
				err, output, caCommonName)
		}
	}

	log.Printf("[mitm][info] ✅ CA removed from Windows trust store")
	return nil
}
