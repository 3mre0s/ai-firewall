package mitm

// Tests for the uninstall command builders verify that each platform's
// removal logic targets the correct program and arguments without actually
// executing the OS commands.
//
// (Her platformun kaldırma mantığının gerçekten çalıştırmadan doğru program
// ve argümanları hedeflediğini doğrulayan kaldırma komutu oluşturucu testleri.)

import (
	"errors"
	"runtime"
	"testing"
)

type fakeCommandRunner struct {
	calls  []osCmd
	failAt int
}

func (f *fakeCommandRunner) next(prog string, args ...string) error {
	f.calls = append(f.calls, osCmd{prog: prog, args: append([]string(nil), args...)})
	if f.failAt > 0 && len(f.calls) == f.failAt {
		return errors.New("synthetic command failure")
	}
	return nil
}

func (f *fakeCommandRunner) CombinedOutput(prog string, args ...string) ([]byte, error) {
	err := f.next(prog, args...)
	return []byte("synthetic output"), err
}

func (f *fakeCommandRunner) Run(prog string, args ...string) error {
	return f.next(prog, args...)
}

func useFakeTrustStoreCommands(t *testing.T, fake *fakeCommandRunner) {
	t.Helper()
	previous := trustStoreCommands
	trustStoreCommands = fake
	t.Cleanup(func() { trustStoreCommands = previous })
}

func TestTrustStoreCommandsAcrossPlatforms(t *testing.T) {
	fake := &fakeCommandRunner{}
	useFakeTrustStoreCommands(t, fake)
	for name, operation := range map[string]func() error{
		"install darwin":    func() error { return installDarwin("/tmp/ca.crt") },
		"install linux":     func() error { return installLinux("/tmp/ca.crt") },
		"install windows":   func() error { return installWindows("C:\\ca.crt") },
		"uninstall darwin":  func() error { return uninstallDarwin("") },
		"uninstall linux":   func() error { return uninstallLinux("") },
		"uninstall windows": func() error { return uninstallWindows("") },
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); err != nil {
				t.Fatal(err)
			}
		})
	}
	if !checkDarwin() || !checkLinux() || !checkWindows() {
		t.Fatal("successful trust-store checks returned false")
	}
	if len(fake.calls) == 0 {
		t.Fatal("no trust-store commands were recorded")
	}
}

func TestTrustStoreCommandFailuresAreReported(t *testing.T) {
	operations := map[string]func() error{
		"install darwin":     func() error { return installDarwin("ca.crt") },
		"install linux copy": func() error { return installLinux("ca.crt") },
		"install windows":    func() error { return installWindows("ca.crt") },
		"uninstall darwin":   func() error { return uninstallDarwin("") },
		"uninstall linux rm": func() error { return uninstallLinux("") },
		"uninstall windows":  func() error { return uninstallWindows("") },
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			fake := &fakeCommandRunner{failAt: 1}
			previous := trustStoreCommands
			trustStoreCommands = fake
			defer func() { trustStoreCommands = previous }()
			if err := operation(); err == nil {
				t.Fatal("expected command failure")
			}
		})
	}
}

func TestCurrentPlatformDispatchUsesRunner(t *testing.T) {
	fake := &fakeCommandRunner{}
	useFakeTrustStoreCommands(t, fake)
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("unsupported test platform")
	}
	if err := InstallCA("ca.crt"); err != nil {
		t.Fatal(err)
	}
	if !CheckInstalled() {
		t.Fatal("CheckInstalled returned false")
	}
	if err := UninstallCA("ca.crt"); err != nil {
		t.Fatal(err)
	}
}

func TestPlatformDispatchMatrix(t *testing.T) {
	fake := &fakeCommandRunner{}
	useFakeTrustStoreCommands(t, fake)
	for _, goos := range []string{"darwin", "linux", "windows"} {
		if err := installCAForOS(goos, "ca.crt"); err != nil {
			t.Fatalf("install %s: %v", goos, err)
		}
		if !checkInstalledForOS(goos) {
			t.Fatalf("check %s returned false", goos)
		}
		if err := uninstallCAForOS(goos, "ca.crt"); err != nil {
			t.Fatalf("uninstall %s: %v", goos, err)
		}
	}
	if err := installCAForOS("plan9", "ca.crt"); err == nil {
		t.Fatal("unsupported install platform was accepted")
	}
	if checkInstalledForOS("plan9") {
		t.Fatal("unsupported check platform returned true")
	}
	if err := uninstallCAForOS("plan9", "ca.crt"); err == nil {
		t.Fatal("unsupported uninstall platform was accepted")
	}
}

func TestExecCommandRunner(t *testing.T) {
	runner := execCommandRunner{}
	if output, err := runner.CombinedOutput("go", "version"); err != nil || len(output) == 0 {
		t.Fatalf("CombinedOutput(go version) = %q, %v", output, err)
	}
	if err := runner.Run("go", "version"); err != nil {
		t.Fatalf("Run(go version): %v", err)
	}
}

func TestLinuxSecondCommandFailuresAreReported(t *testing.T) {
	for name, operation := range map[string]func() error{
		"install update":   func() error { return installLinux("ca.crt") },
		"uninstall update": func() error { return uninstallLinux("") },
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeCommandRunner{failAt: 2}
			previous := trustStoreCommands
			trustStoreCommands = fake
			defer func() { trustStoreCommands = previous }()
			if err := operation(); err == nil {
				t.Fatal("expected second command failure")
			}
		})
	}
}

// TestDarwinUninstallCmds verifies the macOS CA removal command.
// (macOS CA kaldırma komutunu doğrular.)
func TestDarwinUninstallCmds(t *testing.T) {
	t.Parallel()
	cmds := darwinUninstallCmds()
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	cmd := cmds[0]

	if cmd.prog != "security" {
		t.Errorf("program: want %q, got %q", "security", cmd.prog)
	}

	wantArgs := []string{
		"delete-certificate",
		"-c", caCommonName,
		"/Library/Keychains/System.keychain",
	}
	if len(cmd.args) != len(wantArgs) {
		t.Fatalf("arg count: want %d, got %d (args=%v)", len(wantArgs), len(cmd.args), cmd.args)
	}
	for i, want := range wantArgs {
		if cmd.args[i] != want {
			t.Errorf("arg[%d]: want %q, got %q", i, want, cmd.args[i])
		}
	}
}

// TestLinuxUninstallCmds verifies the Linux CA removal sequence: rm then
// update-ca-certificates, both targeting the correct system paths.
// (Linux CA kaldırma sırasını doğrular: rm ardından update-ca-certificates,
// her ikisi de doğru sistem yollarını hedeflemelidir.)
func TestLinuxUninstallCmds(t *testing.T) {
	t.Parallel()
	cmds := linuxUninstallCmds()
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}

	// First command: rm -f <target>
	rm := cmds[0]
	if rm.prog != "rm" {
		t.Errorf("cmd[0] program: want %q, got %q", "rm", rm.prog)
	}
	wantTarget := linuxCertDir + "/" + linuxCertFile
	if len(rm.args) < 2 || rm.args[len(rm.args)-1] != wantTarget {
		t.Errorf("cmd[0] last arg: want %q, got %v", wantTarget, rm.args)
	}
	if rm.args[0] != "-f" {
		t.Errorf("cmd[0] first arg: want %q, got %q", "-f", rm.args[0])
	}

	// Second command: update-ca-certificates (no arguments)
	update := cmds[1]
	if update.prog != "update-ca-certificates" {
		t.Errorf("cmd[1] program: want %q, got %q", "update-ca-certificates", update.prog)
	}
	if len(update.args) != 0 {
		t.Errorf("cmd[1] args: want none, got %v", update.args)
	}
}

// TestWindowsUninstallCmds verifies the Windows certutil removal command.
// (Windows certutil kaldırma komutunu doğrular.)
func TestWindowsUninstallCmds(t *testing.T) {
	t.Parallel()
	cmds := windowsUninstallCmds()
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	cmd := cmds[0]

	if cmd.prog != "certutil" {
		t.Errorf("program: want %q, got %q", "certutil", cmd.prog)
	}

	wantArgs := []string{"-delstore", "ROOT", caCommonName}
	if len(cmd.args) != len(wantArgs) {
		t.Fatalf("arg count: want %d, got %d (args=%v)", len(wantArgs), len(cmd.args), cmd.args)
	}
	for i, want := range wantArgs {
		if cmd.args[i] != want {
			t.Errorf("arg[%d]: want %q, got %q", i, want, cmd.args[i])
		}
	}
}

// TestUninstallCmdsTargetCaCommonName ensures every platform uses the correct
// certificate common name (caCommonName constant) so uninstall matches install.
// (Her platformun doğru sertifika ortak adını kullandığını (caCommonName sabiti)
// doğrular; kaldırma işlemi kurulum ile eşleşmelidir.)
func TestUninstallCmdsTargetCaCommonName(t *testing.T) {
	t.Parallel()

	checkName := func(platform string, cmds []osCmd) {
		for _, cmd := range cmds {
			for _, arg := range cmd.args {
				if arg == caCommonName {
					return
				}
			}
		}
		t.Errorf("[%s] caCommonName %q not found in any command argument", platform, caCommonName)
	}

	checkName("darwin", darwinUninstallCmds())
	checkName("windows", windowsUninstallCmds())
	// Linux uses the cert file name, not the CN — skip that platform for this check.
}
