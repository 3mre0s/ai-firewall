package mitm

// Tests for the uninstall command builders verify that each platform's
// removal logic targets the correct program and arguments without actually
// executing the OS commands.
//
// (Her platformun kaldırma mantığının gerçekten çalıştırmadan doğru program
// ve argümanları hedeflediğini doğrulayan kaldırma komutu oluşturucu testleri.)

import "testing"

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
