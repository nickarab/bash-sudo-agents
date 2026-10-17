package evaluator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nickarab/bash-sudo-agents/pkg/contract"
)

func TestSymlinkToVitalDenied(t *testing.T) {
	home := tempHome(t)
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(proj, "link")); err != nil {
		t.Skipf("symlink não suportado: %v", err)
	}
	eng := New(home, nil)
	v := eng.Audit("rm -rf link", "", "", proj)
	if v.Decision != contract.Deny {
		t.Fatalf("symlink vital: want deny, got %s", v.Decision)
	}
}

func TestSymlinkLoopIsForceAsk(t *testing.T) {
	home := tempHome(t)
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	a := filepath.Join(proj, "a")
	b := filepath.Join(proj, "b")
	if err := os.Symlink(a, b); err != nil {
		t.Skipf("symlink não suportado: %v", err)
	}
	if err := os.Symlink(b, a); err != nil {
		t.Skipf("symlink não suportado: %v", err)
	}
	eng := New(home, nil)
	v := eng.Audit("rm -rf a", "", "", proj)
	if v.Decision != contract.ForceAsk {
		t.Fatalf("symlink loop: want force_ask, got %s", v.Decision)
	}
}

func TestDeepRecursionForceAsk(t *testing.T) {
	home := tempHome(t)
	eng := New(home, nil)
	cmd := "rm -rf /"
	for i := 0; i < 12; i++ {
		cmd = "bash -c " + quote(cmd)
	}
	if v := eng.Audit(cmd, "", "", home); v.Decision != contract.ForceAsk {
		t.Fatalf("recursão profunda: want force_ask, got %s", v.Decision)
	}
}

func TestHeredocInterpreterDenied(t *testing.T) {
	home := tempHome(t)
	eng := New(home, nil)
	cmd := "python3 - <<'EOF'\nimport os\nos.system(\"rm -rf /\")\nEOF"
	if v := eng.Audit(cmd, "", "", home); v.Decision != contract.Deny {
		t.Fatalf("heredoc destrutivo: want deny, got %s (%s)", v.Decision, v.Reason)
	}
}

func TestGovByCDPath(t *testing.T) {
	home := tempHome(t)
	eng := New(home, nil)
	cmd := "cd " + filepath.Join(home, ".gemini", "config") + " && rm hooks.json"
	if v := eng.Audit(cmd, "", "", home); v.Decision != contract.Deny {
		t.Fatalf("gov via cd: want deny, got %s", v.Decision)
	}
}

func TestGovHomonymAllowed(t *testing.T) {
	home := tempHome(t)
	proj := filepath.Join(home, "projetos")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	eng := New(home, nil)
	v := eng.Audit("cd "+proj+" && rm hooks.json", "", "", home)
	if v.Decision != contract.Allow {
		t.Fatalf("homônimo hooks.json: want allow, got %s", v.Decision)
	}
}

func TestUnresolvedVarForceAsk(t *testing.T) {
	home := tempHome(t)
	eng := New(home, nil)
	for _, cmd := range []string{"cp app.tar.gz $DIST_DIR/", "mv $BUILD/out ./", "echo x > $LOG/file"} {
		if v := eng.Audit(cmd, "", "", home); v.Decision != contract.ForceAsk {
			t.Fatalf("%q: want force_ask, got %s", cmd, v.Decision)
		}
	}
}

func TestParseFailureIsForceAsk(t *testing.T) {
	home := tempHome(t)
	eng := New(home, nil)
	if v := eng.Audit("echo 'unclosed", "", "", home); v.Decision != contract.ForceAsk {
		t.Fatalf("parse incompleto: want force_ask, got %s", v.Decision)
	}
}

func TestRedirectionWithFDDenied(t *testing.T) {
	home := tempHome(t)
	eng := New(home, nil)
	if v := eng.Audit("echo x 1>/etc/fstab", "", "", home); v.Decision != contract.Deny {
		t.Fatalf("1>/etc/fstab: want deny, got %s", v.Decision)
	}
}

func TestSuDotCDenied(t *testing.T) {
	home := tempHome(t)
	eng := New(home, nil)
	if v := eng.Audit(`su -c "rm -rf /" root`, "", "", home); v.Decision != contract.Deny {
		t.Fatalf("su -c: want deny, got %s", v.Decision)
	}
}

func TestDiskAndPowerForceAsk(t *testing.T) {
	home := tempHome(t)
	eng := New(home, nil)
	for _, cmd := range []string{"mkfs.ext4 /dev/sdb1", "mount /dev/sdb1 /mnt", "systemctl reboot", "loginctl lock-session"} {
		if v := eng.Audit(cmd, "", "", home); v.Decision != contract.ForceAsk {
			t.Fatalf("%q: want force_ask, got %s", cmd, v.Decision)
		}
	}
}

func TestPrivilegeAsk(t *testing.T) {
	home := tempHome(t)
	eng := New(home, nil)
	for _, cmd := range []string{"sudo apt update", "run0 systemctl restart nginx", "yay -Syu", "sudoedit /etc/fstab"} {
		if v := eng.Audit(cmd, "", "", home); v.Decision != contract.Ask {
			t.Fatalf("%q: want ask, got %s", cmd, v.Decision)
		}
	}
}

func quote(s string) string {
	return "\"" + s + "\""
}
