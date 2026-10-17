package pathx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnderSegmentAware(t *testing.T) {
	if Under("/etcfoo", "/etc") {
		t.Fatal("/etcfoo não está sob /etc")
	}
	if !Under("/etc", "/etc") {
		t.Fatal("/etc está sob /etc")
	}
	if !Under("/etc/passwd", "/etc") {
		t.Fatal("/etc/passwd está sob /etc")
	}
	if !Under("/anything", "/") {
		t.Fatal("tudo está sob /")
	}
}

func TestIsVitalNorm(t *testing.T) {
	cases := map[string]bool{
		"/":              true,
		"/etc":           true,
		"/etcfoo":        false,
		"/etc/passwd":    true,
		"/home":          true,
		"/home/user":     true,
		"/home/user/doc": false,
		"/tmp/build":     false,
		"/e?c":           true,
		"/{etc,usr}":     true,
		"/h?me":          true,
	}
	for in, want := range cases {
		if got := IsVitalNorm(in); got != want {
			t.Errorf("IsVitalNorm(%q)=%v want %v", in, got, want)
		}
	}
}

func TestNormalizeAndHome(t *testing.T) {
	r := New("/home/user")
	if got := r.Normalize("~/x", "/tmp"); got != "/home/user/x" {
		t.Fatalf("Normalize ~/x = %q", got)
	}
	if got := r.Normalize("rel", "/base"); got != "/base/rel" {
		t.Fatalf("Normalize rel = %q", got)
	}
	if got := r.Normalize("$HOME/y", "/base"); got != "/home/user/y" {
		t.Fatalf("Normalize $HOME/y = %q", got)
	}
}

func TestIsVitalArgUnresolved(t *testing.T) {
	r := New("/home/user")
	if r.IsVitalArg("$VAR/etc", "/tmp") {
		t.Fatal("variável não resolvida não deve ser vital")
	}
	if !r.IsVitalArg("/etc/fstab", "/tmp") {
		t.Fatal("/etc/fstab deve ser vital")
	}
	if r.IsVitalArg("/dev/null", "/tmp") {
		t.Fatal("/dev/null não deve ser vital")
	}
}

func TestResolveSymlink(t *testing.T) {
	dir, err := os.MkdirTemp("", "pathx-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/etc", link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	r := New(dir)
	resolved, kind := r.Resolve("link", dir)
	if kind != Resolved || resolved != "/etc" {
		t.Fatalf("Resolve link = %q kind=%v", resolved, kind)
	}
}

func TestResolveLoopAmbiguous(t *testing.T) {
	dir, err := os.MkdirTemp("", "pathx-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.Symlink(a, b); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := os.Symlink(b, a); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if _, kind := New(dir).Resolve("a", dir); kind != SymlinkAmbiguous {
		t.Fatalf("loop: want SymlinkAmbiguous, got %v", kind)
	}
}

func TestResolveTargetSafely(t *testing.T) {
	home, err := os.MkdirTemp("", "pathx-home-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	proj := filepath.Join(home, "projects")
	_ = os.MkdirAll(proj, 0o755)
	r := New(home)
	if _, ok := r.ResolveTargetSafely("src/main.py", proj, nil); !ok {
		t.Fatal("relativo dentro do cwd deveria ser aceito")
	}
	if _, ok := r.ResolveTargetSafely("../../../etc/passwd", proj, nil); ok {
		t.Fatal("traversal deveria ser rejeitado")
	}
	if _, ok := r.ResolveTargetSafely("/etc/shadow", proj, nil); ok {
		t.Fatal("absoluto fora do escopo deveria ser rejeitado")
	}
	if _, ok := r.ResolveTargetSafely("", home, nil); ok {
		t.Fatal("vazio deveria ser rejeitado")
	}
}

func TestSafeDevAndVarLog(t *testing.T) {
	if !IsVarLog("/var/log/syslog") || IsVarLog("/var/logs") {
		t.Fatal("IsVarLog incorreto")
	}
	if New("/home/u").IsVitalArg("/dev/null", "/tmp") {
		t.Fatal("/dev/null não deve ser vital")
	}
}
