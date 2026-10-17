package cache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCacheable(t *testing.T) {
	yes := []string{"lscpu", "uname -a", "cat /etc/os-release", "cat /proc/cpuinfo", "lspci", "lsusb"}
	no := []string{
		"rm -rf /*", "rm -rf /home/user/..", "find / -type f -delete",
		"shred -u /dev/sda", "dd if=/dev/zero of=/dev/sda",
		"lscpu ; rm -rf /", "uname -a | cat", "cat /etc/passwd",
		"cat /etc/shadow", "cat /etc/os-release /proc/cpuinfo",
	}
	for _, c := range yes {
		if !Cacheable(c) {
			t.Errorf("Cacheable(%q)=false, want true", c)
		}
	}
	for _, c := range no {
		if Cacheable(c) {
			t.Errorf("Cacheable(%q)=true, want false", c)
		}
	}
}

func TestWrapUsesCacheWrite(t *testing.T) {
	w := Wrap("lscpu", "/tmp/x.out", "/usr/bin/governance-gate", "abc", 3600, "")
	if !strings.Contains(w, "cache-write") || !strings.Contains(w, "lscpu") {
		t.Fatalf("wrap inesperado: %q", w)
	}
	if strings.Contains(w, "tee") {
		t.Fatalf("wrap não deve usar tee: %q", w)
	}
	w2 := Wrap("pacman -Ss firefox", "/tmp/x.out", "gate", "abc", 600, "head -n 25")
	if !strings.Contains(w2, "head -n 25") || !strings.Contains(w2, "cache-write") {
		t.Fatalf("wrap de busca inesperado: %q", w2)
	}
}

func TestKeyDependsOnLocaleAndCwd(t *testing.T) {
	a := Key("lscpu", "/home/u", "pt_BR.UTF-8", "")
	b := Key("lscpu", "/home/u", "en_US.UTF-8", "")
	c := Key("lscpu", "/other", "pt_BR.UTF-8", "")
	if a == b || a == c {
		t.Fatal("chave deveria variar com locale e cwd")
	}
	if Key("lscpu", "/home/u", "pt", "") != Key(" lscpu  ", "/home/u", "pt", "") {
		t.Fatal("normalização da AST deveria colapsar espaços")
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	dir, err := os.MkdirTemp("", "cache-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if !EnsureDir(dir, os.Getuid()) {
		t.Fatal("EnsureDir")
	}
	key := Key("lscpu", "/x", "", "")
	body := []byte("conteudo\n")
	if err := Write(dir, key, time.Now(), 3600, body); err != nil {
		t.Fatal(err)
	}
	got, ok := Read(dir, key, time.Now())
	if !ok || string(got) != string(body) {
		t.Fatalf("roundtrip: ok=%v body=%q", ok, got)
	}
	// TTL expirado.
	if _, ok := Read(dir, key, time.Now().Add(2*time.Hour)); ok {
		t.Fatal("TTL deveria expirar")
	}
	// Conteúdo adulterado -> inválido.
	path := OutPath(dir, key)
	data, _ := os.ReadFile(path)
	data[len(data)-1] = 'X'
	_ = os.WriteFile(path, data, 0o600)
	if _, ok := Read(dir, key, time.Now()); ok {
		t.Fatal("conteúdo adulterado deveria invalidar")
	}
}

func TestEnsureDirRejectsWrongPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// EnsureDir tenta forçar 0700; se conseguir, aceita.
	if !EnsureDir(dir, os.Getuid()) {
		t.Fatal("EnsureDir deveria ajustar 0700")
	}
	fi, _ := os.Lstat(dir)
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("permissão final: %v", fi.Mode().Perm())
	}
}

func TestQuote(t *testing.T) {
	if Quote("lscpu") != "lscpu" {
		t.Fatal("sem aspas desnecessárias")
	}
	if Quote("/tmp/a b") != "'/tmp/a b'" {
		t.Fatalf("quote: %q", Quote("/tmp/a b"))
	}
	if Quote("a'b") != `'a'\''b'` {
		t.Fatalf("quote com aspa: %q", Quote("a'b"))
	}
}

func TestTTLValues(t *testing.T) {
	if TTL("lscpu") != 3600 || TTL("cat /etc/os-release") != 3600 {
		t.Fatal("TTL diagnóstico")
	}
	if TTL("pacman -Ss x") != 600 || !IsSearch("yay -Ss y") {
		t.Fatal("TTL busca")
	}
	if TTL("ls") != 0 {
		t.Fatal("ls não é cacheável")
	}
}
