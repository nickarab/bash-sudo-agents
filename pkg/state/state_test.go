package state

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "state-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return New(dir), dir
}

func TestConsecutiveDenials(t *testing.T) {
	s, _ := newTestStore(t)
	for i := 1; i <= 3; i++ {
		n, err := s.Record("deny", "rm -rf /")
		if err != nil {
			t.Fatal(err)
		}
		if n != i {
			t.Fatalf("deny %d: got %d", i, n)
		}
	}
}

func TestApprovalResets(t *testing.T) {
	s, _ := newTestStore(t)
	_, _ = s.Record("deny", "a")
	_, _ = s.Record("deny", "b")
	if n, _ := s.Record("allow", "lscpu"); n != 0 {
		t.Fatalf("allow deveria zerar, got %d", n)
	}
	if s.Count() != 0 {
		t.Fatalf("count após reset: %d", s.Count())
	}
	if n, _ := s.Record("deny", "c"); n != 1 {
		t.Fatalf("recomeço: got %d", n)
	}
}

func TestCorruptStateIsConservative(t *testing.T) {
	s, dir := newTestStore(t)
	if err := os.WriteFile(filepath.Join(dir, "rejection.json"), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := s.Record("deny", "rm -rf /")
	if err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Fatalf("estado corrompido deveria ser conservador (>=2), got %d", n)
	}
}

func TestTTLExpiry(t *testing.T) {
	s, _ := newTestStore(t)
	_, _ = s.Record("deny", "a")
	_, _ = s.Record("deny", "b")
	// Avança o relógio além do TTL: o contador expira.
	future := time.Now().Add(time.Duration(TTLSeconds+10) * time.Second)
	s.now = func() time.Time { return future }
	if s.Count() != 0 {
		t.Fatalf("TTL: esperado 0, got %d", s.Count())
	}
}

func TestConcurrentExactCount(t *testing.T) {
	s, _ := newTestStore(t)
	const n = 64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, _ = s.Record("deny", "rm -rf /")
		}()
	}
	wg.Wait()
	if got := s.Count(); got != n {
		t.Fatalf("contador concorrente: want %d got %d (lost update)", n, got)
	}
}
