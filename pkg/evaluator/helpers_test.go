package evaluator

import (
	"os"
	"testing"
)

// tempHome cria um HOME temporário com profundidade 2 (/tmp/xxxx), necessária
// para reproduzir escapes como `rm -rf ~/../../etc`.
func tempHome(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "gate-home-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
