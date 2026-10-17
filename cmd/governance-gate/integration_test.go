package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Harness de integração (executa o binário real via reexec de TestMain)
// ---------------------------------------------------------------------------

func cleanEnv(overrides map[string]string) []string {
	drop := map[string]bool{"HOME": true, "ANTIGRAVITY_GATE_CACHE_DIR": true, "GOVERNANCE_GATE_EXEC": true}
	var env []string
	for _, kv := range os.Environ() {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		if drop[k] {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "GOVERNANCE_GATE_EXEC=1")
	for k, v := range overrides {
		env = append(env, k+"="+v)
	}
	return env
}

func runBinary(t *testing.T, home, cacheDir string, stdin []byte) (map[string]any, string) {
	t.Helper()
	exe, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = cleanEnv(map[string]string{"HOME": home, "ANTIGRAVITY_GATE_CACHE_DIR": cacheDir})
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("exec do gate falhou: %v (stderr=%s)", err, errb.String())
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("stdout não é JSON: %q (%v)", out.String(), err)
	}
	return m, out.String()
}

type corpusCase struct {
	Name       string         `json:"name"`
	Cmd        string         `json:"cmd"`
	Cwd        string         `json:"cwd"`
	Target     string         `json:"target"`
	Want       string         `json:"want"`
	OW         string         `json:"ow"`
	Stdin      string         `json:"stdin"`
	Payload    map[string]any `json:"payload"`
	Workspaces []string       `json:"workspaces"`
}

func TestGoldenCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/cases.jsonl")
	if err != nil {
		t.Fatalf("corpus ausente: %v", err)
	}
	home := mustMkdir(t, "home")
	ws := mustMkdir(t, "ws")
	gov := filepath.Join(home, ".gemini", "config", "plugins", "bash-sudo-agents")
	if err := os.MkdirAll(gov, 0o755); err != nil {
		t.Fatal(err)
	}
	replace := func(s string) string {
		s = strings.ReplaceAll(s, "HOME", home)
		s = strings.ReplaceAll(s, "WS", ws)
		s = strings.ReplaceAll(s, "GOV", gov)
		return s
	}

	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var tc corpusCase
		if err := json.Unmarshal([]byte(line), &tc); err != nil {
			t.Fatalf("caso inválido: %v", err)
		}
		t.Run(tc.Name, func(t *testing.T) {
			cacheDir := mustMkdir(t, "cache-"+sanitize(tc.Name))
			var stdin []byte
			switch {
			case tc.Stdin != "" || (tc.Stdin == "" && tc.Cmd == "" && tc.Payload == nil):
				stdin = []byte(tc.Stdin)
			case tc.Payload != nil:
				b, _ := json.Marshal(tc.Payload)
				b = []byte(replace(string(b)))
				if len(tc.Workspaces) > 0 {
					var m map[string]any
					_ = json.Unmarshal(b, &m)
					var wss []any
					for _, w := range tc.Workspaces {
						wss = append(wss, replace(w))
					}
					m["workspacePaths"] = wss
					b, _ = json.Marshal(m)
				}
				stdin = b
			default:
				cwd := home
				if tc.Cwd == "WS" {
					cwd = ws
				}
				payload := map[string]any{
					"toolCall": map[string]any{
						"name": "run_command",
						"args": map[string]any{
							"CommandLine": tc.Cmd,
							"TargetFile":  replace(tc.Target),
							"Cwd":         cwd,
						},
					},
				}
				if len(tc.Workspaces) > 0 {
					var wss []any
					for _, w := range tc.Workspaces {
						wss = append(wss, replace(w))
					}
					payload["workspacePaths"] = wss
				}
				b, _ := json.Marshal(payload)
				stdin = b
			}
			got, raw := runBinary(t, home, cacheDir, stdin)
			decision, _ := got["decision"].(string)
			if decision != tc.Want {
				t.Fatalf("want=%s got=%s raw=%s", tc.Want, decision, raw)
			}
			checkOverwrite(t, tc.OW, got["overwrite"])
		})
	}
}

func checkOverwrite(t *testing.T, spec string, ow any) {
	if spec == "" {
		return
	}
	cmdStr := ""
	if m, ok := ow.(map[string]any); ok {
		cmdStr, _ = m["CommandLine"].(string)
	}
	switch {
	case spec == "absent":
		if cmdStr != "" {
			t.Fatalf("overwrite deveria estar ausente, veio %q", cmdStr)
		}
	case strings.HasPrefix(spec, "contains:"):
		want := strings.TrimPrefix(spec, "contains:")
		if !strings.Contains(cmdStr, want) {
			t.Fatalf("overwrite %q deveria conter %q", cmdStr, want)
		}
	case strings.HasPrefix(spec, "not_contains:"):
		bad := strings.TrimPrefix(spec, "not_contains:")
		if strings.Contains(cmdStr, bad) {
			t.Fatalf("overwrite %q não deveria conter %q", cmdStr, bad)
		}
	}
}

func TestConcurrentRejectionCount(t *testing.T) {
	home := mustMkdir(t, "home-conc")
	cacheDir := mustMkdir(t, "cache-conc")
	payload, _ := json.Marshal(map[string]any{
		"toolCall": map[string]any{
			"name": "run_command",
			"args": map[string]any{"CommandLine": "rm -rf /", "Cwd": home},
		},
	})
	const n = 24
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			runBinary(t, home, cacheDir, payload)
		}()
	}
	wg.Wait()
	data, err := os.ReadFile(filepath.Join(cacheDir, "rejection.json"))
	if err != nil {
		t.Fatalf("estado ausente: %v", err)
	}
	var st struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("estado corrompido: %v (%s)", err, data)
	}
	if st.Count != n {
		t.Fatalf("contador concorrente: want %d got %d", n, st.Count)
	}
}

func TestEscalationOnThirdConsecutiveDeny(t *testing.T) {
	home := mustMkdir(t, "home-esc")
	cacheDir := mustMkdir(t, "cache-esc")
	var last map[string]any
	for i := 0; i < 3; i++ {
		payload, _ := json.Marshal(map[string]any{
			"toolCall": map[string]any{
				"name": "run_command",
				"args": map[string]any{"CommandLine": "rm -rf /", "Cwd": home},
			},
		})
		last, _ = runBinary(t, home, cacheDir, payload)
	}
	reason, _ := last["reason"].(string)
	if !strings.Contains(reason, "ALERTA") {
		t.Fatalf("3ª recusa deveria escalar: %q", reason)
	}
}

func TestCacheHitAfterWrite(t *testing.T) {
	home := mustMkdir(t, "home-cache")
	cacheDir := mustMkdir(t, "cache-hit")
	payload, _ := json.Marshal(map[string]any{
		"toolCall": map[string]any{
			"name": "run_command",
			"args": map[string]any{"CommandLine": "lscpu", "Cwd": home},
		},
	})
	first, _ := runBinary(t, home, cacheDir, payload)
	ow, _ := first["overwrite"].(map[string]any)
	wrapped, _ := ow["CommandLine"].(string)
	if !strings.Contains(wrapped, "cache-write") {
		t.Fatalf("primeira execução deveria injetar cache-write: %q", wrapped)
	}
	// Executa o wrapper para popular o cache.
	execWrapped(t, home, cacheDir, wrapped)
	second, _ := runBinary(t, home, cacheDir, payload)
	ow2, _ := second["overwrite"].(map[string]any)
	got, _ := ow2["CommandLine"].(string)
	if !strings.HasPrefix(got, "cat ") {
		t.Fatalf("segunda execução deveria ser cache hit (cat), veio %q", got)
	}
}

func execWrapped(t *testing.T, home, cacheDir, wrapped string) {
	t.Helper()
	cmd := exec.Command("/bin/bash", "-c", wrapped)
	cmd.Env = cleanEnv(map[string]string{"HOME": home, "ANTIGRAVITY_GATE_CACHE_DIR": cacheDir})
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("wrapper falhou: %v (%s)", err, out)
	}
}

func TestReadOnlyVsWriteTools(t *testing.T) {
	home := mustMkdir(t, "home-tools")
	cacheDir := mustMkdir(t, "cache-tools")
	cases := []struct {
		name    string
		payload map[string]any
		want    string
	}{
		{"read-only", map[string]any{"toolCall": map[string]any{"name": "view_file", "args": map[string]any{"AbsolutePath": "/x"}}}, "auto_approve"},
		{"write", map[string]any{"toolCall": map[string]any{"name": "write_to_file", "args": map[string]any{"TargetFile": filepath.Join(home, "x")}}}, "allow"},
		{"unknown", map[string]any{"toolCall": map[string]any{"name": "zzz", "args": map[string]any{}}}, "force_ask"},
	}
	for _, c := range cases {
		b, _ := json.Marshal(c.payload)
		got, raw := runBinary(t, home, cacheDir, b)
		if got["decision"] != c.want {
			t.Fatalf("%s: want %s got %v (%s)", c.name, c.want, got["decision"], raw)
		}
	}
}

func TestRenderHooksSubcommand(t *testing.T) {
	dir := mustMkdir(t, "render")
	tmpl := filepath.Join(dir, "hooks.json")
	out := filepath.Join(dir, "out.json")
	if err := os.WriteFile(tmpl, []byte(`{"governance-gate":{"PreToolUse":[{"hooks":[{"type":"command","command":"__GATE_PATH__"}]}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	exe, _ := filepath.Abs(os.Args[0])
	cmd := exec.Command(exe, "render-hooks", "--template", tmpl, "--out", out, "--gate", "/opt/gate")
	cmd.Env = cleanEnv(nil)
	if err := cmd.Run(); err != nil {
		t.Fatalf("render-hooks: %v", err)
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), "/opt/gate") || strings.Contains(string(data), "__GATE_PATH__") {
		t.Fatalf("render-hooks inesperado: %s", data)
	}
}

func mustMkdir(t *testing.T, prefix string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", prefix+"-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func sanitize(s string) string {
	r := strings.NewReplacer("/", "_", " ", "_", "~", "_", "(", "", ")", "")
	return r.Replace(s)
}
