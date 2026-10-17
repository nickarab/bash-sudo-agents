// Command governance-gate é o motor de governança do Antigravity Linux.
//
// Subcomandos:
//
//	(default)        hook PreToolUse: lê o payload no stdin e emite UMA linha JSON.
//	cache-write      segunda fase do cache (lê stdin, grava atômico, ecoa stdout).
//	render-hooks     gera o hooks.json final a partir do template (sem sed/jq).
//	version          imprime a versão.
package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nickarab/bash-sudo-agents/pkg/audit"
	"github.com/nickarab/bash-sudo-agents/pkg/cache"
	"github.com/nickarab/bash-sudo-agents/pkg/compress"
	"github.com/nickarab/bash-sudo-agents/pkg/contract"
	"github.com/nickarab/bash-sudo-agents/pkg/evaluator"
	"github.com/nickarab/bash-sudo-agents/pkg/policy"
	"github.com/nickarab/bash-sudo-agents/pkg/shparse"
	"github.com/nickarab/bash-sudo-agents/pkg/state"
)

// Version é a versão do motor (runtime Go nativo).
const Version = "5.0.0"

const rejectionLimit = 3

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "cache-write":
			runCacheWrite(os.Args[2:])
			return
		case "render-hooks":
			runRenderHooks(os.Args[2:])
			return
		case "version", "--version", "-v":
			os.Stdout.WriteString("governance-gate " + Version + " (Go)\n")
			return
		}
	}
	runGate()
}

// ---------------------------------------------------------------------------
// Hook PreToolUse
// ---------------------------------------------------------------------------

var (
	emitOnce sync.Once
)

func writeOutput(o contract.Output) {
	emitOnce.Do(func() {
		data, err := json.Marshal(o)
		if err != nil {
			data = []byte(`{"decision":"force_ask","reason":"[gate] erro de serialização"}`)
		}
		_, _ = os.Stdout.Write(append(data, '\n'))
	})
}

func runGate() {
	// Guarda de pânico ANTES de qualquer trabalho: qualquer panic vira force_ask.
	defer func() {
		if r := recover(); r != nil {
			writeOutput(contract.Output{
				Decision: "force_ask",
				Reason:   "[governance-gate] erro interno — confirmação humana exigida (fail-closed).",
			})
		}
	}()

	g := newGate()
	writeOutput(g.decide())
}

type gate struct {
	engine   *evaluator.Engine
	logger   *audit.Logger
	store    *state.Store
	cacheDir string
	cacheOK  bool
	gateBin  string
	home     string
	uid      int
}

func newGate() *gate {
	home := os.Getenv("HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	uid := os.Getuid()
	dir := cache.DirFor(uid)
	ok := cache.EnsureDir(dir, uid)
	g := &gate{
		engine:   evaluator.New(home, nil),
		cacheDir: dir,
		cacheOK:  ok,
		gateBin:  selfPath(),
		home:     home,
		uid:      uid,
	}
	if ok {
		g.logger = audit.New(dir)
		g.store = state.New(dir)
	}
	return g
}

func selfPath() string {
	if p, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			return resolved
		}
		return p
	}
	return "governance-gate"
}

func (g *gate) decide() contract.Output {
	start := time.Now()
	lat := func() int { return int(time.Since(start).Milliseconds()) }

	raw, ok := readStdin(1<<20, 2*time.Second)
	if !ok {
		return forceAsk("[governance-gate] Timeout de leitura do payload — schema inesperado; confirmação humana exigida (fail-closed).")
	}
	if strings.TrimSpace(string(raw)) == "" {
		if g.logger != nil {
			g.logger.Log("force_ask", "stdin vazio", "FAILSAFE_SCHEMA", "", g.home, lat())
		}
		return forceAsk("[governance-gate] Payload vazio no stdin — schema inesperado; confirmação humana exigida (fail-closed).")
	}
	p, err := contract.ParsePayload(raw, g.home)
	if err != nil {
		if g.logger != nil {
			g.logger.Log("force_ask", "payload malformado: "+err.Error(), "FAILSAFE_SCHEMA", "", g.home, lat())
		}
		return forceAsk("Failsafe: payload malformado (" + err.Error() + ") — confirmação humana exigida.")
	}

	// Workspaces informados pelo payload afetam as raízes de governança.
	g.engine = evaluator.New(g.home, p.Workspaces)
	cwd := p.Cwd
	targetPath, _ := g.engine.Resolver.ResolveTargetSafely(p.TargetRaw, cwd, p.Workspaces)

	v := g.engine.Audit(p.Cmd, p.TargetRaw, targetPath, cwd)
	count := 0
	if g.store != nil {
		count, _ = g.store.Record(v.Decision.String(), p.Cmd)
	}

	switch v.Decision {
	case contract.Deny:
		if g.logger != nil {
			g.logger.Log("deny", v.Reason, v.Rule, p.Cmd, cwd, lat())
		}
		if count >= rejectionLimit {
			return contract.Output{Decision: v.Decision.String(), Reason: escalation(v.Reason, cwd)}
		}
		return contract.Output{Decision: v.Decision.String(), Reason: v.Reason}
	case contract.ForceAsk:
		if g.logger != nil {
			g.logger.Log("force_ask", v.Reason, v.Rule, p.Cmd, cwd, lat())
		}
		return contract.Output{Decision: v.Decision.String(), Reason: v.Reason}
	case contract.Ask:
		if g.logger != nil {
			g.logger.Log("ask", v.Reason, v.Rule, p.Cmd, cwd, lat())
		}
		return contract.Output{Decision: v.Decision.String(), Reason: v.Reason}
	}

	// Fail-closed de schema: payload válido, mas sem CommandLine reconhecível.
	if p.Cmd == "" {
		if policy.Has(policy.ReadOnlyTools, p.ToolName) {
			if g.logger != nil {
				g.logger.Log("auto_approve", "Ferramenta de leitura sem CommandLine (TargetFile auditado).", "", "", cwd, lat())
			}
			return contract.Output{Decision: "auto_approve"}
		}
		if policy.Has(policy.WriteTools, p.ToolName) {
			if g.logger != nil {
				g.logger.Log("allow", "Ferramenta de escrita/orquestração sem CommandLine (TargetFile auditado).", "", "", cwd, lat())
			}
			return contract.Output{Decision: "allow"}
		}
		if g.logger != nil {
			g.logger.Log("force_ask", "Payload sem CommandLine reconhecível (fail-closed).", "FAILSAFE_SCHEMA", "", cwd, lat())
		}
		return forceAsk("[governance-gate] Chamada sem `CommandLine` reconhecível — schema inesperado; confirmação humana exigida (fail-closed).")
	}

	// Cache local com TTL.
	if g.cacheOK {
		if ttl := cache.TTL(p.Cmd); ttl > 0 {
			key := cache.Key(p.Cmd, cwd, os.Getenv("LANG"), os.Getenv("LC_ALL"))
			out := cache.OutPath(g.cacheDir, key)
			if _, hit := cache.Read(g.cacheDir, key, time.Now()); hit {
				return g.emitOverwrite(cache.HitCommand(out), "CACHE_HIT", targetPath, cwd, p.Cmd, lat())
			}
			if cache.Cacheable(p.Cmd) {
				wrapped := cache.Wrap(p.Cmd, out, g.gateBin, key, ttl, compress.PacmanSuffix(p.Cmd))
				if wrapped != p.Cmd {
					return g.emitOverwrite(wrapped, "CACHE_WRITE", targetPath, cwd, p.Cmd, lat())
				}
			}
		}
	}

	// Auto-compressor sintático.
	sp := shparse.Parse(p.Cmd, g.home)
	if out, ok := compress.Compress(p.Cmd, sp.HasPipe, sp.HasRedirect, sp.Background); ok {
		return g.emitOverwrite(out, "COMPRESS", targetPath, cwd, p.Cmd, lat())
	}

	if g.logger != nil {
		g.logger.Log("auto_approve", "allow:policy", "", p.Cmd, cwd, lat())
	}
	return contract.Output{Decision: "auto_approve"}
}

// emitOverwrite re-audita o comando sintetizado; se a re-validação não aprovar,
// o overwrite NUNCA é emitido (invariante de arquitetura da Seção 5.5).
func (g *gate) emitOverwrite(newCmd, rule, targetPath, cwd, origCmd string, latency int) contract.Output {
	v := g.engine.Audit(newCmd, "", targetPath, cwd)
	if v.Decision != contract.Allow {
		if g.logger != nil {
			g.logger.Log("deny", "Overwrite rejeitado: "+v.Reason, "OVERWRITE_REVALIDATION", newCmd, cwd, latency)
		}
		return contract.Output{Decision: "deny", Reason: "Comando otimizado rejeitado na re-validação: " + v.Reason}
	}
	if g.logger != nil {
		g.logger.Log("auto_approve", "overwrite:"+rule, rule, newCmd, cwd, latency)
	}
	return contract.Output{
		Decision:  "auto_approve",
		Overwrite: &contract.OverwriteField{CommandLine: newCmd},
	}
}

func forceAsk(reason string) contract.Output {
	return contract.Output{Decision: "force_ask", Reason: reason}
}

func escalation(reason, cwd string) string {
	return "🛑 [ALERTA DE SEGURANÇA: LIMITE DE RECUSAS ATINGIDO (3/3)] " + reason +
		" — Contexto: " + cwd + ". EXECUÇÃO SUSPENSA. Aguardando intervenção manual do administrador."
}

// readStdin lê até limit bytes com deadline cooperativo.
func readStdin(limit int64, timeout time.Duration) ([]byte, bool) {
	ch := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(io.LimitReader(os.Stdin, limit))
		ch <- b
	}()
	select {
	case b := <-ch:
		return b, true
	case <-time.After(timeout):
		return nil, false
	}
}

// ---------------------------------------------------------------------------
// Subcomandos
// ---------------------------------------------------------------------------

func runCacheWrite(args []string) {
	var file string
	ttl := 0
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--file":
			if i+1 < len(args) {
				file = args[i+1]
				i++
			}
		case "--ttl":
			if i+1 < len(args) {
				ttl = atoiSafe(args[i+1])
				i++
			}
		}
	}
	uid := os.Getuid()
	dir := cache.DirFor(uid)
	if file == "" || filepath.Clean(filepath.Dir(file)) != filepath.Clean(dir) || ttl <= 0 {
		os.Exit(1)
	}
	key := strings.TrimSuffix(filepath.Base(file), ".out")
	body, _ := io.ReadAll(os.Stdin)
	if err := cache.Write(dir, key, time.Now(), ttl, body); err != nil {
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(body)
}

func runRenderHooks(args []string) {
	var template, out, gate string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--template":
			if i+1 < len(args) {
				template = args[i+1]
				i++
			}
		case "--out":
			if i+1 < len(args) {
				out = args[i+1]
				i++
			}
		case "--gate":
			if i+1 < len(args) {
				gate = args[i+1]
				i++
			}
		}
	}
	if template == "" || out == "" || gate == "" {
		os.Exit(2)
	}
	data, err := os.ReadFile(template)
	if err != nil {
		os.Exit(1)
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		os.Exit(1)
	}
	v = replaceGate(v, gate)
	rendered, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		os.Exit(1)
	}
	if err := os.WriteFile(out, append(rendered, '\n'), 0o644); err != nil {
		os.Exit(1)
	}
}

func replaceGate(v any, gate string) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok && strings.Contains(s, "__GATE_PATH__") {
				x[k] = strings.ReplaceAll(s, "__GATE_PATH__", gate)
			} else {
				x[k] = replaceGate(val, gate)
			}
		}
	case []any:
		for i := range x {
			x[i] = replaceGate(x[i], gate)
		}
	}
	return v
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
