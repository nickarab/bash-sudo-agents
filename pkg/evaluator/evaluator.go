// Package evaluator implementa a auditoria constitucional (RULE-02..15) sobre
// a AST do shell. Cada detector opera sobre comandos simples normalizados
// (argv + redirecionamentos) e sobre a resolução de caminhos de pkg/pathx.
package evaluator

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nickarab/bash-sudo-agents/pkg/contract"
	"github.com/nickarab/bash-sudo-agents/pkg/pathx"
	"github.com/nickarab/bash-sudo-agents/pkg/policy"
	"github.com/nickarab/bash-sudo-agents/pkg/shparse"
)

const maxRecursion = 8

// Engine executa a auditoria com um HOME e um conjunto de workspaces fixos.
type Engine struct {
	Resolver *pathx.Resolver
	Roots    []string
}

// New cria um Engine.
func New(home string, workspaces []string) *Engine {
	r := pathx.New(home)
	return &Engine{Resolver: r, Roots: r.GovRoots(workspaces)}
}

// Verdict é o resultado da auditoria.
type Verdict struct {
	Decision contract.Decision
	Reason   string
	Rule     string
}

// Audit executa a cadeia de regras para um comando.
// targetRaw é o alvo cru informado pela ferramenta; targetPath é o alvo
// resolvido (vazio se fora de escopo); cwd é o diretório de trabalho relatado.
func (e *Engine) Audit(cmd, targetRaw, targetPath, cwd string) Verdict {
	if cwd == "" {
		cwd = e.Resolver.Home
	}
	// O cwd relatado é resolvido para servir de base confiável.
	if resolved, kind := pathx.CanonKind(cwd); kind == pathx.Resolved {
		cwd = resolved
	}

	p := shparse.Parse(cmd, e.Resolver.Home)

	// RULE-06: veto irreversível ao sudo_runner legado.
	if hasSudoRunner(p) {
		return Verdict{contract.Deny, "[governance-gate / RULE-06] sudo_runner.sh foi descontinuado.", "RULE-06"}
	}

	// RULE-02: anti-destruição (semântico).
	if bin, uncertain := e.detectDestructive(cmd, cwd); bin != "" {
		return Verdict{contract.Deny, "[governance-gate / RULE-02] Veto sumário: comando destrutivo detectado.", "RULE-02"}
	} else if uncertain {
		return Verdict{contract.ForceAsk, "[governance-gate / RULE-02] Estrutura de comando não analisável com segurança — confirmação humana exigida (fail-closed).", "RULE-02"}
	}

	// RULE-02 estendida: mutação direta de caminho vital.
	if bin := e.detectMutation(cmd, cwd); bin != "" {
		if e.varlogCleanupAllowed(cmd, cwd) {
			return Verdict{contract.Ask, "[governance-gate / RULE-02] Truncamento/redirecionamento em /var/log (limpeza de log) exige confirmação.", "RULE-02"}
		}
		return Verdict{contract.Deny, "[governance-gate / RULE-02] Veto: mutação direta de caminho vital detectada (" + bin + ").", "RULE-02"}
	}

	// RULE-07: estabilidade de serviços essenciais (anti-crash).
	if e.detectServiceKill(cmd, cwd) {
		return Verdict{contract.Deny, "[governance-gate / RULE-07] Tentativa de interromper serviço crítico da sessão.", "RULE-07"}
	}

	// RULE-05: preservação da árvore de permissões.
	if bin := e.detectPermAbuse(cmd, cwd); bin != "" {
		return Verdict{contract.Deny, "[governance-gate / RULE-05] Alteração recursiva de permissões em diretório protegido.", "RULE-05"}
	}

	// RULE-03: operações de disco/formatação.
	if e.detectDisk(cmd, cwd) {
		return Verdict{contract.ForceAsk, "[governance-gate / RULE-03] Operação de disco/formatação exige confirmação explícita.", "RULE-03"}
	}

	// RULE-07 (energia/sessão).
	if e.detectPower(cmd, cwd) {
		return Verdict{contract.ForceAsk, "[governance-gate / RULE-07] Desligamento/reinício/suspensão da máquina ou da sessão exige confirmação explícita.", "RULE-07"}
	}

	// RULE-11/12: proteção da infraestrutura de governança.
	if e.detectGovTarget(targetRaw, targetPath, cwd) {
		return Verdict{contract.Deny, "[governance-gate / RULE-12] Escrita em arquivo de governança detectada.", "RULE-12"}
	}
	if e.detectGovMutation(cmd, cwd) {
		return Verdict{contract.Deny, "[governance-gate / RULE-12] Comando tenta modificar a infraestrutura de governança.", "RULE-12"}
	}
	if govPattern.MatchString(cmd) && writeOpsPattern.MatchString(cmd) {
		return Verdict{contract.Deny, "[governance-gate / RULE-12] Comando tenta modificar arquivo de governança.", "RULE-12"}
	}

	// Interpretadores inline sobre caminhos protegidos.
	switch e.detectInlineInterpreter(cmd, cwd) {
	case "deny":
		return Verdict{contract.Deny, "[governance-gate / RULE-12/RULE-02] Interpretador inline com destruição de raiz/vital ou manipulação da governança.", "RULE-12"}
	case "force_ask":
		return Verdict{contract.ForceAsk, "[governance-gate / RULE-02] Interpretador inline referenciando caminho vital exige confirmação explícita.", "RULE-02"}
	}

	// Anti-fadiga: alvo com variável não resolvida em operação de mutação.
	if e.hasUnresolvedTarget(cmd, cwd) {
		return Verdict{contract.ForceAsk, "[governance-gate / RULE-02] Alvo com variável de shell não resolvida em operação de mutação — confirmação explícita exigida.", "RULE-02"}
	}

	// Symlink cuja resolução é incerta (ELOOP) — conservadorismo explícito.
	if e.hasAmbiguousSymlink(cmd, cwd) {
		return Verdict{contract.ForceAsk, "[governance-gate / RULE-02] Alvo com symlink não resolvível com segurança — confirmação explícita exigida.", "RULE-02"}
	}

	// Fail-closed de análise: parse incompleto sem veto explícito.
	if p.Incomplete {
		return Verdict{contract.ForceAsk, "[governance-gate] Comando não analisável com segurança (parse incompleto) — confirmação humana exigida (fail-closed).", "FAILSAFE_PARSE"}
	}

	// RULE-15: elevação de privilégio rotineira -> ask (Always Allow).
	if privileged, ptype := e.cmdIsPrivileged(p); privileged || e.subshellPrivileged(p) {
		label := ptype
		if label == "" {
			label = "privileged"
		}
		return Verdict{contract.Ask, "[governance-gate / RULE-15] Elevação de privilégio (" + label + "). Aprove e marque 'Always Allow' para não ser perguntado novamente.", "RULE-15"}
	}

	return Verdict{contract.Allow, "", ""}
}

// ---------------------------------------------------------------------------
// Helpers de argv / privilégio
// ---------------------------------------------------------------------------

func baseName(p string) string {
	return filepath.Base(p)
}

type privInfo struct {
	ptype      string
	payload    string
	hasPayload bool
}

// skipWithValue são flags de elevação que consomem o próximo token.
var skipWithValue = map[string]bool{
	"-u": true, "--user": true, "-g": true, "--group": true,
	"-h": true, "--host": true, "-p": true, "--prompt": true,
	"-C": true, "--close-from": true, "-D": true, "--chdir": true,
	"-T": true, "--command-timeout": true, "-R": true, "--chroot": true,
}

func isAssignment(tok string) bool {
	eq := strings.IndexByte(tok, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := tok[i]
		if c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

// unwrapPrivilege remove prefixos de elevação (sudo/doas/pkexec/run0/su/env/…)
// usando um único parser de flags (fim da divergência do motor legado).
func unwrapPrivilege(args []string) ([]string, privInfo) {
	info := privInfo{}
	i := 0
	n := len(args)
	for i < n {
		tok := args[i]
		if tok == "--" {
			i++
			break
		}
		if isAssignment(tok) {
			i++
			continue
		}
		base := baseName(tok)
		switch base {
		case "sudoedit":
			info.ptype = "sudoedit"
			i++
			continue
		case "sudo", "doas", "pkexec", "run0":
			if info.ptype == "" {
				info.ptype = base
			}
			i++
			continue
		case "command", "busybox", "exec":
			i++
			continue
		case "env":
			i++
			for i < n && (isAssignment(args[i]) || strings.HasPrefix(args[i], "-")) {
				if args[i] == "--" {
					i++
					break
				}
				i++
			}
			continue
		case "su":
			info.ptype = "su"
			i++
			if i < n && args[i] == "-" {
				i++
			}
			if i < n && !strings.HasPrefix(args[i], "-") {
				i++ // nome de usuário
			}
			continue
		}
		if strings.HasPrefix(tok, "-") && tok != "-" {
			if tok == "-c" && info.ptype == "su" {
				if i+1 < n {
					info.payload = args[i+1]
					info.hasPayload = true
				}
				i += 2
				continue
			}
			if skipWithValue[tok] {
				i++
				if i < n && !strings.HasPrefix(args[i], "-") {
					i++
				}
				continue
			}
			i++
			continue
		}
		break
	}
	if i > n {
		i = n
	}
	return args[i:], info
}

// shellPayload devolve o código de um `shell -c CODE`.
func shellPayload(rest []string) (string, bool) {
	if len(rest) < 3 {
		return "", false
	}
	if _, ok := policy.ShellBins[baseName(rest[0])]; !ok {
		return "", false
	}
	for i := 1; i < len(rest)-1; i++ {
		if rest[i] == "-c" {
			return strings.Join(rest[i+1:], " "), true
		}
	}
	return "", false
}

// walk percorre todos os comandos simples, recursando em `shell -c`/`su -c`.
// Retorna found=true se o visitante pediu parada; uncertain=true se houve
// estrutura não analisável (profundidade excessiva) — conservadorismo.
func (e *Engine) walk(cmd, cwd string, depth int, visit func(rest []string, s shparse.Simple, info privInfo) bool) (found bool, uncertain bool) {
	if depth > maxRecursion {
		return false, true
	}
	p := shparse.Parse(cmd, e.Resolver.Home)
	if p.Incomplete {
		uncertain = true
	}
	for _, s := range p.Simples {
		rest, info := unwrapPrivilege(s.ArgsString())
		if code, ok := shellPayload(rest); ok {
			if f, u := e.walk(code, cwd, depth+1, visit); f {
				return true, uncertain
			} else if u {
				uncertain = true
			}
		}
		if info.hasPayload {
			if f, u := e.walk(info.payload, cwd, depth+1, visit); f {
				return true, uncertain
			} else if u {
				uncertain = true
			}
		}
		if visit(rest, s, info) {
			return true, uncertain
		}
	}
	return false, uncertain
}

// cmdIsPrivileged classifica a elevação de privilégio por comando simples.
func (e *Engine) cmdIsPrivileged(p *shparse.Result) (bool, string) {
	for _, s := range p.Simples {
		argv := s.ArgsString()
		if len(argv) == 0 {
			continue
		}
		if ok, ptype := classifyPrivilege(argv); ok {
			return true, ptype
		}
	}
	return false, ""
}

func classifyPrivilege(argv []string) (bool, string) {
	first := baseName(argv[0])
	switch first {
	case "sudoedit":
		return true, "sudoedit"
	case "sudo", "doas", "pkexec", "su", "run0":
		if first == "sudo" {
			for _, a := range argv[1:] {
				if a == "-e" || a == "--edit" {
					return true, "sudoedit"
				}
			}
		}
		return true, first
	}
	if _, ok := policy.PackageBins[first]; ok {
		for _, tok := range argv[1:] {
			if isPackageSync(tok) {
				return true, "package_install"
			}
		}
	}
	if first == "systemctl" {
		hasUser := false
		hasVerb := false
		for _, tok := range argv[1:] {
			if tok == "--user" {
				hasUser = true
			}
			if _, ok := policy.ServiceVerbs[tok]; ok {
				hasVerb = true
			}
		}
		if !hasUser && hasVerb {
			return true, "systemctl"
		}
	}
	return false, ""
}

func isPackageSync(tok string) bool {
	if !strings.HasPrefix(tok, "-S") {
		return false
	}
	if len(tok) == 2 {
		return true
	}
	c := tok[2]
	return c != 's' && c != 'i'
}

// subshellPrivileged detecta elevação escondida em substituições de comando.
func (e *Engine) subshellPrivileged(p *shparse.Result) bool {
	for _, s := range p.Simples {
		if !s.Subst {
			continue
		}
		for _, a := range s.Args {
			switch baseName(a.Text) {
			case "sudo", "doas", "pkexec", "run0", "su":
				return true
			}
			if a.Text == "sudo" || a.Text == "doas" || a.Text == "pkexec" || a.Text == "run0" || a.Text == "su" {
				return true
			}
		}
	}
	return false
}

func hasSudoRunner(p *shparse.Result) bool {
	for _, s := range p.Simples {
		for _, a := range s.Args {
			b := baseName(a.Text)
			if b == "sudo_runner" || b == "sudo_runner.sh" {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Regexes auxiliares (apenas fallback textual; nunca fonte primária de veto)
// ---------------------------------------------------------------------------

// Nota: Go (RE2) não suporta lookahead. O padrão de operações de escrita foi
// reescrito com `>[^&]` para preservar a semântica (excluir `>&`/`<&` de
// duplicação de fd) do motor legado.
var (
	govPattern = regexp.MustCompile(`plugins/bash-sudo-agents/|scratch/security/|\.gemini/config/config\.json|\.gemini/config/hooks\.json|\.agents/hooks\.json`)

	writeOpsPattern = regexp.MustCompile(`(>[^&]|\btee\b|\bsed\s+-i|\bdd\b[^;&|\n]*\bof=|\brsync\b|\btar\s+(?:-[a-zA-Z]*x|--extract)|(^|[;&|\s])(chmod|chown|chattr|rm|mv|cp|install|shred|ln|unlink)(\s|$))`)

	protectedMention = regexp.MustCompile(`/(?:boot|etc|usr|var|sys|proc|dev|bin|sbin|lib|lib64|root|opt|srv|mnt|home)(?:/|\b)|/dev/|\b(?:passwd|shadow|gshadow|sudoers|fstab|crypttab)\b|scratch/security|bash-sudo-agents|hooks\.json`)
)
