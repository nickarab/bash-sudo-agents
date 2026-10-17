// Package pathx centraliza a resolução e a comparação de caminhos.
//
// Regras de ouro (v5.0.0):
//   - toda comparação de pertencimento é segment-aware (filepath.Rel), nunca
//     prefixo de string ("/etc" não casa "/etcfoo");
//   - symlinks são resolvidos sempre que possível; se a resolução for ambígua
//     (ELOOP/ENAMETOOLONG) o chamador trata como incerto -> force_ask;
//   - `$HOME`/`~` são expandidos apenas a partir do HOME do processo.
package pathx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"governance-gate/pkg/policy"
)

// Kind descreve o resultado da resolução de um caminho.
type Kind int

const (
	// Resolved: caminho resolvido com sucesso (symlinks do ancestral existente).
	Resolved Kind = iota
	// SymlinkAmbiguous: EvalSymlinks retornou ELOOP/ENAMETOOLONG.
	SymlinkAmbiguous
	// Unresolved: caminho contém variável de shell não resolvida.
	Unresolved
)

// Resolver resolve caminhos relativos a um HOME e a um cwd.
type Resolver struct {
	Home string
}

// New cria um Resolver. Se home for vazio, usa os.UserHomeDir().
func New(home string) *Resolver {
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = h
		}
	}
	return &Resolver{Home: home}
}

// ExpandHome substitui `~`, `~/`, `$HOME` e `${HOME}` pelo HOME do processo.
// NÃO usa substituição cega: apenas nas posições em que o shell expandiria.
func (r *Resolver) ExpandHome(arg string) string {
	switch {
	case arg == "~":
		return r.Home
	case strings.HasPrefix(arg, "~/"):
		return filepath.Join(r.Home, arg[2:])
	}
	if strings.Contains(arg, "$HOME") || strings.Contains(arg, "${HOME}") {
		arg = strings.ReplaceAll(arg, "${HOME}", r.Home)
		arg = strings.ReplaceAll(arg, "$HOME", r.Home)
	}
	return arg
}

// Normalize expande HOME, torna absoluto (relativo ao cwd) e limpa o caminho,
// SEM resolver symlinks (equivalente leve de os.path.normpath).
func (r *Resolver) Normalize(arg, cwd string) string {
	p := r.ExpandHome(arg)
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	return filepath.Clean(p)
}

// Resolve devolve o caminho canônico, resolvendo symlinks do ancestral existente
// mais profundo (o alvo pode não existir ainda).
func (r *Resolver) Resolve(arg, cwd string) (string, Kind) {
	norm := r.Normalize(arg, cwd)
	// Variável residual (após expandir HOME): não é resolvível.
	if strings.Contains(norm, "$") {
		return norm, Unresolved
	}
	return CanonKind(norm)
}

// Canon resolve symlinks de `norm`, resolvendo o diretório-pai quando o próprio
// caminho não existe. ELOOP/ENAMETOOLONG -> SymlinkAmbiguous.
func Canon(norm string) string {
	if resolved, kind := evalDeepest(norm); kind == Resolved {
		return resolved
	}
	return norm
}

// CanonKind devolve o caminho canônico e o Kind da resolução.
func CanonKind(norm string) (string, Kind) {
	return evalDeepest(norm)
}

func evalDeepest(norm string) (string, Kind) {
	if resolved, err := filepath.EvalSymlinks(norm); err == nil {
		return resolved, Resolved
	} else if ambiguous(err) {
		return norm, SymlinkAmbiguous
	}
	parent := filepath.Dir(norm)
	if parent == norm {
		return norm, Resolved
	}
	if rp, err := filepath.EvalSymlinks(parent); err == nil {
		return filepath.Join(rp, filepath.Base(norm)), Resolved
	} else if ambiguous(err) {
		return norm, SymlinkAmbiguous
	}
	// Sobe recursivamente até um ancestral resolvível.
	resolvedParent, kind := evalDeepest(parent)
	if kind != Resolved {
		return norm, kind
	}
	return filepath.Join(resolvedParent, filepath.Base(norm)), Resolved
}

func ambiguous(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENAMETOOLONG) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "too many levels of symbolic links") ||
		strings.Contains(msg, "too many links") ||
		strings.Contains(msg, "file name too long")
}

// Under informa se child está contido em (ou é igual a) parent, de forma
// segment-aware.
func Under(child, parent string) bool {
	child = strings.TrimRight(child, "/")
	parent = strings.TrimRight(parent, "/")
	if child == "" {
		child = "/"
	}
	if parent == "" {
		parent = "/"
	}
	if parent == "/" {
		return strings.HasPrefix(child, "/")
	}
	if child == parent {
		return true
	}
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, "../")
}

// HasGlob informa se há metacaractere de glob.
func HasGlob(arg string) bool {
	return strings.ContainsAny(arg, "?[]{}*")
}

// IsVitalNorm verifica se um caminho JÁ normalizado é raiz/vital do sistema.
func IsVitalNorm(norm string) bool {
	if norm == "/" || norm == "/*" {
		return true
	}
	if !strings.HasPrefix(norm, "/") {
		return false
	}
	rest := strings.TrimLeft(norm, "/")
	top := rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		top = rest[:i]
	}
	if HasGlob(top) {
		return componentMatchesVital(top)
	}
	if _, ok := policy.TopDirs()[top]; ok {
		return true
	}
	if top == "home" {
		rest2 := strings.TrimLeft(rest[len("home"):], "/")
		if rest2 == "" || !strings.Contains(rest2, "/") {
			return true
		}
	}
	return false
}

// IsVitalArg expande/normaliza e verifica se o argumento é um caminho vital.
// Alvos com variável residual são tratados como NÃO vitais (a retenção é feita
// pela regra de variável não resolvida -> force_ask). Symlinks do ancestral
// existente são resolvidos — fechando o bypass `ln -s /etc x && rm -rf x`.
func (r *Resolver) IsVitalArg(arg, cwd string) bool {
	expanded := r.ExpandHome(arg)
	if strings.Contains(expanded, "$") {
		return false
	}
	norm := r.Normalize(arg, cwd)
	if _, ok := policy.SafeDev()[norm]; ok {
		return false
	}
	if IsVitalNorm(norm) {
		return true
	}
	resolved, _ := r.Resolve(arg, cwd)
	if _, ok := policy.SafeDev()[resolved]; ok {
		return false
	}
	return IsVitalNorm(resolved)
}

// IsSystemPathNorm: raiz ou topo vital do SO (sem a regra de home).
func IsSystemPathNorm(norm string) bool {
	if norm == "/" {
		return true
	}
	if !strings.HasPrefix(norm, "/") {
		return false
	}
	top := strings.TrimLeft(norm, "/")
	if i := strings.IndexByte(top, '/'); i >= 0 {
		top = top[:i]
	}
	_, ok := policy.TopDirs()[top]
	return ok
}

// IsVitalFileNorm verifica arquivos vitais específicos.
func IsVitalFileNorm(norm string) bool {
	_, ok := policy.VitalFiles()[norm]
	return ok
}

// componentMatchesVital cobre ? [] * via match e {} via expansão de chaves.
func componentMatchesVital(comp string) bool {
	alts := braceExpand(comp)
	for _, alt := range alts {
		for vital := range policy.TopDirs() {
			if match(alt, vital) {
				return true
			}
		}
		if match(alt, "home") {
			return true
		}
	}
	return false
}

// braceExpand expande a primeira ocorrência de {a,b,c} (uma única vez).
func braceExpand(comp string) []string {
	open := strings.IndexByte(comp, '{')
	if open < 0 {
		return []string{comp}
	}
	closeIdx := strings.IndexByte(comp[open:], '}')
	if closeIdx < 0 {
		return []string{comp}
	}
	closeIdx += open
	prefix, body, suffix := comp[:open], comp[open+1:closeIdx], comp[closeIdx+1:]
	var out []string
	for _, part := range strings.Split(body, ",") {
		out = append(out, prefix+part+suffix)
	}
	return out
}

// match implementa casamento de glob simples (fnmatch), sem suporte a `**`.
func match(pattern, name string) bool {
	ok, err := filepath.Match(pattern, name)
	return err == nil && ok
}

// IsVarLog informa se o caminho normalizado está sob /var/log.
func IsVarLog(norm string) bool {
	return norm == "/var/log" || strings.HasPrefix(norm, "/var/log/")
}

// GovRoots devolve os caminhos reais (canônicos) da infraestrutura de governança.
func (r *Resolver) GovRoots(workspaces []string) []string {
	home := r.Home
	raw := []string{
		filepath.Join(home, ".gemini", "config", "plugins", "bash-sudo-agents"),
		filepath.Join(home, ".gemini", "antigravity", "scratch", "security"),
		filepath.Join(home, ".gemini", "config", "hooks.json"),
		filepath.Join(home, ".gemini", "config", "agents"),
		filepath.Join(home, ".gemini", "config"),
	}
	for _, ws := range workspaces {
		raw = append(raw,
			filepath.Join(ws, ".agents", "hooks.json"),
			filepath.Join(ws, ".agents"),
		)
	}
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		out = append(out, Canon(p))
	}
	return out
}

// IsGovPath informa se path está sob alguma raiz de governança.
func IsGovPath(path string, roots []string) bool {
	for _, root := range roots {
		if Under(path, root) {
			return true
		}
	}
	return false
}

// IsGovAncestor informa se path CONTÉM (é ancestral de) alguma raiz de governança.
func IsGovAncestor(path string, roots []string) bool {
	if IsGovPath(path, roots) {
		return false
	}
	for _, root := range roots {
		if Under(root, path) {
			return true
		}
	}
	return false
}

// ResolveTargetSafely reproduz a política de raízes permitidas para TargetFile.
// Retorna ("", false) quando o alvo está fora do escopo.
func (r *Resolver) ResolveTargetSafely(target, cwd string, workspaces []string) (string, bool) {
	if strings.TrimSpace(target) == "" {
		return "", false
	}
	expanded := r.ExpandHome(target)
	if !filepath.IsAbs(expanded) {
		expanded = filepath.Join(cwd, expanded)
	}
	resolved := Canon(filepath.Clean(expanded))
	roots := []string{Canon(cwd), Canon(filepath.Join(r.Home, "projects")), Canon("/tmp")}
	for _, ws := range workspaces {
		roots = append(roots, Canon(ws))
	}
	for _, root := range roots {
		if Under(resolved, root) {
			return resolved, true
		}
	}
	return "", false
}
