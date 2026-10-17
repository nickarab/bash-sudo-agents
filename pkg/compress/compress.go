// Package compress implementa o auto-compressor sintático (injeção de wrappers
// conservadores). Só dispara quando o binário do CallExpr É o comando alvo —
// nunca por prefixo de string.
package compress

import (
	"regexp"

	"governance-gate/pkg/shparse"
)

var (
	journalGuards = regexp.MustCompile(`(-n\s*\d+|--lines(=|\s*)\d+|-[a-zA-Z]*f\b|--follow)`)
	dmesgGuards   = regexp.MustCompile(`\b(tail|head)\b|-w\b|--follow`)
	gitLogGuards  = regexp.MustCompile(`(-\d+|-n\s*\d+)`)
	pacmanSearch  = regexp.MustCompile(`^(pacman|yay|paru)\s+-Ss\s+`)
	gitLog        = regexp.MustCompile(`^git\s+log(\s|$)`)
)

// Compress devolve o comando com o wrapper injetado e ok=true.
func Compress(cmd string, hasPipe, hasRedirect, background bool) (string, bool) {
	if hasPipe || hasRedirect || background {
		return cmd, false
	}
	p := shparse.Parse(cmd, "")
	if len(p.Simples) != 1 {
		return cmd, false
	}
	args := p.Simples[0].ArgsString()
	if len(args) == 0 {
		return cmd, false
	}
	switch args[0] {
	case "journalctl":
		if journalGuards.MatchString(cmd) {
			return cmd, false
		}
		return cmd + " --no-pager -n 35", true
	case "dmesg":
		if dmesgGuards.MatchString(cmd) {
			return cmd, false
		}
		return cmd + " --color=never | tail -n 35", true
	case "pacman", "yay", "paru":
		if pacmanSearch.MatchString(cmd) {
			return cmd + " | head -n 25", true
		}
		return cmd, false
	}
	if gitLog.MatchString(cmd) {
		if gitLogGuards.MatchString(cmd) {
			return cmd, false
		}
		return cmd + " -n 15", true
	}
	return cmd, false
}

// PacmanSuffix é o limitador embutido no wrap de cache de buscas de pacote.
func PacmanSuffix(cmd string) string {
	if pacmanSearch.MatchString(cmd) {
		return "head -n 25"
	}
	return ""
}
