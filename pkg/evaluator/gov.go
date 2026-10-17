package evaluator

import (
	"regexp"
	"strings"

	"github.com/nickarab/bash-sudo-agents/pkg/pathx"
	"github.com/nickarab/bash-sudo-agents/pkg/policy"
	"github.com/nickarab/bash-sudo-agents/pkg/shparse"
)

// ---------------------------------------------------------------------------
// RULE-11/12: proteção da infraestrutura de governança por caminho resolvido
// ---------------------------------------------------------------------------

func (e *Engine) detectGovTarget(targetRaw, targetPath, cwd string) bool {
	if strings.TrimSpace(targetRaw) == "" && targetPath == "" {
		return false
	}
	if targetRaw != "" {
		resolved := e.Resolver.Normalize(targetRaw, cwd)
		if govPattern.MatchString(targetRaw) || govPattern.MatchString(resolved) {
			return true
		}
		c := pathx.Canon(resolved)
		if pathx.IsGovPath(c, e.Roots) {
			return true
		}
	}
	if targetPath != "" {
		if govPattern.MatchString(targetPath) || pathx.IsGovPath(pathx.Canon(targetPath), e.Roots) {
			return true
		}
	}
	return false
}

func (e *Engine) detectGovMutation(cmd, cwd string) bool {
	p := shparse.Parse(cmd, e.Resolver.Home)
	cur := cwd
	for _, s := range p.Simples {
		rest, _ := unwrapPrivilege(s.ArgsString())
		if len(rest) > 0 {
			b := baseName(rest[0])
			if b == "cd" || b == "pushd" {
				if len(rest) > 1 {
					cur = e.Resolver.Normalize(rest[1], cur)
				}
			} else if _, ok := policy.GovMutationBins[b]; ok {
				targets, recursive := e.govMutationTargets(b, rest[1:], cur)
				for _, t := range targets {
					c := pathx.Canon(e.Resolver.Normalize(t, cur))
					if pathx.IsGovPath(c, e.Roots) {
						return true
					}
					if recursive && pathx.IsGovAncestor(c, e.Roots) {
						return true
					}
				}
			}
		}
		for _, rd := range s.Redirects {
			if !isOutputRedirect(rd.Op) {
				continue
			}
			c := pathx.Canon(e.Resolver.Normalize(rd.Target.Text, cur))
			if pathx.IsGovPath(c, e.Roots) || pathx.IsGovAncestor(c, e.Roots) {
				return true
			}
		}
	}
	return false
}

func (e *Engine) govMutationTargets(binary string, args []string, cwd string) ([]string, bool) {
	recursive := false
	for _, a := range args {
		if isRecursiveFlag(a) || isRecursivePermFlag(a) {
			recursive = true
		}
	}
	switch binary {
	case "sed", "perl":
		if !hasInplaceFlag(args) {
			return nil, recursive
		}
		return inplaceFileOperands(args), recursive
	case "tar":
		var dirs []string
		for i, a := range args {
			if (a == "-C" || a == "--directory") && i+1 < len(args) {
				dirs = append(dirs, args[i+1])
			} else if strings.HasPrefix(a, "--directory=") {
				dirs = append(dirs, strings.SplitN(a, "=", 2)[1])
			}
		}
		return dirs, true
	case "rsync":
		ops := rsyncOperands(args)
		if len(ops) > 0 {
			return ops[len(ops)-1:], true
		}
		return nil, true
	case "dd":
		var out []string
		for _, a := range args {
			if strings.HasPrefix(a, "of=") {
				out = append(out, a[len("of="):])
			}
		}
		return out, recursive
	case "cp", "install", "tee", "ln":
		ops := nonFlagArgs(args)
		if len(ops) > 0 {
			return ops[len(ops)-1:], recursive
		}
		return nil, recursive
	case "chmod", "chown":
		ops := nonFlagArgs(args)
		if len(ops) > 1 {
			return ops[1:], recursive
		}
		return nil, recursive
	}
	return nonFlagArgs(args), recursive
}

// ---------------------------------------------------------------------------
// Interpretadores inline (python3 -c, perl -e, node -e, heredoc-stdin)
// ---------------------------------------------------------------------------

var (
	inlineRootDestruction = regexp.MustCompile(
		`\b(?:shutil\.rmtree|os\.rmtree|rmtree|rmSync|rmdirSync|unlinkSync|os\.(?:remove|unlink|rmdir))` +
			`\s*\(?\s*['"\s]*` +
			`(?:(?:/|~/?)(?:[\s,;)'"]|$)` +
			`|/(?:boot|etc|usr|var|sys|proc|dev|bin|sbin|lib|lib64|root|opt|srv|mnt|home)\b` +
			`|\*|\$HOME)`)

	inlineRM = regexp.MustCompile(
		`(?:^|[\s;&|(\x60])rm\s+-[A-Za-z]*[rR][A-Za-z]*f?[A-Za-z]*\s+` +
			`(?:/\*` +
			`|/(?:boot|etc|usr|var|sys|proc|dev|bin|sbin|lib|lib64|root|opt|srv|mnt|home)(?:[/\s);&\x60]|$)` +
			`|/(?:[\s);&\x60]|$)` +
			`|~/?\s*(?:[\s);&\x60]|$)` +
			`|\.\./?(?:[\s);&\x60]|$))`)

	inlineFind = regexp.MustCompile(
		`(?:^|[\s;&|(\x60])find\s+[^;&|\n]*\s(?:-delete|-(?:exec|execdir|ok)\s+(?:rm|shred|dd|sh|bash)\b)`)

	inlineShred = regexp.MustCompile(`(?:^|[\s;&|(\x60])shred\b[^;&|\n]*/dev/`)

	inlineDD = regexp.MustCompile(`(?:^|[\s;&|(\x60])dd\s+[^;&|\n]*\bof=/dev/`)
)

// Dequote substitui aspas por espaço (o interpretador avalia o texto).
func Dequote(code string) string {
	return strings.NewReplacer("'", " ", `"`, " ").Replace(code)
}

func inlineDestructiveText(dequoted string) bool {
	return inlineRM.MatchString(dequoted) || inlineRootDestruction.MatchString(dequoted) ||
		inlineFind.MatchString(dequoted) || inlineShred.MatchString(dequoted) ||
		inlineDD.MatchString(dequoted)
}

func (e *Engine) detectInlineInterpreter(cmd, cwd string) string {
	p := shparse.Parse(cmd, e.Resolver.Home)
	for _, s := range p.Simples {
		rest, _ := unwrapPrivilege(s.ArgsString())
		if len(rest) == 0 {
			continue
		}
		if _, ok := policy.InlineInterpreters[baseName(rest[0])]; !ok {
			continue
		}
		code := ""
		hasEval := false
		for _, a := range rest[1:] {
			if policy.Has(policy.EvalFlags, a) {
				hasEval = true
			}
		}
		if hasEval {
			code = strings.Join(rest[1:], " ")
		} else {
			// Modo stdin-script: `python3 - <<'EOF' ... EOF`.
			for _, rd := range s.Redirects {
				if rd.HasHdoc && rd.Hdoc != "" {
					code = rd.Hdoc
					break
				}
			}
		}
		if strings.TrimSpace(code) == "" {
			continue
		}
		if govPattern.MatchString(code) {
			return "deny"
		}
		dequoted := Dequote(code)
		if inlineDestructiveText(dequoted) {
			return "deny"
		}
		if bin, _ := e.detectDestructive(dequoted, cwd); bin != "" {
			return "deny"
		}
		if e.detectMutation(dequoted, cwd) != "" || e.detectPermAbuse(dequoted, cwd) != "" {
			return "deny"
		}
		if protectedMention.MatchString(code) {
			return "force_ask"
		}
	}
	return ""
}
