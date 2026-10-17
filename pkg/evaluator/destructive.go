package evaluator

import (
	"strings"

	"github.com/nickarab/bash-sudo-agents/pkg/pathx"
	"github.com/nickarab/bash-sudo-agents/pkg/policy"
	"github.com/nickarab/bash-sudo-agents/pkg/shparse"
)

// ---------------------------------------------------------------------------
// RULE-02: detecção semântica de destruição (rm/find/shred/dd)
// ---------------------------------------------------------------------------

func (e *Engine) detectDestructive(cmd, cwd string) (string, bool) {
	bin := ""
	found, uncertain := e.walk(cmd, cwd, 0, func(rest []string, _ shparse.Simple, _ privInfo) bool {
		if len(rest) == 0 {
			return false
		}
		switch baseName(rest[0]) {
		case "rm":
			if e.rmIsDestructive(rest[1:], cwd) {
				bin = "rm"
				return true
			}
		case "find":
			if e.findIsDestructive(rest[1:], cwd) {
				bin = "find"
				return true
			}
		case "shred":
			if e.shredIsDestructive(rest[1:], cwd) {
				bin = "shred"
				return true
			}
		case "dd":
			if e.ddIsDestructive(rest[1:], cwd) {
				bin = "dd"
				return true
			}
		}
		return false
	})
	if !found {
		return "", uncertain
	}
	return bin, uncertain
}

func isRecursiveFlag(a string) bool {
	if a == "--recursive" {
		return true
	}
	return strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") &&
		(strings.Contains(a, "r") || strings.Contains(a, "R"))
}

func isRecursivePermFlag(a string) bool {
	if a == "--recursive" {
		return true
	}
	return strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "R")
}

func nonFlagArgs(args []string) []string {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

func (e *Engine) rmIsDestructive(args []string, cwd string) bool {
	targets := nonFlagArgs(args)
	if len(targets) == 0 {
		return false
	}
	recursive := false
	for _, a := range args {
		if isRecursiveFlag(a) {
			recursive = true
			break
		}
	}
	for _, a := range targets {
		norm := e.Resolver.Normalize(a, cwd)
		if pathx.IsVitalFileNorm(norm) {
			return true
		}
		if !recursive {
			continue
		}
		// Raiz do HOME e escape por `..` são sempre destrutivos (fim do bypass
		// que dependia de regex textual no motor legado).
		switch a {
		case "~", "~/", "$HOME", "${HOME}", "$HOME/", "${HOME}/", "..", "../", "./..", "./../":
			return true
		}
		if e.Resolver.IsVitalArg(a, cwd) {
			return true
		}
	}
	return false
}

func (e *Engine) findIsDestructive(args []string, cwd string) bool {
	for i, a := range args {
		if a == "-delete" || strings.HasPrefix(a, "-delete") {
			return true
		}
		switch a {
		case "-exec", "-execdir", "-ok":
			if i+1 < len(args) {
				inner := baseName(args[i+1])
				if inner == "rm" || inner == "shred" || inner == "dd" || inner == "sh" || inner == "bash" {
					return true
				}
			}
		case "-fprint", "-fprint0", "-fls", "-fprintf":
			if i+1 < len(args) && e.Resolver.IsVitalArg(args[i+1], cwd) {
				return true
			}
		}
	}
	return false
}

func (e *Engine) shredIsDestructive(args []string, cwd string) bool {
	for _, a := range nonFlagArgs(args) {
		if strings.HasPrefix(a, "/dev/") {
			return true
		}
		if e.Resolver.IsVitalArg(a, cwd) {
			return true
		}
	}
	return false
}

func (e *Engine) ddIsDestructive(args []string, cwd string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "of=") {
			dest := a[len("of="):]
			if strings.HasPrefix(dest, "/dev/") {
				return true
			}
			if e.Resolver.IsVitalArg(dest, cwd) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// RULE-02 estendida: mutação direta de caminho vital
// ---------------------------------------------------------------------------

func isOutputRedirect(op string) bool {
	switch op {
	case ">", ">>", ">|", "&>":
		return true
	}
	return false
}

func (e *Engine) detectMutation(cmd, cwd string) string {
	bin := ""
	e.walk(cmd, cwd, 0, func(rest []string, s shparse.Simple, _ privInfo) bool {
		// Redirecionamentos de saída (inclui fds numerados: 1>/etc/fstab).
		for _, rd := range s.Redirects {
			if isOutputRedirect(rd.Op) && e.Resolver.IsVitalArg(rd.Target.Text, cwd) {
				bin = "redirect"
				return true
			}
		}
		if len(rest) == 0 {
			return false
		}
		b := baseName(rest[0])
		args := rest[1:]
		switch {
		case policy.Has(policy.MutationBins, b):
			if e.mutationIsDestructive(b, args, cwd) {
				bin = b
				return true
			}
		case policy.Has(policy.InplaceBins, b):
			if e.inplaceIsDestructive(b, args, cwd) {
				bin = b
				return true
			}
		case b == "tar":
			if e.tarIsDestructive(args, cwd) {
				bin = "tar"
				return true
			}
		case b == "rsync":
			if e.rsyncIsDestructive(args, cwd) {
				bin = "rsync"
				return true
			}
		}
		return false
	})
	return bin
}

func (e *Engine) mutationIsDestructive(binary string, args []string, cwd string) bool {
	operands := nonFlagArgs(args)
	switch binary {
	case "mv":
		for _, a := range operands {
			if e.Resolver.IsVitalArg(a, cwd) {
				return true
			}
		}
	case "cp", "install", "tee", "ln":
		if len(operands) == 0 {
			return false
		}
		return e.Resolver.IsVitalArg(operands[len(operands)-1], cwd)
	case "truncate":
		for _, a := range operands {
			if e.Resolver.IsVitalArg(a, cwd) {
				return true
			}
		}
	}
	return false
}

func hasInplaceFlag(args []string) bool {
	for _, a := range args {
		if a == "-i" || strings.HasPrefix(a, "-i.") || strings.HasPrefix(a, "--in-place") {
			return true
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a[1:], "i") {
			return true
		}
	}
	return false
}

func inplaceFileOperands(args []string) []string {
	hasExpr := false
	for _, a := range args {
		if a == "-e" || a == "-f" || strings.HasPrefix(a, "--expression") || strings.HasPrefix(a, "--file") {
			hasExpr = true
		}
	}
	var files []string
	scriptConsumed := hasExpr
	for _, a := range args {
		if a == "inplace" {
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if !scriptConsumed {
			scriptConsumed = true
			continue
		}
		files = append(files, a)
	}
	return files
}

func (e *Engine) inplaceIsDestructive(binary string, args []string, cwd string) bool {
	if binary == "awk" {
		ok := false
		for i := range args {
			if args[i] == "-i" && i+1 < len(args) && args[i+1] == "inplace" {
				ok = true
			}
		}
		if !ok {
			return false
		}
	} else if !hasInplaceFlag(args) {
		return false
	}
	for _, a := range inplaceFileOperands(args) {
		if e.Resolver.IsVitalArg(a, cwd) {
			return true
		}
	}
	return false
}

func (e *Engine) tarIsDestructive(args []string, cwd string) bool {
	extract := false
	for _, a := range args {
		switch {
		case a == "--extract" || a == "--get" || a == "--untar":
			extract = true
		case !strings.HasPrefix(a, "-") && isAlpha(a) && strings.Contains(a, "x"):
			extract = true
		case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a[1:], "x"):
			extract = true
		}
	}
	if !extract {
		return false
	}
	for i, a := range args {
		var dest string
		if a == "-C" || a == "--directory" {
			if i+1 < len(args) {
				dest = args[i+1]
			}
		} else if strings.HasPrefix(a, "--directory=") {
			dest = strings.SplitN(a, "=", 2)[1]
		}
		if dest != "" && e.Resolver.IsVitalArg(dest, cwd) {
			return true
		}
	}
	return false
}

func isAlpha(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

func rsyncOperands(args []string) []string {
	var ops []string
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			ops = append(ops, args[i+1:]...)
			break
		}
		if policy.Has(policy.RsyncValueFlags, a) {
			i += 2
			continue
		}
		if strings.HasPrefix(a, "--") && strings.Contains(a, "=") {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			i++
			continue
		}
		ops = append(ops, a)
		i++
	}
	return ops
}

func (e *Engine) rsyncIsDestructive(args []string, cwd string) bool {
	ops := rsyncOperands(args)
	if len(ops) < 2 {
		return false
	}
	return e.Resolver.IsVitalArg(ops[len(ops)-1], cwd)
}

// ---------------------------------------------------------------------------
// RULE-05: abuso de permissões
// ---------------------------------------------------------------------------

func modeIsWorldWritable(tok string) bool {
	t := strings.ToLower(tok)
	if policy.Has(policy.WorldWritableSymbolic, t) {
		return true
	}
	if isDigits(t) && len(t) >= 3 {
		last := t[len(t)-1]
		return (last-'0')&2 != 0
	}
	return false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func looksLikeMode(tok string) bool {
	return isDigits(tok) || strings.ContainsAny(tok, "+=")
}

func (e *Engine) chmodIsAbusive(args []string, cwd string) bool {
	recursive := false
	for _, a := range args {
		if isRecursivePermFlag(a) {
			recursive = true
			break
		}
	}
	if !recursive {
		return false
	}
	var targets []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if modeIsWorldWritable(a) {
			return true
		}
		if !looksLikeMode(a) {
			targets = append(targets, a)
		}
	}
	for _, a := range targets {
		if strings.Contains(a, "$") {
			return true
		}
		if pathx.IsSystemPathNorm(e.Resolver.Normalize(a, cwd)) {
			return true
		}
	}
	return false
}

func (e *Engine) chownIsAbusive(args []string, cwd string) bool {
	recursive := false
	for _, a := range args {
		if isRecursivePermFlag(a) {
			recursive = true
			break
		}
	}
	if !recursive {
		return false
	}
	operands := nonFlagArgs(args)
	for _, a := range operands[min(1, len(operands)):] {
		if strings.Contains(a, "$") {
			return true
		}
		if pathx.IsSystemPathNorm(e.Resolver.Normalize(a, cwd)) {
			return true
		}
	}
	return false
}

func (e *Engine) detectPermAbuse(cmd, cwd string) string {
	bin := ""
	e.walk(cmd, cwd, 0, func(rest []string, _ shparse.Simple, _ privInfo) bool {
		if len(rest) == 0 {
			return false
		}
		switch baseName(rest[0]) {
		case "chmod":
			if e.chmodIsAbusive(rest[1:], cwd) {
				bin = "chmod"
				return true
			}
		case "chown":
			if e.chownIsAbusive(rest[1:], cwd) {
				bin = "chown"
				return true
			}
		}
		return false
	})
	return bin
}

// ---------------------------------------------------------------------------
// RULE-03 (disco) e RULE-07 (serviços / energia)
// ---------------------------------------------------------------------------

func (e *Engine) detectDisk(cmd, cwd string) bool {
	found := false
	e.walk(cmd, cwd, 0, func(rest []string, _ shparse.Simple, _ privInfo) bool {
		if len(rest) == 0 {
			return false
		}
		b := baseName(rest[0])
		switch {
		case strings.HasPrefix(b, "mkfs"), policy.Has(policy.DiskBins, b):
			found = true
			return true
		case b == "mount" && len(rest) >= 2:
			found = true
			return true
		}
		return false
	})
	return found
}

func (e *Engine) detectPower(cmd, cwd string) bool {
	found := false
	e.walk(cmd, cwd, 0, func(rest []string, _ shparse.Simple, _ privInfo) bool {
		if len(rest) == 0 {
			return false
		}
		b := baseName(rest[0])
		switch b {
		case "systemctl":
			for _, tok := range rest[1:] {
				if policy.Has(policy.PowerVerbs, tok) {
					found = true
					return true
				}
			}
		case "loginctl":
			for _, tok := range rest[1:] {
				if policy.Has(policy.LoginctlVerbs, tok) {
					found = true
					return true
				}
			}
		case "shutdown", "reboot", "poweroff", "halt", "telinit":
			found = true
			return true
		case "init":
			for _, tok := range rest[1:] {
				if tok == "0" || tok == "6" {
					found = true
					return true
				}
			}
		}
		return false
	})
	return found
}

var serviceKillWords = []string{
	"hyprland", "wayland", "xorg", "xwayland", "sddm", "gdm",
	"sddm-helper", "gnome-shell", "sway",
}

func (e *Engine) detectServiceKill(cmd, cwd string) bool {
	found := false
	e.walk(cmd, cwd, 0, func(rest []string, _ shparse.Simple, _ privInfo) bool {
		if len(rest) == 0 {
			return false
		}
		b := baseName(rest[0])
		switch b {
		case "systemctl":
			hasVerb := false
			hasCritical := false
			for _, tok := range rest[1:] {
				if strings.HasPrefix(tok, "-") {
					continue
				}
				if policy.Has(policy.ServiceVerbs, tok) {
					hasVerb = true
				}
				if _, ok := policy.CriticalServices[tok]; ok || strings.HasPrefix(tok, "getty") {
					hasCritical = true
				}
			}
			if hasVerb && hasCritical {
				found = true
				return true
			}
		case "pkill", "killall":
			for _, tok := range rest[1:] {
				lt := strings.ToLower(tok)
				for _, w := range serviceKillWords {
					if lt == w || strings.Contains(lt, w) {
						found = true
						return true
					}
				}
			}
		case "kill":
			has9 := false
			has1 := false
			for _, tok := range rest[1:] {
				if tok == "-9" || tok == "-KILL" || tok == "-s" {
					has9 = true
				}
				if tok == "1" {
					has1 = true
				}
			}
			if has9 && has1 {
				found = true
				return true
			}
		}
		return false
	})
	return found
}

// ---------------------------------------------------------------------------
// Anti-fadiga: variáveis não resolvidas e limpeza de /var/log
// ---------------------------------------------------------------------------

func (e *Engine) hasUnresolvedTarget(cmd, cwd string) bool {
	found := false
	e.walk(cmd, cwd, 0, func(rest []string, s shparse.Simple, _ privInfo) bool {
		if len(rest) > 0 {
			if _, ok := policy.UnresolvedOps[baseName(rest[0])]; ok {
				for _, a := range rest[1:] {
					if strings.HasPrefix(a, "-") {
						continue
					}
					if strings.Contains(e.Resolver.ExpandHome(a), "$") {
						found = true
						return true
					}
				}
			}
		}
		for _, rd := range s.Redirects {
			if isOutputRedirect(rd.Op) && strings.Contains(e.Resolver.ExpandHome(rd.Target.Text), "$") {
				found = true
				return true
			}
		}
		return false
	})
	return found
}

// hasAmbiguousSymlink detecta alvos cuja resolução de symlink é incerta
// (ELOOP/ENAMETOOLONG): nunca se degrada para comparação léxica silenciosa.
func (e *Engine) hasAmbiguousSymlink(cmd, cwd string) bool {
	found := false
	e.walk(cmd, cwd, 0, func(rest []string, s shparse.Simple, _ privInfo) bool {
		if len(rest) > 0 {
			if _, ok := policy.UnresolvedOps[baseName(rest[0])]; ok {
				for _, a := range rest[1:] {
					if strings.HasPrefix(a, "-") || strings.Contains(a, "$") {
						continue
					}
					if _, kind := e.Resolver.Resolve(a, cwd); kind == pathx.SymlinkAmbiguous {
						found = true
						return true
					}
				}
			}
		}
		for _, rd := range s.Redirects {
			if !isOutputRedirect(rd.Op) || strings.Contains(rd.Target.Text, "$") {
				continue
			}
			if _, kind := e.Resolver.Resolve(rd.Target.Text, cwd); kind == pathx.SymlinkAmbiguous {
				found = true
				return true
			}
		}
		return false
	})
	return found
}

func looksLikePath(a string) bool {
	return strings.HasPrefix(a, "/") || strings.HasPrefix(a, "~") ||
		strings.HasPrefix(a, "./") || strings.HasPrefix(a, "../") || strings.Contains(a, "/")
}

func (e *Engine) isVarLog(arg, cwd string) bool {
	if strings.Contains(e.Resolver.ExpandHome(arg), "$") {
		return false
	}
	return pathx.IsVarLog(e.Resolver.Normalize(arg, cwd))
}

func (e *Engine) varlogCleanupAllowed(cmd, cwd string) bool {
	allowed := true
	saw := false
	e.walk(cmd, cwd, 0, func(rest []string, s shparse.Simple, _ privInfo) bool {
		if len(rest) > 0 && baseName(rest[0]) == "truncate" {
			var ops []string
			for _, a := range rest[1:] {
				if !strings.HasPrefix(a, "-") && looksLikePath(a) {
					ops = append(ops, a)
				}
			}
			if len(ops) == 0 {
				allowed = false
				return true
			}
			for _, a := range ops {
				if !e.isVarLog(a, cwd) {
					allowed = false
					return true
				}
			}
			saw = true
		}
		for _, rd := range s.Redirects {
			if !isOutputRedirect(rd.Op) {
				continue
			}
			if !e.isVarLog(rd.Target.Text, cwd) {
				allowed = false
				return true
			}
			saw = true
		}
		return false
	})
	return allowed && saw
}
