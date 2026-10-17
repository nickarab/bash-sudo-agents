// Package shparse transforma uma linha de comando shell em uma lista de
// comandos simples normalizados (argv + redirecionamentos), usando o parser
// POSIX/bash mvdan.cc/sh/v3/syntax. As detecções semânticas operam sobre esses
// nós — nunca sobre regex de texto cru.
package shparse

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Word é uma palavra já normalizada.
type Word struct {
	Text     string // texto com $VAR preservado e HOME expandido
	Static   bool   // sem expansões/substituições audáveis
	HasSubst bool   // contém substituição de comando/processo
}

// Redirect representa um redirecionamento com o fd explícito preservado
// (cobre `1>/etc/fstab`, que o motor legado perdia).
type Redirect struct {
	Op      string // ">", ">>", "<", ">&", ...
	Fd      string // "1", "2", "" ...
	Target  Word
	HasHdoc bool
	Hdoc    string
}

// Simple é um comando simples (CallExpr) normalizado.
type Simple struct {
	Args       []Word
	Redirects  []Redirect
	Background bool
	Subst      bool // originado de substituição de comando/processo
	Raw        string
}

// Result é o produto do parse.
type Result struct {
	Simples     []Simple
	Incomplete  bool // parse falhou (conservadorismo -> force_ask)
	HasPipe     bool
	HasRedirect bool
	Background  bool
}

// Args devolve apenas os textos das palavras.
func (s Simple) ArgsString() []string {
	out := make([]string, len(s.Args))
	for i, a := range s.Args {
		out[i] = a.Text
	}
	return out
}

// Parse analisa `cmd`, expandindo `$HOME` a partir de `home`.
func Parse(cmd, home string) *Result {
	res := &Result{}
	file, err := parseFile(cmd)
	if err != nil {
		res.Incomplete = true
		// Re-parse conservador segmento a segmento para maximizar o que é audável.
		for _, seg := range splitFallback(cmd) {
			f, err2 := parseFile(seg)
			if err2 != nil {
				continue
			}
			walkFile(res, f, home, false)
		}
		return res
	}
	walkFile(res, file, home, false)
	return res
}

func parseFile(cmd string) (*syntax.File, error) {
	p := syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.KeepComments(false))
	return p.Parse(strings.NewReader(cmd), "")
}

func walkFile(res *Result, file *syntax.File, home string, subst bool) {
	var walk func(n syntax.Node, subst bool)
	walk = func(n syntax.Node, subst bool) {
		syntax.Walk(n, func(node syntax.Node) bool {
			switch x := node.(type) {
			case *syntax.Stmt:
				if ce, ok := x.Cmd.(*syntax.CallExpr); ok {
					res.Simples = append(res.Simples, buildSimple(ce, x.Redirs, home, subst))
				}
				if x.Background {
					res.Background = true
				}
				if len(x.Redirs) > 0 {
					res.HasRedirect = true
				}
			case *syntax.BinaryCmd:
				if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
					res.HasPipe = true
				}
			case *syntax.CmdSubst:
				for _, st := range x.Stmts {
					walk(st, true)
				}
				return false
			case *syntax.ProcSubst:
				for _, st := range x.Stmts {
					walk(st, true)
				}
				return false
			}
			return true
		})
	}
	walk(file, subst)
}

func buildSimple(call *syntax.CallExpr, redirs []*syntax.Redirect, home string, subst bool) Simple {
	s := Simple{Subst: subst}
	for _, a := range call.Args {
		s.Args = append(s.Args, renderWord(a, home))
	}
	for _, r := range redirs {
		rd := Redirect{Op: r.Op.String()}
		if r.N != nil {
			rd.Fd = r.N.Value
		}
		if r.Word != nil {
			rd.Target = renderWord(r.Word, home)
		}
		if r.Hdoc != nil {
			rd.HasHdoc = true
			rd.Hdoc = renderWord(r.Hdoc, home).Text
		}
		s.Redirects = append(s.Redirects, rd)
	}
	s.Raw = renderSimple(&s)
	return s
}

// renderSimple reconstrói uma representação textual aproximada (para logs e
// detecção de substituição de privilégio).
func renderSimple(s *Simple) string {
	var sb strings.Builder
	for i, a := range s.Args {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(quoteIfNeeded(a.Text))
	}
	for _, r := range s.Redirects {
		sb.WriteByte(' ')
		if r.Fd != "" {
			sb.WriteString(r.Fd)
		}
		sb.WriteString(r.Op)
		sb.WriteString(quoteIfNeeded(r.Target.Text))
	}
	return sb.String()
}

func quoteIfNeeded(s string) string {
	if strings.ContainsAny(s, " \t\"'$&|;<>()") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

func renderWord(w *syntax.Word, home string) Word {
	var sb strings.Builder
	static := true
	hasSubst := false

	var render func(parts []syntax.WordPart)
	render = func(parts []syntax.WordPart) {
		for _, p := range parts {
			switch x := p.(type) {
			case *syntax.Lit:
				sb.WriteString(x.Value)
			case *syntax.SglQuoted:
				// Conteúdo literal; ANSI-C ($'...') é decodificado (fecha o
				// bypass `bash -c $'rm -rf /e\x74c'`).
				if x.Dollar {
					sb.WriteString(decodeAnsiC(x.Value))
				} else {
					sb.WriteString(x.Value)
				}
			case *syntax.DblQuoted:
				for _, part := range x.Parts {
					if lit, ok := part.(*syntax.Lit); ok {
						sb.WriteString(unescapeDbl(lit.Value))
						continue
					}
					render([]syntax.WordPart{part})
				}
			case *syntax.ParamExp:
				static = false
				name := ""
				if x.Param != nil {
					name = x.Param.Value
				}
				if name == "HOME" {
					sb.WriteString(home)
				} else if name != "" {
					sb.WriteString("$" + name)
				} else {
					sb.WriteString("${...}")
				}
			case *syntax.CmdSubst:
				static = false
				hasSubst = true
				sb.WriteString("$(...)")
			case *syntax.ProcSubst:
				static = false
				hasSubst = true
				sb.WriteString(x.Op.String() + "(...)")
			case *syntax.ArithmExp:
				static = false
				sb.WriteString("$((...))")
			case *syntax.ExtGlob:
				static = false
				sb.WriteString("*")
			default:
				static = false
			}
		}
	}
	render(w.Parts)
	return Word{Text: sb.String(), Static: static, HasSubst: hasSubst}
}

// decodeAnsiC decodifica escapes de `$'...'` (ANSIC quoting).
func decodeAnsiC(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			sb.WriteByte(c)
			continue
		}
		i++
		switch n := s[i]; n {
		case 'n':
			sb.WriteByte('\n')
		case 't':
			sb.WriteByte('\t')
		case 'r':
			sb.WriteByte('\r')
		case 'a':
			sb.WriteByte(7)
		case 'b':
			sb.WriteByte(8)
		case 'f':
			sb.WriteByte(12)
		case 'v':
			sb.WriteByte(11)
		case 'e', 'E':
			sb.WriteByte(27)
		case '\\', '\'', '"', '?':
			sb.WriteByte(n)
		case 'x':
			if b, ok := hexByte(s, i+1); ok {
				sb.WriteByte(b)
				i += 2
			} else {
				sb.WriteByte('\\')
				sb.WriteByte(n)
			}
		case 'u', 'U':
			// Unicode: mantém o escape literal (não impacta a auditoria de shell).
			sb.WriteByte('\\')
			sb.WriteByte(n)
		case '0', '1', '2', '3', '4', '5', '6', '7':
			val := int(n - '0')
			j := i + 1
			for j < len(s) && j < i+3 && s[j] >= '0' && s[j] <= '7' {
				val = val*8 + int(s[j]-'0')
				j++
			}
			sb.WriteByte(byte(val))
			i = j - 1
		default:
			sb.WriteByte('\\')
			sb.WriteByte(n)
		}
	}
	return sb.String()
}

func hexByte(s string, start int) (byte, bool) {
	if start+1 >= len(s) {
		return 0, false
	}
	v := func(c byte) (byte, bool) {
		switch {
		case c >= '0' && c <= '9':
			return c - '0', true
		case c >= 'a' && c <= 'f':
			return c - 'a' + 10, true
		case c >= 'A' && c <= 'F':
			return c - 'A' + 10, true
		}
		return 0, false
	}
	h, ok1 := v(s[start])
	l, ok2 := v(s[start+1])
	if !ok1 || !ok2 {
		return 0, false
	}
	return h<<4 | l, true
}

// unescapeDbl aplica as regras de escape dentro de aspas duplas do bash:
// `\` só escapa `$`, “ ` “, `"`, `\` e newline.
func unescapeDbl(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			n := s[i+1]
			switch n {
			case '$', '`', '"', '\\':
				sb.WriteByte(n)
				i++
				continue
			case '\n':
				i++
				continue
			}
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

// splitFallback divide conservadoramente em ; && || e newlines fora de aspas.
func splitFallback(cmd string) []string {
	var segs []string
	var buf strings.Builder
	quote := rune(0)
	runes := []rune(cmd)
	for i := 0; i < len(runes); i++ {
		ch := runes[i]
		if quote != 0 {
			buf.WriteRune(ch)
			if ch == quote {
				quote = 0
			} else if ch == '\\' && quote == '"' && i+1 < len(runes) {
				i++
				buf.WriteRune(runes[i])
			}
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
			buf.WriteRune(ch)
		case '\\':
			buf.WriteRune(ch)
			if i+1 < len(runes) {
				i++
				buf.WriteRune(runes[i])
			}
		case '\n', ';':
			segs = append(segs, buf.String())
			buf.Reset()
		case '|':
			segs = append(segs, buf.String())
			buf.Reset()
			if i+1 < len(runes) && runes[i+1] == '|' {
				i++
			}
		case '&':
			segs = append(segs, buf.String())
			buf.Reset()
			if i+1 < len(runes) && runes[i+1] == '&' {
				i++
			}
		default:
			buf.WriteRune(ch)
		}
	}
	segs = append(segs, buf.String())
	var out []string
	for _, s := range segs {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}
