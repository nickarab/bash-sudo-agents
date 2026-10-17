package shparse

import "testing"

func TestSimpleCommand(t *testing.T) {
	p := Parse("lscpu", "/home/u")
	if p.Incomplete || len(p.Simples) != 1 {
		t.Fatalf("parse lscpu: %+v", p)
	}
	if got := p.Simples[0].ArgsString(); len(got) != 1 || got[0] != "lscpu" {
		t.Fatalf("args=%v", got)
	}
}

func TestControlKeywordsSeparateCommands(t *testing.T) {
	p := Parse("if true; then rm -rf /etc; fi", "/home/u")
	var found bool
	for _, s := range p.Simples {
		if s.Args[0].Text == "rm" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rm não encontrado na AST: %+v", p.Simples)
	}
}

func TestRedirectPreservesFD(t *testing.T) {
	p := Parse("echo x 1>/etc/fstab", "/home/u")
	if len(p.Simples) != 1 || len(p.Simples[0].Redirects) != 1 {
		t.Fatalf("redirects: %+v", p.Simples)
	}
	r := p.Simples[0].Redirects[0]
	if r.Op != ">" || r.Fd != "1" || r.Target.Text != "/etc/fstab" {
		t.Fatalf("redirect inesperado: %+v", r)
	}
}

func TestCmdSubstFlattened(t *testing.T) {
	p := Parse(`echo "$(rm -rf /)"`, "/home/u")
	var seen bool
	for _, s := range p.Simples {
		if s.Args[0].Text == "rm" && s.Subst {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("substituição não foi achatada: %+v", p.Simples)
	}
}

func TestSubshellAndPipe(t *testing.T) {
	p := Parse("( rm -rf / ) | tee log", "/home/u")
	if !p.HasPipe {
		t.Fatal("pipe não detectado")
	}
	if len(p.Simples) < 2 {
		t.Fatalf("subshell não achatada: %+v", p.Simples)
	}
}

func TestAnsiCQuotingDecoded(t *testing.T) {
	p := Parse(`bash -c $'rm -rf /e\x74c'`, "/home/u")
	if len(p.Simples) != 1 {
		t.Fatalf("parse: %+v", p)
	}
	if got := p.Simples[0].Args[2].Text; got != "rm -rf /etc" {
		t.Fatalf("ANSI-C não decodificado: %q", got)
	}
}

func TestParamExpansion(t *testing.T) {
	p := Parse("cat $HOME/x $OTHER/y", "/home/u")
	got := p.Simples[0].ArgsString()
	if got[1] != "/home/u/x" {
		t.Fatalf("HOME não expandido: %v", got)
	}
	if got[2] != "$OTHER/y" {
		t.Fatalf("variável desconhecida deveria permanecer: %v", got)
	}
}

func TestHeredocBody(t *testing.T) {
	p := Parse("python3 - <<'EOF'\nimport os\nEOF", "/home/u")
	if len(p.Simples) != 1 || len(p.Simples[0].Redirects) != 1 {
		t.Fatalf("heredoc: %+v", p.Simples)
	}
	if !p.Simples[0].Redirects[0].HasHdoc {
		t.Fatal("heredoc body não capturado")
	}
}

func TestParseErrorIncomplete(t *testing.T) {
	p := Parse("echo 'unclosed", "/home/u")
	if !p.Incomplete {
		t.Fatal("aspas desbalanceadas deveriam marcar Incomplete")
	}
}
