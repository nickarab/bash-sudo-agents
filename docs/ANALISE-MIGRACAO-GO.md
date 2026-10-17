# Análise Técnica e Plano de Engenharia — Migração do Governance Gate para Go

**Projeto:** `bash-sudo-agents` (Antigravity Linux Governance Engine)
** Estado atual:** v4.5.0 — motor 100% Python 3 (`plugin/hooks/governance-gate.py`, 1.871 linhas)
**Objetivo desta entrega:** diagnóstico do runtime atual, mapeamento de requisitos, especificação arquitetural do substituto em Go e plano de erradicação total do ecossistema Python.
**Escopo explícito:** regras legadas de `monitors.lua` (RULE-01) saem do portfólio do novo motor. Todo Python — hook, testes, scripts inline do instalador, caches — será excluído.

---

## 1. Mapeamento de Requisitos e Fluxo do Hook

### 1.1 Ciclo de vida do `PreToolUse` no Antigravity

O gate é registrado em `hooks.json` como `matcher: "*"` (todas as ferramentas), tipo `command`, timeout 15 s. O ciclo por chamada de ferramenta do agente é:

```
Agente (@agente-bash) quer executar ferramenta
        │
        ▼
Antigravity Host ── serializa payload JSON ──▶ stdin do gate
   { toolCall: { name, args: { CommandLine, TargetFile, Cwd } },
     cwd, workspacePaths, ... }
        │
        ▼
governance-gate (processo novo a cada chamada)
   1. parse do payload (tolerante a variações de schema)
   2. auditoria constitucional (RULE-02..15) → (decision, reason)
   3. RULE-10: contador de recusas consecutivas (persistente)
   4. cache TTL + auto-compressor → possível "overwrite" de CommandLine
   5. audit.log estruturado (JSONL, metadados fora do contrato)
        │
        ▼
stdout: UMA linha JSON → host aplica a decisão
   { "decision": "...", "reason": "...", "overwrite": { "CommandLine": "..." } }
```

Pontos contratuais que o novo motor em Go deve preservar byte-a-byte:

| Aspecto | Contrato atual |
|---|---|
| Entrada | JSON no stdin; vazio ou malformado ⇒ **force_ask** (fail-closed, v4.5.0) |
| Saída | exatamente um objeto JSON em stdout; exit code sempre `0` |
| Chaves aceitas | `decision` (sempre), `reason` (opcional), `overwrite.CommandLine` (opcional) |
| Campos lidos | `toolCall.name`, `toolCall.args.{CommandLine\|command, TargetFile\|file_path, Cwd\|cwd}`, `cwd` top-level, `command`/`toolName`/`target` de fallback, `workspacePaths[]` |
| Efeitos colaterais | cache dir + rejection state + audit log; NUNCA devem bloquear/falhar a decisão |
| Timeout | 15 s no host; estouro ⇒ stdout vazio ⇒ comportamento do host (indefendido hoje) |

### 1.2 Taxonomia de decisões (semântica exigida)

A taxonomia anti-fadiga consolidada na v4.4.0/v4.5.0 é o coração do produto:

1. **`auto_approve`** — único valor do contrato que **pula o card de aprovação nativo**. Emissões:
   - diagnósticos seguros auditados sem命中 de regra (`lscpu`, `ls -la`, `echo ...`);
   - ferramentas de leitura puras sem `CommandLine` (`view_file`, `grep_search`, …) — `TargetFile` auditado antes;
   - **hits de cache** (`cat <cache_file>`) e **wrappers de escrita de cache** (`( cmd ) | tee <cache>`);
   - overwrites do compressor (journalctl/dmesg/git log/pacman) — sempre re-auditados antes da emissão.
2. **`allow`** — delega à política padrão do host (que mostra diff/review nativo). Reservado a ferramentas de **escrita/orquestração** sem alvo protegido (`write_to_file`, `edit_file`, `invoke_subagent`, …). Não pula o card de `run_command` — por isso NUNCA é usado para comandos de terminal.
3. **`ask`** — elevação **rotineira**: `sudo`/`doas`/`pkexec`/`su`/`run0`, `sudo -e`/`sudoedit`, `pacman|yay|paru -S*` (exceto busca `-Ss`), `systemctl` de sistema (sem `--user`), e limpeza de `/var/log` (`truncate`/redirect). Compatível com o **"Always Allow" nativo**: o usuário aprova uma vez por recurso e para de ser perguntado.
4. **`force_ask`** — pergunta **sempre**, ignora grants acumulados: irreversíveis de energia/sessão (`reboot`, `poweroff`, `shutdown`, `systemctl|loginctl suspend|hibernate|lock-session`, `init 0|6`), disco/formatação (`mkfs`, `fdisk`, `parted`, `umount`, `wipefs`, `losetup`, `cryptsetup`, `sgdisk`, `mount -opts`), alvos com `$VAR` não resolvida em operações de mutação, interpretadores inline referenciando caminho vital e **qualquer fail-closed** (stdin vazio, JSON inválido, schema sem CommandLine de ferramenta desconhecida, panic interno).
5. **`deny`** — veto sumário: destruição recursiva em raiz/vitais (`rm -rf /etc`, `find -delete`, `shred /dev/*`, `dd of=/dev/*`), mutação direta de vital (`mv/cp/install/truncate/tee/ln/sed -i/tar -x -C/rsync`/redirect `>`), serviço crítico da sessão (`systemctl restart sddm`, `pkill hyprland`, `kill -9 1`), `sudo_runner` legado (RULE-06) e **mutação da própria infraestrutura de governança** (plugin, policies, `hooks.json` global e de workspace — RULE-11/12).

### 1.3 Compressão de saída (injeção de wrappers sintáticos)

Objetivo: economizar tokens de contexto do LLM sem alterar a semântica pedida. Gatilhos atuais (só quando o comando **não** tem pipe nem redirect):

| Comando | Overwrite injetado | Guarda |
|---|---|---|
| `journalctl …` | `… --no-pager -n 35` | não injeta se houver `-n N`/`--lines N`/`-f`/`--follow` |
| `dmesg …` | `… --color=never \| tail -n 35` | não injeta se houver `-w`/`--follow`/`tail`/`head` |
| `git log …` | `… -n 15` | não injeta se houver `-N`/`-n N` |
| `pacman/yay/paru -Ss …` | `… \| head -n 25` (dentro do wrapper de cache) | — |

Requisito inegociável (Seção 5.5 do código legado): **todo overwrite é re-auditado** (`_emit_overwrite` → `audit_command(new_cmd)`); se a re-auditoria não aprovar, o gate emite `deny` e nunca o overwrite. Em Go isso vira invariante de arquitetura: o caminho de emissão de overwrite só existe através de uma função que obriga a segunda passada do avaliador (impossível de "esquecer", como detalhado em §3.5).

### 1.4 Cache com TTL e controle de recusas 3X

- **Cache:** whitelist de binários estáticos/diagnósticos (`lscpu`, `uname`, `lspci`, `lsusb`, `pacman|yay|paru -Ss`, `cat /etc/os-release`, `cat /proc/cpuinfo`). TTL 3600 s (diagnóstico) / 600 s (busca de pacote). Chave = hash do comando + cwd + `LANG` + `LC_ALL`. No MISS, o gate injeta `( <cmd> ) | tee <cache>`; no HIT, injeta `cat <cache>`. O compressor `-Ss` é embutido no wrap para o cache já gravar saída truncada.
- **Rejeições (RULE-10):** contador de recusas **consecutivas** persistido em JSON (`deny` incrementa; qualquer outra decisão zera). Ao atingir 3, o `reason` ganha o bloco de escalação (🛑 ALERTA … EXECUÇÃO SUSPENSA). TTL de inatividade 24 h.

---

## 2. Diagnóstico de Falhas e Vulnerabilidades do Python Atual

Análise crítica do `governance-gate.py` v4.5.0. Cada item é um requisito de correção para o port em Go. Medições feitas nesta máquina (Python 3.14.7): custo de gateamento por chamada ≈ **30–40 ms** (0,110 s / 3 execuções sequenciais), somados ao fork/exec do host.

### 2.1 Fragilidades do parser sintático (`shlex` + regex)

O design atual é um *híbrido*: um segmentador de caracteres feito à mão (`_shell_split_commands`) + `shlex.split` por segmento + uma "superfície" com strings removidas (`_regex_surface`) para ~10 regexes de fallback. Nenhum deles entende **gramática** de shell. Bypasses e erros concretos:

1. **Substituição de processo `<(...)` / `>(...)`** — o segmentador não reconhece `<(`; `diff <(a) <(rm -rf /x)` vira tokens colados `<(rm`, `-rf`, `/x)` que nenhum detector de `rm` semântico inspeciona (só sobrevive se a regex de superfície casar por sorte o padrão literal `rm\s+-...`). `tee >(sh redirigido)` idem.
2. **`bash -c` só é recursado quando o binário é o primeiro token "nu"** — `su -c "rm -rf /" root` e qualquer `-c` atrás de env/variável escapa: `su`/`run0` **não** estão em `SHELL_BINS` nem no unwrapper, logo `_detect_destructive` termina com `argv[0]=="su"` e o comando inteiro cai em `ask` (não `deny`). Elevação rotineira carregando payload destrutivo literal é rebaixada de veto para "pergunta".
3. **Heredocs** — `python3 - <<'EOF\nimport os; os.system("rm -rf /")\nEOF` não tem `-c`, o corpo do heredoc é fatiado por `\n` como se fossem comandos independentes (falsos positivos) ou ignorado conforme formatação. `_detect_inline_interpreter` só cobre flags `-c/-e/--eval`, não stdin script.
4. **Continuação de linha com `\` + newline** — o segmentador consome `\`+char, mas `shlex.split` do segmento reinterpeta o resultado de forma diferente do shell; comandos `rm \<nl>-rf /` podem quebrar a detecção semântica (dependendo da posição da quebra dentro do token).
5. **Palavras-chave de controle não são separadores** — `if true; then rm -rf /etc; fi` produz segmento `then rm -rf /etc` ⇒ `argv[0]=="then"` ⇒ detecção semântica falha; só não é bypass total porque a regex de fallback (`_BOUNDARY` = whitespace) resgata. `for f in …; do rm $f; done`, `{ rm -rf /; }`, `(rm -rf /)` (sem espaço), `eval "…"` — todos dependem exclusivamente de **regex sobre texto**, exatamente a classe de fragilidade que o projeto declarou superar ("Parser semântico com shlex para substituir regex frágeis" — docstring item 7 — na prática virou *shlex **e** ~12 regexes*).
6. **`_regex_surface` remove conteúdo de `$'...'`** — ANSI-C quoting: `bash -c $'rm -rf /e\x74c'` tem o interior riscado da superfície (o `'` abre string literal no scanner de aspas); o path com escape hexadecimal nem casaria os padrões. Bypass duplo (superfície + normalização).
7. **Variáveis de ambiente no caminho do binário e prefixos** — `_unwrap_privilege_prefix` trata `VAR=x cmd` apenas para `env` explícito como token; `LD_PRELOAD=/x sudo ls` é aceito, mas `$SUDO_BIN rm -rf /etc` e `command -v`-style dispatch não têm semântica. Flags de `sudo` em `parse_command` (`value_flags`) divergem das de `_unwrap_privilege_prefix` (`skip_with_value`: um set tem `-p --login`, outro `-C -D`) — inconsistência interna que produz `target_bin` errado conforme a chamada.
8. **Whitelist de privilégio incompleta** — `apt`, `dnf`, `zypper`, `emerge`, `ninja -C`, `podman run --privileged -v /:/host`, `nsenter`, `chroot`, `unshare` não são classificados; `pacman --sync` (forma longa) não casa `^-S(?![si])`. Na direção oposta, o gate **nega** o que importa (destruição), mas **deixa passar como `auto_approve`** writes em `/etc` via `podman`/`nsenter`/`tee` embutido em interpreted languages (item 3).
9. **`find`** — `_find_is_destructive` cobre `-delete`/`-exec rm`, mas ignora `-fprint`/`-fls`/`-fprintf` (escrita arbitrária em caminho vital) e `-exec sh -c '…'` (inner `sh` não está no set de verificação).
10. **Prefixo de compressor é string crua** — `cmd.startswith("journalctl")` casa `journalctl_evil`; `startswith("git log")` casa `git loganything`. Sobrevive à re-auditoria, mas injeta flags em comandos que o usuário/agente não escreveu (violação do contrato "overwrite conservador").
11. **Regex de redirect** `(?<![0-9])>{1,2}` **exclui `1>/etc/fstab` e `2>/etc/x`** — exatamente as formas numeradas que scripts de build usam. Escrever em `/etc/fstab` via `echo x 1>/etc/fstab` **não** é vetado pela RULE-02 estendida. (Bypass funcional real, não teórico.)

### 2.2 Race conditions e falhas de concorrência

O contrato do hook (**processo novo por chamada de ferramenta**, multiplicado por subagentes paralelos) garante que múltiplas instâncias do gate operam nos mesmos arquivos de estado. Hoje **não há nenhum lock** (`fcntl`/`flock` ausente do código) e nenhuma escrita é atômica.

**Evidência empírica nesta máquina:** 24 execuções concorrentes de `deny` no mesmo `HOME`, com um leitor agressivo observando `rejection_state.json`:

```
leituras com JSON corrompido: 25 (de um pool contínuo de leituras)
```

Consequências mapeadas:

1. **Truncation window do `write_text()`** (`open(path,'w')` + write): leitores veem o arquivo **vazio/parcial**. No gate, `_load_rejection_state()` captura a exceção e retorna `{"count": 0}` ⇒ **a Regra 3X pode nunca disparar sob concorrência** (o contador zera silenciosamente no meio de uma sequência real de refusas). Fail-open na escalada.
2. **Lost update no read-modify-write do contador** — duas instâncias leem `count=2`, ambas escrevem `count=3`; a terceira refusão vira `4`? Não: vira `3` de novo. Com N paralelos o contador é arbitrário. A escalada 3X é, portanto, *não determinística* em cenários multi-agente — que é justamente o caso de uso principal do produto.
3. **`_clear_rejection_state` usa `unlink`** concorrente com `exists()`/`read_text()` de outros processos — TOCTOU clássico (`FileNotFoundError` capturado e ignorado; estado pode ser apagado entre o `deny` de um agente e o seu `_save`).
4. **Cache**: HIT faz `exists()` + `stat()` + `stat()` novamente (double stat, valores podem divergir); MISS faz dois ou mais agentes escreverem o mesmo `<hash>.cache` com `tee` **não atômico** — HIT posterior pode servir `cat` de arquivo **interleavado/corrompido** ou parcialmente truncado por um `tee` concorrente ainda em execução (o gate injeta o `cat cache` antes do writer terminar? Não — só no processo filho; mas dois processos-irmãos com o mesmo comando em paralelo criam exatamente esse par MISS/MISS). Não há validação de integridade de conteúdo (só tamanho > 0 e mtime).
5. **`CACHE_DIR.mkdir()` seguido de `os.chmod(0o700)`** — janela em que o diretório existe com modo herdado do umask; e `parents=True` cria intermediários sem a mesma garantia.
6. **`audit.log` abre/fecha a cada entrada** (append O_APPEND < PIPE_BUF é quase atômico, mas a criação do diretório/log em paralelo com o item 5 reintroduz a janela).

### 2.3 Tratamento de traversal e symlinks

1. **Deteção de vitais é léxica** — `_rm_is_destructive`/`_path_is_vital` usam `_normalize_path` (`os.path.normpath`) **sem resolver symlinks**. O `_canon_path` com `realpath` só existe no caminho de governança (RULE-12). Consequência direta: `ln -s /etc x && rm -rf x` (ou um symlink pré-existente em `~/tmp -> /usr`) **escapa da RULE-02** e é emitido como `auto_approve`. Só a sorte (gov pattern) pega `x` apontando para dentro de `~/.gemini`.
2. **`resolve_target_safely`** inclui `/tmp` (world-writable) como raiz permitida e resolve **antes** da execução da ferramenta: TOCTOU clássico — o agente escreve `TargetFile=/tmp/link`, o gate resolve `/tmp/link -> /etc/shadow`? Não: resolve e **rejeita** (fora das raízes). Mas se o symlink for trocado *depois* da auditoria (`ln -s /home/proj/x /tmp/w` no momento do gate; `ln -s /etc/y /tmp/w` no momento do host tool), a escrita cai fora de qualquer escopo auditado. Sem `O_NOFOLLOW`/verificação de dono em nada no fluxo.
3. **`$HOME` expandido por `str.replace`** — `_expand_home_vars` substitui `${HOME}`/`$HOME` literais em qualquer posição, inclusive dentro de strings do comando já removidas/escapadas de formas que o shell interpretaria diferente (e.g. `'$HOME/x'` single-quoted NÃO é expandida pelo shell, mas o gate expande — comportamento divergente, pode gerar tanto falso positivo quanto máscara).
4. **cwd do payload é aceito cru** — `cwd = Path(cwd_str)` sem `os.path.realpath`; um `cwd` relatando caminho via symlink faz alvos **relativos** serem normalizados contra uma base não resolvida, deslocando toda a comparação de vitais/governança.
5. **Comparação de ancestrais por prefixo de string** (`_under`) — correta para `/` + segmento, mas aplicada sobre `realpath` de um lado e `_canon_path` "melhor esforço" do outro (fallbacks `except: return norm` silenciam ELOOP/EPERM ⇒ a comparação pode voltar a ser léxica sem aviso).

### 2.4 Latência de runtime (cold-start)

Medido nesta máquina: **≈30–40 ms por invocação** apenas de Python (import de `re`/`json`/`shlex`/`pathlib` + compilação dos ~14 regex de módulo + `Path.home()` + syscalls de estado), fora o `fork+exec` do host. Cada turno do agente dispara 1..N hooks (uma por ferramenta, e subagentes paralelos multiplicam). Com o pipeline de compressão, o hook está no caminho crítico de **todas** as interações. Um binário Go estático comparable mede tipicamente **1–3 ms** (sem VM, sem import graph, regex pré-compilados no build), redução de ~10–30×; e elimina o *dependency surface* do `python3` do sistema-alvo (versão mínima 3.8 verificada no instalador, comportamento de `shlex` variando entre CPython minor).

### 2.5 Riscos de fail-open

1. **stdout vazio ⇒ host decide** — todas as defesas vivem em `out()`, que **só roda se o processo sobreviver**. Vetores de morte silenciosa: (a) timeout de 15 s do host (loops internos nunca protegidos por deadline); (b) `SIGKILL`/OOM; (c) **exceção dentro do próprio `out()`**: `print(json.dumps(..., ensure_ascii=False))` com `reason` contendo `🛑`/`—` sob stdout non-UTF-8 ⇒ `UnicodeEncodeError`. Em `LC_ALL=C` a coação PEP 540 salva (verificado nesta máquina: o emoji saiu íntegro), mas o sistema tem locales `*.iso885915` instalados — sob um deles, a escalação 3X *crasha dentro do handler de failsafe* (`main` chama `out()` de novo com o mesmo caractere problemático) e o processo morre com exit 1 e stdout vazio. **O evento de maior severidade do gate (3 refusões seguidas) é o que tem maior chance de produzir saída vazia.** Em Go, stdout é byte-stream: nunca há erro de encoding (e `encoding/json` escapa o que for preciso) — a classe de bug desaparece por construção.
2. **`except Exception: pass` como política de estado** — corrupção de cache/estado/lock ⇒ decisão continua como se nada existisse; especificamente o contador 3X vira 0 (§2.2.1), ou seja, **a degradação falha para menos fricção = fail-open de escalada**.
3. **`depth > _MAX_RECURSION: return None`** — nesting de `bash -c "bash -c '...bash -c \"rm -rf /\"...'"` além de 3 níveis ⇒ destruição detecta **nada** e emite allow. O teto deveria ser "não consegui analisar ⇒ force_ask", não "não analisei ⇒ OK".
4. **`has_redirect` por `[<>]` no texto cru** é usado para **desligar o compressor**, mas o caminho inverso importa: um comando que a auditoria semântica não entende é emitido `allow`/`auto_approve` no fim do fluxo (`return "allow"` default). O default "não casou regra ⇒ seguro" é fail-open *por design de whitelist inversa*: qualquer nova classe de ataque fora dos 15 padrões passa. O motor em Go não elimina isso (o mundo é maior que as regras), mas pode torná-lo *medido*: logar `rule=None` decisions com latência e hash, e manter um regime de fuzzing (ver §3.7).
5. **`_load_rejection_state` aceita JSON válido com lixo** — `data.get("count", 0)` sem verificação de tipo: `{"count": "9999"}` vindos de corrupção prévia disparam escalada permanente, e `{}` (escrito por terceiros) zera tudo. Estado deve ser validado de forma estrita e assinado internamente (ver §3.4).

---

## 3. Especificação de Engenharia: COMO será implementado em Go

### 3.0 Princípios do design

- **Um binário estático, zero runtime deps.** `CGO_ENABLED=0`, sem Python, sem interprete, sem pip.
- **Gramática em vez de regex.** O comando é **parseado** (AST do POSIX/bash) e as detecções operam sobre **nós semânticos**. Regex continuam apenas como *tie-breaker* de texto (mensagens), nunca como fonte de veto.
- **Fail-closed por construção da linguagem.** Panic ⇒ `force_ask`; erro de parse ⇒ conservadorismo; estado ilegível ⇒ tratar como *pior caso* (contador suspeito ⇒ manter fricção), não como zero.
- **Concorrência correta no SO, não no processo.** Múltiplas instâncias simultâneas são o modelo de execução; todo estado compartilhado passa por `flock` + rename atômico.

### 3.1 Parser de shell e AST — `pkg/shparse`

Biblioteca: **`mvdan.cc/sh/v3/syntax`** (parser de shell POSIX/bash em Go puro, mantido ativamente, sem cgo).

Pipeline de análise de um `CommandLine`:

1. **Parse tolerante**: `syntax.Parser{KeepComments:false}` sobre a string. Em `ParseError`, tenta re-parse **segmento a segmento** (split conservador em `;`/`&&`/`||`/newline fora de aspas) para maximizar o que é auditável; o que não parses ⇒ marca `incompreendido=true` (→ §3.5, regra de conservadorismo).
2. **Parse interativa** (`parser.Interactive` = false, `syntax.KeepRedirection`) para capturar também `<(...)`.
3. **Walk estruturado** com `syntax.Walk` inspecionando tipos de nó:
   - `*syntax.CallExpr` → `Args []*WordExpr`; a primeira palavra é o **binário**: resolve literais via `syntax.Word` quando `Lit`, marca como `dinâmica` quando contém `CmdSubst`/`ParamExp` que não se pode provar o valor;
   - `*syntax.BinaryCmd` (&&, ||), `*syntax.Stmt`, `*syntax.Pipeline` (inclui `Stdin`/`>` `<`), `*syntax.Redirect` (`>`, `>>`, `>|`, `n>`, `n>|` — **cobrindo `1>/etc/fstab` que a regex atual perde**), `*syntax.CmdSubst` (recurse!), `*syntax.CallApp`/`*syntax.BlockStmt`/`*syntax.Subshell`/`*syntax.FuncDecl`/`*syntax.WhileStmt`/`*syntax.ForStmt`/`*syntax.CaseClause` (todos os escapes do §2.1 viram nós nomeados de AST, não texto);
   - `*syntax.ParamExp` com nomes conhecidos (`HOME`) ⇒ expande; outros ⇒ `unresolved` (→ `force_ask`, preservando a semântica anti-fadiga v4.5.0);
   - herídocs: `Redir.Op == syntax.Dshift` com `Word` literal ⇒ o corpo **é** analisado se o binário for interpretador com modo stdin-script (fechando §2.1.3).
4. **Normalização semântica por binário** (a "IR" do gate): para cada `CallExpr` reconhecido, um extrator dedicado produz uma struct rica: `{op: RM, recursive: true, force: true, targets: [path...], unresolved: false}`. Um arquivo `ops.go` registra os extratores por classe (`rm/find/shred/dd/mv/cp/install/truncate/tee/ln/sed/perl/awk/tar/rsync/chmod/chown/systemctl/loginctl/mount-class/interpreters-class`). Isso substitui as ~25 funções heurísticas soltas do Python por uma **tabela de despachos testável por unidade**.
5. **Recursão estrutural nos wrappers**: os nós já resolvidos de `sudo|doas|pkexec|run0|su|env|command` (com um único parser de flags compartilhado — elimina a divergência `-p/--login` vs `-C/-D` do §2.1.7), de `sh|bash|zsh… -c <word>` (a word é o **argumento literal do `-c` na AST** — não "join de tokens"), e de interpretadores `-c/-e/-E/-r/--eval` **e** heredoc-stdin (fecha §2.1.2: `su -c "rm -rf /"` é `deny`, não `ask`).
6. **Depth-limit → conservadorismo**: o limite de recursão (ex.: 8) não retorna `nil`/`allow`; retorna `ErrTooDeep`, tratado como não-compreendido → `force_ask`. Inversão explícita do fail-open do §2.5.3.

`ParsedCommand` legado (flags de pipe/redirect/background) vira subproduto da AST: `Pipeline != nil`, `Redirects`, `Stmt.Background`.

### 3.2 Resolução de caminhos — `pkg/pathx`

API única e obrigatória para **todas** as comparações (vitais E governança — unificando os dois pesos e duas medidas do Python):

```
Resolve(target, cwd) → (absoluto string, kind: Resolved|SymlinkAmbiguous|Unresolved, err)
```

Passos: `filepath.Expand` controlado (somente `$HOME`/`~`, a partir do HOME do processo — nunca `replace` cego) → `filepath.Join(cwd, …)` se relativo → `filepath.Clean` → **`filepath.EvalSymlinks` no ancestral existente mais profundo** (o alvo pode não existir ainda — `rm` de path inexistente, `>` de arquivo novo: resolve-se o diretório pai real e re-anexa o último componente, mesma estratégia correta do `_canon_path`, porém agora **também para vitais**) → teste de pertencimento **segment-aware** com `filepath.Rel` (proíbido prefix-string matching; fecha `/etc` vs `/etcfoo`).

Regras adicionais:
- O `cwd` **relatado pelo payload** passa por `EvalSymlinks` antes de servir de base (fecha §2.3.4).
- `EvalSymlinks` retornando `ELOOP`/`ENAMETOOLONG` ⇒ `SymlinkAmbiguous` ⇒ `force_ask` (nunca fallback léxico silencioso — §2.3.5).
- Vitals e governance roots são carregados **já resolvidos** uma única vez por execução (`realpath` das raízes no boot do processo, cacheado em memória local).
- `TargetFile` de ferramentas de escrita: mesma API + política de raízes (cwd, `~/projects`, `/tmp` mantidos por compatibilidade, mas `/tmp` com ressalva documentada).

### 3.3 Cache nativo — `pkg/cache`

Diretório por spec: **`/tmp/antigravity-gate-cache-<uid>`**, `0700`, dono = uid efetivo.

- **Criação segura**: `os.Mkdir(dir, 0700)` com verificação pós-criação via `syscall.Fstat`/`Lstat` de **dono e modo** (e `O_NOFOLLOW` ao abrir qualquer componente em `/tmp`); se um diretório pré-existente não pertence ao uid ou não é `0700`, o cache é **desabilitado para esta execução** (o gate segue sem cache; NUNCA se tenta "consertar" caminho de terceiro). Umask não é confiável: o modo é sempre forçado por `Mkdir`/`Chmod` atômicos de criação.
- **Chave**: `sha256(version || normalized-command || cwd-resolvido || LANG || LC_ALL || umask-do-host?)` — a normalização é a reconstrução canônica da AST (não o texto cru), então `lscpu` e ` lscpu  ` colidem (melhoria sobre o Python). Um salt de **versão do formato** permite invalidação global no upgrade.
- **Arquivo por chave**: `<hash>.out` + `<hash>.lock` (lock separado do dado, para não precisar lock em cima do inode sendo renomeado).
- **Leitura (HIT)**: `open(lockfile)` → `syscall.Flock(fd, LOCK_SH)` → `fstat`/leitura do header interno (`magic|createdAtMono|ttl|contentHash`) → valida TTL contra **relógio do arquivo + relógio do processo** e valida `sha256` do conteúdo → `LOCK_UN`. TTL medido por *timestamp no corpo*, não `mtime` (fecha o refresh-por-`touch` do §2.2.4 e a double-stat do §2.2.4). Arquivo sem magic/assinatura ⇒ MISS silencioso.
- **Escrita (MISS)**: o **wrap injetado** deixa de ser `tee cache` (escrita não atômica e destrutiva em concorrência) e passa a ser o script de duas fases gerado pelo próprio gate: `( cmd ) > cache.<pid>.tmp && mv -f cache.<pid>.tmp cache` — ou, mais limpo, um subcomando do próprio binário (`governance-gate cache-write --key … --ttl …` lendo stdin da pipe) que faz `flock LOCK_EX` + write em tmp + `fsync` + **`os.Rename`** atômico. Recomenda-se a segunda opção: elimina `tee` do ataque-superfície e o nome temporatório fica controlado pelo Go (0600, `O_EXCL`).
- O wrap de leitura no HIT continua `cat <arquivo>` (path entre aspas via `strconv.Quote` no estilo POSIX-`quote` do próprio shlex-go), mas o gate só injeta caminhos dentro do próprio diretório de cache revalidado com `EvalSymlinks` (equivalente funcional do `_under(realpath)` legado).

### 3.4 Estado de rejeições — `pkg/state`

- Mesmo diretório-raiz do cache (`/tmp/antigravity-gate-cache-<uid>`), arquivo `rejection.json` + `rejection.lock`.
- **Read-modify-write inteiro sob `flock(LOCK_EX)`** — a única forma de eliminar os lost updates do §2.2.2. Sequência: lock → read → validate (schema estrito `struct { Count int; LastReject int64; LastCmdHash string; Schema int }`) → mutar → write tmp + fsync → `os.Rename` → unlock. `os.Rename` sobre o caminho canônico torna **impossível** um leitor ver JSON truncado (fecha §2.2.1, os 25 reads corrompidos da demonstração).
- **Falha de estado ⇒ conservadorismo, não fresh**: se o arquivo existe mas está ilegível/corrompido, `count` é tratado como **≥ 1 suspeito** (não zera) e um `audit.log` registra `state_corrupt`; a Regra 3X continua funcionando. O `except: return fresh` do Python é a antítese exata que o port deve abolir.
- TTL de inatividade (24 h) avaliado no load sob o lock; reset por aprovação é uma operação `count=0` dentro da mesma seção crítica (sem `unlink` TOCTOU).
- Contador é **global por uid** (fiel ao comportamento atual do produto). A arquitetura deixa o *keying* por sessão como melhoria futura trivial (`sessions/<sessionKey>.json`) — decisão de produto adiada, não omissão.

### 3.5 Fail-closed em Go — esqueleto do `cmd`

```
main():
    defer emit-or-force-ask()      // guardado ANTES de qualquer trabalho
    payload, err := readStdin(rlimit 1 MiB, deadline 2 s)
    decision := audit(payload)     // puro, sem I/O de saída
    flush(decision)

guarda:
    func recover(): se panic != nil → substitui resultado pendente por
                    force_ask("[gate] erro interno — confirmação humana")
```

Invariantes:
1. **`out()` é terminal e única porta de stdout** — um `sync.Once` garante exatamente um documento JSON emitido, mesmo no caminho de panic (em Go, `os.Stdout` é byte-stream: o problema de encoding do §2.5.1 não existe; ainda assim o marshaling usa `ensure_ascii`-equivalente seguro — `encoding/json` por padrão já escapa `<`,`>`,`&` e mantém saída válida em qualquer locale).
2. **Ausência de resultado ⇒ force_ask**: a estrutura de controle usa um tipo `verdict` com valor zero = `force_ask` (não `"allow"`), para que qualquer `return` esquecido no switch de regras não approva. O default da função de auditoria é o mesmo por semântica de tipo.
3. **Deadline cooperativo**: um `context.WithTimeout(ctx, 3s)` amarra parse, cache, estado; timeout interno ⇒ `force_ask` (bem antes dos 15 s do host). O gate Go tem folga de ~40× no orçamento.
4. **Re-audição obrigatória de overwrite**: o tipo `Emit` do §1.3 só aceita `Overwrite(cmd)` construído por `Revalidated(newCmd) (Verdict, Overwrite)` — a função roda o avaliador completo sobre o comando injetado e **recusa a construção** se o verdict não for aprovativo (compilador não permite emitir overwrite sem ter passado por ali — o análogo em Go de tornar estado inválido inexistenciável).
5. **Não-compreendido ⇒ conservador**: `incompreendido=true` (parse falhou, profundidade excessiva, `SymlinkAmbiguous`, ferramenta fora dos dois conjuntos conhecidos sem CommandLine) só pode resultar em `force_ask` — nunca `allow`/`auto_approve` (generaliza o fail-closed de schema v4.4.0 para o fail-closed de *análise*).

### 3.6 Estratégias por subsistema (mapeamento 1:1 com o Python)

| Subsistema Python | Implementação Go | Observação de port |
|---|---|---|
| `parse_command` + `_shell_split_commands` + `_regex_surface` | AST walk do `pkg/shparse` | a "superfície sem strings" morre: a AST já distingue literal de código executável — `git commit -m "rm -rf /"` é `Lit("rm -rf /")` dentro de uma `Word`, nunca um `CallExpr` |
| 14 regexes `*_PATTERN` | classificadores de nós + tabelas de verbos/binários | regras de energia/serviço/disco viram `match` por *primeira palavra literal* da AST — sem `_BOUNDARY`, sem falsos positivos de `echo su` |
| `VITAL_*` / `_is_vital_path` / `_under` | `pkg/pathx` segment-aware + listas em `policy.go` (embedded via `go:embed`) | tabela de vitais versionada junto com políticas; teste de pertencimento por `filepath.Rel` |
| RULE-10 | `pkg/state` com flock+rename | §3.4 |
| Cache | `pkg/cache` | §3.3 |
| Compressor | `pkg/compress` — regra só dispara sobre `CallExpr` cujo binário **é** o comando (fecha `startswith` de §2.1.10); guardas (`-f`, `-n N`) lidas do argv da AST | overwrite re-auditado (§3.5.4) |
| `safe_cache_wrap` | `pkg/cache.RenderWrap` produzindo o wrapper canônico com quoting do próprio Go | — |
| `audit_command` | `pkg/evaluator` — cadeia ordenada de `Rule{ID, Classifica(ast) Verdict}` com precedência explícita `deny > force_ask > ask > allow/auto_approve` | ordens de §1.2 preservadas; RULE-01 (monitors) **excluída** por escopo |
| `audit_log` | `pkg/audit` — JSONL com `O_APPEND`, rotação por tamanho no boot (legado não roda) | hash `sha256(cwd+cmd)[:16]` mantido |
| Taxonomia `READ_ONLY_TOOLS`/`WRITE_TOOLS` | mapa em `contract.go` + fail-closed para desconhecidas | conjunto revisitável por PR |

### 3.7 Testes e robustez contínua

- **Table-driven unit tests** por pacote: `shparse` (entrada→nós), `pathx` (traversal/symlink/ELOOP), `state` (concorrência: N goroutines + processos, invariante `count` exato), `cache` (TTL, atomicity, chave por locale), `evaluator` (todo caso da suíte Python vira um `case{cmd, want}` — port direto).
- **Testes de integração stdin/stdout**: `os/exec` sobre o binário compilado no `TestMain`, payload por pipe, asserts no JSON — o contrato do host é testado de ponta a ponta em ~2 ms por caso (vs ~40 ms do Python).
- **Fuzzing nativo**: `go test -fuzz FuzzParse` (mvdan/sh é parser alvo de fuzz corpus público) e fuzz do avaliador completo (payload arbitrário ⇒ invariante: sempre JSON válido, sempre `decision` ∈ domínio, nunca panic escapado).
- **`-race`** em toda suíte (detecta uso de estado compartilhado no daemon-less modelo por-process).
- **Golden tests** dos wrappers injetados (compressor/cache) para travar o contrato byte-a-byte contra regressões de quoting.

---

## 4. Estratégia de Transição e Eliminação Total do Python

### 4.1 Novo `install.sh` (Go puro, sem scripts auxiliares)

Fases (mesma numeração de 5 passos, sem `command -v python3`):

1. **Pré-requisito**: `go >= 1.22` no build host (documentado; não baixar toolchain silenciosamente). Sem `python3` em lugar algum.
2. **Build estático** a partir do repo: `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o build/governance-gate ./cmd/governance-gate` (stripped, sem símbolos, sem informação de build path; resultado único ~3–5 MB, zero runtime deps no alvo).
3. **Instalação atômica**: binário copiado para `$HOME/.gemini/config/plugins/bash-sudo-agents/hooks/governance-gate` via **tmp + rename** (nunca escrever sobre o binário em execução), `chown` implícito, `chmod 0755`; políticas `chmod 0444`.
4. **Registro do hook por template puro**: o `plugin/hooks.json` versionado passa a trazer o comando literal absoluto `"$TARGET/hooks/governance-gate"` resolvido com `sed` (placeholder `__GATE_PATH__` continua, mas a substituição deixa de depender do `python3 - <<'PY'` heredoc do instalador — é uma única linha `sed "s|__GATE_PATH__|$GATE_ABS|"` + `jq` **opcional**; recomenda-se gerar o JSON final por um `governance-gate render-hooks` subcomando do próprio binário, eliminando até o `sed`/`jq`).
5. **Smoke test sem interpretador**: `printf '{"toolCall":{"name":"run_command","args":{"CommandLine":"lscpu"}}}' | "$GATE_ABS"` e verificação `grep '"decision"'` (idêntico ao atual, agora apontado para o binário). Teste adicional de fail-closed: stdin vazio ⇒ `force_ask`.
6. **Blindagem**: `chmod 0444` dos arquivos de política/hook; binário `0755` + diretório `0755` root-owned pelo usuário. `chattr +i` opcional se disponível (documentado, não obrigatório).

### 4.2 Reimaginação da suíte de testes (pytest → `go test`)

- `tests/test_governance_gate.py` (1.205 linhas, 21 classes) → pacotes `_test.go` espelhados: `TestCacheCommandInjection` → `pkg/cache/wrap_test.go`; `TestPathTraversal` → `pkg/pathx/resolve_test.go`; `TestPrivilegeDetection`/`TestDestructiveHardening`/`TestVitalMutation`/`TestInlineInterpreter`/`TestV440HardeningAndAntiFatigue`/`TestV450Fixes` → `pkg/evaluator/rules_test.go` (table-driven, um case = um `cmd/want/why`); `TestRejectionLimit`/`TestRejectionState` → `pkg/state/state_test.go` (+ novo teste de concorrência real, inexistente em Python); `TestIntegrationSubprocess` → `cmd/governance-gate/integration_test.go`.
- `tests/verify_fixes.py` (script standalone de 90 checks) → **golden corpus**: `testdata/cases.jsonl` consumido por um único `TestGoldenCorpus` de integração (executa o binário para cada linha, compara decisão e — quando specified — o overwrite injetado). Um arquivo de dados, não um programa; fácil de adicionar casos em PRs de incidente de segurança.
- Casos legados de `monitors.lua` (TestMonitorRule e afins) **não são portados** (saíram do escopo); o `MONITOR_PATTERN`, `_monitor_write_intent` e `READ_ONLY_BINS` do gate morrem com o Python.
- A classe `TestPythonCompatibility` (PEP 563 etc.) é substituída por um `go vet` + build matrix 386/amd64/arm64 no CI local.
- Meta de paridade: nenhum caso dos 90 checks de `verify_fixes.py` pode perder-se no port — o corpus golden é a checklist de aceite da migração, mais os novos casos dos bypasses aqui descobertos (§2.1.2 `su -c`, §2.1.11 `1>/etc`, §2.3.1 symlink-vital, §2.5.1 encoding-fail-open, §2.2 concorrência), cada um entrando como teste **escrever-primeiro** (TDD de regressão de segurança).

### 4.3 Erradicação do Python (checklist de exclusão)

```
# código-fonte e artefatos
rm plugin/hooks/governance-gate.py
rm -r plugin/hooks/__pycache__                      # governance-gate.cpython-314.pyc
rm tests/test_governance_gate.py tests/verify_fixes.py
rm -r tests/__pycache__                             # incl. *.pytest-9.1.1.pyc
rm -r .pytest_cache                                 # CACHEDIR.TAG, v/, README
# instalados fora do repo (também no host ~/.gemini/config/...):
rm "$HOME/.gemini/config/plugins/bash-sudo-agents/hooks/governance-gate.py"
rm -r "$HOME/.gemini/config/plugins/bash-sudo-agents/hooks/__pycache__" 2>/dev/null

# references textuais a purgar
install.sh      → remover blocos `command -v python3`, version-check, heredoc `python3 - <<'PY'`, smoke em python3
plugin.json     → descrição: "governance-gate.py" vira "governance-gate (Go binary)"
security/*.json → campo "description": trocar "motor Python" / "governance-gate.py"
README.md / CHANGELOG.md → bump v5.0.0, seção "Runtime: Go 1.22+, binário estático"
.gitignore      → adicionar build/, *.test, cob; remover regras de __pycache__/.pytest_cache (órfãs)

# estado de runtime legado no host (após primeira execução do Go novo)
rm -rf "$HOME/.cache/antigravity/bash_agents"       # substituído por /tmp/antigravity-gate-cache-<uid>
# (preservar audit.log movendo-o antes para o novo diretório — histórico de auditoria não se destrói)

# verificação final (gate de aceite)
find . -name '*.py' -o -name '__pycache__' -o -name '.pytest_cache' | grep . && exit 1
! grep -rn "python3\|pytest\|__pycache__" install.sh plugin/ security/ README.md
go vet ./... && go test -race ./... && ./install.sh
```

Ordem de transição segura: (1) corpus golden + falhantes novos escritos em Go contra o comportamento **esperado** (não o atual); (2) implementação por pacote; (3) dual-run em dev — mesmo payload no `governance-gate.py` e no binário Go, diff das decisões; divergências **só** aceitáveis quando justificadas por bug corrigido (lista do §2); (4) install.sh novo → flip do hook; (5) remoção física do Python (checklist acima) + commit `chore(runtime): expurgar Python — v5.0.0 Go nativo`.

---

## Apêndice A — Evidências empíricas coletadas nesta análise

| # | Experimento | Resultado |
|---|---|---|
| A1 | Latência: 3× execução completa do gate (payload `lscpu`), Python 3.14.7 | 0,110 s wall ≈ **37 ms/chamada** (fork+interp+audit) |
| A2 | 24 instâncias concorrentes de `deny` no mesmo HOME + leitor do `rejection_state.json` | **25 leituras com JSON corrompido/ilegível** durante as escritas; janela de truncamento confirmada (→ §2.2.1: `except → fresh → contador zera = escalada 3X falha aberta`) |
| A3 | Contador final com 24 processos efetivamente serializados pelo scheduler | preservado (12/12, 24/24) — a perda de update é probabilística; a **janela de corrupção de leitura é reprodutível** e basta |
| A4 | Escalação 3X sob `LC_ALL=C` sem `LANG` | sobreviveu (emoji impresso íntegro) — PEP 540 coação em C locale; **locale `*.iso885915` presentes no sistema mantêm o vetor do §2.5.1 vivo para non-C/non-UTF8** |

## Apendice B — Mapa de arquivos do repositório

| Arquivo | Destino |
|---|---|
| `plugin/hooks/governance-gate.py` | substituído por `cmd/governance-gate/main.go` + `pkg/*` |
| `plugin/hooks.json` | comando do hook → binário absoluto (sem `python3`) |
| `install.sh` | fase de build Go + registro por `render-hooks`/`sed` (sem heredoc Python) |
| `tests/*.py`, `.pytest_cache/`, `__pycache__/` | excluídos; substituídos por `*_test.go` + `testdata/cases.jsonl` |
| `security/*.json` | mantidos (dados de política), texto rebatizado; carregáveis por `go:embed`/runtime |
| `plugin/agents`, `skills`, `rules`, `plugin.json` | mantidos (Markdown), apenas referências nominais atualizadas |
