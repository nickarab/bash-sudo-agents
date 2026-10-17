# Changelog

Todo o histórico relevante do **Antigravity Linux Governance**. Formato baseado em
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/).

## [5.0.0] - 2026-10-17

**Migração total do motor de governança para Go nativo.** O runtime Python
(`plugin/hooks/governance-gate.py`, 1.871 linhas) foi substituído por um binário
estático (`cmd/governance-gate` + `pkg/*`), sem Python no caminho crítico.

### Adicionado

- **Parser de shell por AST** (`pkg/shparse`, `mvdan.cc/sh/v3/syntax`): as
  detecções operam sobre nós semânticos, não sobre regex de texto.
- **`pkg/pathx`**: API única de resolução de caminhos (vitais e governança),
  segment-aware (`filepath.Rel`), com `EvalSymlinks` do ancestral existente e
  `SymlinkAmbiguous` (ELOOP) tratado como incerteza.
- **`pkg/state`**: contador 3X serializado por `flock` + `rename` atômico; estado
  corrompido é tratado como suspeito (≥1), nunca zerado.
- **`pkg/cache`**: cache em `/tmp/antigravity-gate-cache-<uid>` (0700), escrita
  atômica via o subcomando `governance-gate cache-write` (fim do `tee`),
  validação de TTL no corpo e `sha256` do conteúdo.
- **Subcomandos** `cache-write`, `render-hooks` (gera o `hooks.json` sem
  `sed`/`jq`/Python) e `version`.
- **Corpus golden** `cmd/governance-gate/testdata/cases.jsonl` + suíte
  table-driven (`pkg/evaluator/rules_test.go`) e testes por pacote.
- **Guarda de pânico** (`recover`) e deadline cooperativo: qualquer falha interna
  vira `force_ask`.

### Corrigido (bypasses e falhas confirmados na análise)

- **`su -c "rm -rf /"`** e demais `-c` atrás de env/variável agora são recursados
  (`deny`, não `ask`).
- **Redirecionamento com fd explícito** (`1>/etc/fstab`, `2>/etc/x`) agora é
  vetado — o regex legado os ignorava.
- **Symlink para caminho vital** (`ln -s /etc x && rm -rf x`) agora é resolvido e
  vetado.
- **Heredoc de interpretador** (`python3 - <<'EOF' ... rm -rf /`) é analisado.
- **Recursão profunda** (`bash -c "bash -c ..."`) satura em `force_ask` em vez de
  `allow` silencioso (fail-closed de análise).
- **Concorrência**: eliminados os `lost update` e as leituras de JSON truncado do
  contador 3X e do cache (flock + rename).
- **Fail-open de encoding**: stdout é byte-stream; o alerta de escalação 3X não
  pode mais morrer em locale non-UTF8.
- **Falsos positivos de prefixo** do compressor (`journalctl_evil`,
  `git loganything`) eliminados.
- **`$'...'` (ANSI-C quoting)** é decodificado antes da auditoria.

### Alterado

- **RULE-01 (monitores)** foi **retirada do portfólio do motor de runtime**:
  permanece como diretriz constitucional, mas o hook não emite mais `force_ask`
  para edição de `monitors.lua`.
- Taxonomia preservada: `auto_approve` (comandos seguros/cache/compressão),
  `ask` (elevação rotineira com *Always Allow*), `force_ask` (disco, energia,
  governança, `$VAR` não resolvido), `deny` (destruição e governança).
- Estado de runtime migrado de `~/.cache/antigravity/bash_agents` para
  `/tmp/antigravity-gate-cache-<uid>`; `audit.log` continua em JSONL.

### Removido

- `plugin/hooks/governance-gate.py`, `tests/test_governance_gate.py`,
  `tests/verify_fixes.py`, `.pytest_cache/` e `__pycache__/`.
- Blocos `python3`/version-check/heredoc do `install.sh`.

### Testes

- `go vet ./...` limpo; `go test ./...` e `go test -race ./...` verdes.
- Meta de paridade: todo o corpus do `verify_fixes.py`/`pytest` v4.5.0 foi portado
  para `rules_test.go` + `testdata/cases.jsonl`, mais os novos casos de regressão
  dos bypasses acima.

## [4.5.0] - 2026-10-16

Correção dos seis problemas identificados na auditoria de runtime. Foco em
**entregar a promessa anti-fadiga** e **fechar vetores de bypass confirmados**.

### Corrigido

- **P1 — `allow` não auto-aprovava (causa raiz de "pedir confirmação em todo comando").**
  Conforme a documentação oficial do `PreToolUse` do Antigravity, `allow` apenas
  *delega à política padrão do host* (que ainda prompta `run_command`); quem pula o
  card é `auto_approve`. Agora:
  - comandos auditados e seguros, cache-hit, cache-write e auto-compressão emitem
    **`auto_approve`**;
  - `allow` fica reservado às ferramentas de **escrita/orquestração** (review/diff
    nativo do host);
  - ferramentas de **leitura** sem `CommandLine` emitem `auto_approve`;
  - `NON_COMMAND_TOOLS` foi dividida em `READ_ONLY_TOOLS` e `WRITE_TOOLS`, cobrindo
    as ferramentas reais do Antigravity (`multi_replace_file_content`,
    `find_by_name`, `generate_image`, `list_permissions`, `ask_permission`).
- **P2 — Destruição via interpretador inline com raiz nua.** `python3 -c "import os;
  os.system('rm -rf /')"` era `allow`. O código passado a `-c`/`-e`/`--eval` agora é
  desquotado e submetido às detecções semânticas do gate + padrão dedicado de remoção
  de raiz/vital (`shutil.rmtree`, `rmSync`, `os.remove`, ...) → **`deny`**.
- **P3 — Auto-proteção burlável por caminho relativo/symlink.** `cd ~/.gemini/config
  && rm hooks.json` era `allow`. A proteção de RULE-11/12 agora é por **caminho
  resolvido**: pseudo-cwd acompanha `cd` na mesma linha, `$HOME` é expandido,
  symlinks são resolvidos (`realpath`) e o alvo é comparado com os diretórios/arquivos
  reais de governança (incluindo `.agents/hooks.json` de cada `workspacePaths`).
  Remoção recursiva de um **ancestral** (ex.: `rm -rf ~/.gemini/config`) também é
  vetada. O `GOV_PATTERN` de substring permanece apenas como fallback.
- **P4 — Bins de mutação vital incompletos.** `sed -i`, `perl -pi`, `tar -x -C <vital>`
  e `rsync <...> <vital>` agora são detectados por `_detect_mutation` (com parsing de
  flags próprio, evitando falsos positivos como `sed -n` e `tar xf` sem `-C`).
- **P5 — Falsos positivos que contrariavam a anti-fadiga.**
  - Alvo com variável não resolvida (`$VAR`) em operação de mutação passa de `deny`
    para **`force_ask`** (deny fica reservado à destruição cujo caminho literal já é
    vital).
  - Truncamento/redirecionamento sob `/var/log/**` (limpeza rotineira de log) passa
    de `deny` para **`ask`**.
- **P6 — Fail-open em stdin vazio.** Payload ausente/vazio passou de `allow` para
  **`force_ask`** (coerente com o fail-closed de payload malformado).

### Endurecimentos adicionais

- `$HOME`/`${HOME}` agora são expandidos na normalização de caminhos.
- `_detect_mutation` passou a ler os alvos de binário do comando **bruto** (shlex),
  capturando `cp x "/etc/fstab"` sem reintroduzir falsos positivos em mensagens de
  commit.
- Cache-hit valida que o arquivo está fisicamente sob `CACHE_DIR` (`realpath`) antes
  de emitir o `overwrite`.
- Mensagens/docstrings atualizadas para refletir a taxonomia nova.

### Testes

- `python3 tests/verify_fixes.py` → **122/122**.
- `pytest tests/test_governance_gate.py -q` → **137/137**.
- Total: **259 verificações** (antes 224).

## [4.4.0] - versões anteriores

- v4.4.x: endurecimento semântico, taxonomia anti-fadiga (`ask`/`force_ask`), RULE-05
  semântica, interpretadores inline e fail-closed de schema.
- v4.3.0: RULE-02 endurecida (-R/--recursive, globs, `find -exec`), RULE-12 (dd/tar/
  rsync/ln), variantes de `sudoedit`.
- v4.2.1: correções C-1/C-2/H-4/H-6 (bypasses de recursão e `systemctl --user`).
