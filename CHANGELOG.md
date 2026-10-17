# Changelog

Todo o histórico relevante do **Antigravity Linux Governance**. Formato baseado em
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/).

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
