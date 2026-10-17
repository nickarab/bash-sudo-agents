#!/usr/bin/env python3
"""
governance-gate.py — Antigravity Linux Governance Engine (v4.4.0)
Arquitetura do Sistema:
  - @agente-bash: Operador de Terminal (LLM)
  - governance-gate.py: Motor de Governança Semântica, Guardrail, Cache e Compressor no Runtime (Hook)
  - @agente-sudo-policy: Gestor Constitucional Legislativo (LLM)
Recursos:
  1. Auditoria e Firewall Constitucional (RULE-01 a RULE-15)
  2. Auto-Compressor Sintático de Tokens (overwrite com blindagem de sintaxe)
  3. Cache Local de Saídas com TTL (diretório 0700, mesma conta de usuário)
  4. Failsafe Universal (Zero Downtime)
  5. Estado de Rejeição Persistente (RULE-10 - 3X com TTL 24h)
  6. Re-validação de Overwrite (comando modificado re-auditado)
  7. Parser semântico com shlex para substituição de regex frágeis
  8. Detecção semântica de destruição (rm/find/shred/dd) com split de shell
  9. RULE-03 (disco/formatação), RULE-05 (permissões, semântica) e RULE-07 (serviços
     críticos + classe de energia: reboot/poweroff/suspend sempre force_ask)
  10. Taxonomia de privilégio anti-fadiga (v4.4.0): elevação rotineira (sudo/doas/
      pkexec/su/run0, pacman/yay/paru -S*, systemctl de sistema) usa decisão "ask",
      que respeita o "Always Allow" nativo do Antigravity. "force_ask" (sempre
      pergunta, ignora grants) fica reservado a disco/formatação, monitores,
      governança e energia. "deny" fica reservado a destruição real.
  11. Fail-closed: payload JSON válido sem `CommandLine` reconhecível e cuja
      ferramenta não é de leitura/escrita conhecida gera "force_ask", nunca "allow".
  12. Blindagem contra falsos positivos de aspas: os padrões de regex operam
      sobre uma "superfície" com strings literais removidas, mas preservando
      substituições de comando ($(...) e crases). `git commit -m "rm -rf /"` deixa
      de ser vetado.
  13. RULE-02 estendida: mutações diretas em caminhos vitais por `mv`, `cp`,
      `install`, `truncate`, `tee`, `ln` e redirecionamentos `>`/`>>` são vetadas.
      Cobre também `bash -c "..."` por recursão.
  14. Escapes via interpretador inline (`python3 -c`, `perl -e`, ...) que
      referenciem caminhos protegidos são retidos (governança -> deny; vital ->
      force_ask).
  15. RULE-10 reescrita: contador de recusas CONSECUTIVAS (qualquer aprovação
      zera a sequência), sem dependência de bucket temporal.
Zero dependências externas (estritamente Python 3.8+ Standard Library).
"""

# Habilita anotações preguiçosas (PEP 563): permite usar PEP 604 (`str | None`)
# e PEP 585 (`list[str]`) em Python 3.8/3.9 sem quebrar no import do módulo.
from __future__ import annotations

import fnmatch
import sys
import json
import os
import re
import shlex
import hashlib
import time
from pathlib import Path
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Caminhos dinâmicos (sem hardcode de usuário)
# ---------------------------------------------------------------------------
HOME = Path.home()
PLUGIN_DIR = HOME / ".gemini" / "config" / "plugins" / "bash-sudo-agents"
SECURITY_DIR = HOME / ".gemini" / "antigravity" / "scratch" / "security"
CACHE_DIR = HOME / ".cache" / "antigravity" / "bash_agents"
REJECTION_STATE_FILE = CACHE_DIR / "rejection_state.json"

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------
REJECTION_TTL_SECONDS = 86400  # 24 horas
REJECTION_LIMIT = 3

# Ferramentas que NÃO carregam `CommandLine`. São consideradas "seguras por
# schema" (o `TargetFile`, quando existe, é auditado normalmente). Qualquer
# ferramenta fora desta lista e sem CommandLine cai em fail-closed (force_ask).
NON_COMMAND_TOOLS = frozenset({
    # Leitura / navegação
    "view_file", "read_file", "list_dir", "list_files", "grep_search",
    "codebase_search", "search_files", "open_file",
    # Escrita / edição (TargetFile auditado)
    "write_to_file", "create_file", "edit_file", "replace_file_content",
    "apply_patch", "delete_file",
    # Conversa / orquestração / rede
    "ask_question", "send_message", "search_web", "read_url_content",
    "manage_task", "schedule", "invoke_subagent", "define_subagent",
    "manage_subagents", "todo_write", "browser_action",
})


# ---------------------------------------------------------------------------
# Utilitários de saída e logging
# ---------------------------------------------------------------------------

def _now_ms() -> int:
    return int(time.time() * 1000)


def out(decision: str, reason: str = "", overwrite: dict | None = None) -> None:
    """Emite a decisão JSON no stdout e encerra com código 0.

    O contrato exposto ao hook é apenas {decision, reason, overwrite}. Os
    metadados de auditoria estruturada (regra, hash do comando, latência) são
    registrados exclusivamente em `audit.log`, via `audit_log()`.
    """
    res: dict = {"decision": decision}
    if reason:
        res["reason"] = reason
    if overwrite:
        res["overwrite"] = overwrite
    print(json.dumps(res, ensure_ascii=False))
    sys.exit(0)


def audit_log(decision: str, reason: str, rule: str | None, cmd: str,
              cwd: str, latency_ms: int) -> None:
    """Escreve log estruturado em JSON para o arquivo de auditoria."""
    try:
        log_dir = CACHE_DIR
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "audit.log"
        cmd_hash = hashlib.sha256(f"{cwd}:{cmd}".encode("utf-8")).hexdigest()[:16]
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "decision": decision,
            "reason": reason,
            "rule": rule,
            "cmd_hash": cmd_hash,
            "latency_ms": latency_ms,
        }
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass  # Nunca falhar o gate por causa de logging


def _escalation_reason(reason: str, cwd: str) -> str:
    """Monta a notificação de escalação 3X no campo `reason` (respeita o contrato de saída)."""
    return (
        "🛑 [ALERTA DE SEGURANÇA: LIMITE DE RECUSAS ATINGIDO (3/3)] "
        f"{reason} — Contexto: {cwd}. "
        "EXECUÇÃO SUSPENSA. Aguardando intervenção manual do administrador."
    )


# ---------------------------------------------------------------------------
# Estado de rejeição persistente (RULE-10 — Regra 3X, recusas CONSECUTIVAS)
# ---------------------------------------------------------------------------

def _load_rejection_state() -> dict:
    """Carrega {count, last_reject, last_cmd}, expirando por TTL (24h)."""
    fresh = {"count": 0, "last_reject": 0, "last_cmd": ""}
    try:
        if REJECTION_STATE_FILE.exists():
            data = json.loads(REJECTION_STATE_FILE.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return fresh
            if time.time() - data.get("last_reject", 0) >= REJECTION_TTL_SECONDS:
                return fresh
            return data
    except Exception:
        pass
    return fresh


def _save_rejection_state(state: dict) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        REJECTION_STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        os.chmod(REJECTION_STATE_FILE, 0o600)
    except Exception:
        pass


def _clear_rejection_state() -> None:
    """Zera o contador de recusas consecutivas (usado em aprovações)."""
    try:
        if REJECTION_STATE_FILE.exists():
            REJECTION_STATE_FILE.unlink()
    except Exception:
        pass


def _record_decision(decision: str, cmd: str) -> int:
    """Atualiza o contador de recusas CONSECUTIVAS (RULE-10).

    Semântica: apenas `deny` incrementa o contador. Qualquer outra decisão
    (`allow`, `ask`, `force_ask`) interrompe a sequência e zera o contador —
    ou seja, uma aprovação (ou um comando seguro) reseta a Regra 3X.

    Retorna o número de recusas consecutivas após a atualização.
    """
    state = _load_rejection_state()
    if decision == "deny":
        state["count"] = int(state.get("count", 0)) + 1
        state["last_reject"] = time.time()
        state["last_cmd"] = re.sub(r"\s+", " ", (cmd or "").strip())[:200]
        _save_rejection_state(state)
        return int(state["count"])
    if state.get("count"):
        _clear_rejection_state()
    return 0


def _get_rejection_count() -> int:
    """Quantidade de recusas consecutivas atualmente registradas."""
    return int(_load_rejection_state().get("count", 0))


# ---------------------------------------------------------------------------
# Parser semântico com shlex (Seções 5.1 e 8.3)
# ---------------------------------------------------------------------------

@dataclass
class ParsedCommand:
    argv: list[str]
    raw_cmd: str
    has_pipe: bool
    has_redirect: bool
    redirect_ops: list[str]
    background: bool
    sudo_like: bool
    privilege_type: str | None
    target_bin: str | None


def _safe_split(cmd: str) -> list[str]:
    """shlex.split tolerante: nunca lança exceção para aspas desbalanceadas."""
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return cmd.split()


def parse_command(cmd: str) -> ParsedCommand:
    """
    Analisa semanticamente um comando shell usando shlex.
    Detecta: pipes, redirecionamentos, background, privilégios sudo-like,
    e o binário alvo real.
    """
    has_pipe = "|" in cmd
    has_redirect = bool(re.search(r'[<>]', cmd))
    redirect_ops = re.findall(r'[<>]', cmd)
    background = cmd.strip().endswith("&")

    argv = _safe_split(cmd)

    # Detecta comandos de elevação de privilégio
    privilege_type = None
    sudo_like = False
    target_bin = argv[0] if argv else None

    if argv:
        first = argv[0]
        # sudoedit é sudo em modo de edição (edita arquivos como root)
        if first == "sudoedit":
            sudo_like = True
            privilege_type = "sudoedit"
            target_bin = "sudoedit"
        # Comandos diretos de privilégio
        elif first in {"sudo", "doas", "pkexec", "su", "run0"}:
            sudo_like = True
            privilege_type = first
            if first == "sudo" and ("-e" in argv[1:] or "--edit" in argv[1:]):
                privilege_type = "sudoedit"
            # O comando real vem após as flags do sudo
            # Ex: sudo -u user cmd -> cmd
            remaining = argv[1:]
            # Flags que consomem um valor vs. flags booleanas
            value_flags = {"-u", "--user", "-g", "--group", "-h", "--host", "-p", "--login"}
            bool_flags = {"-i", "-s", "-E", "-n", "-H", "-b", "-e", "-k", "-v", "-V"}
            i = 0
            while i < len(remaining):
                tok = remaining[i]
                if tok == "--":
                    i += 1
                    break
                if tok in value_flags:
                    i += 1  # pular flag
                    if i < len(remaining) and not remaining[i].startswith("-"):
                        i += 1  # pular valor da flag
                elif tok in bool_flags or tok.startswith("-"):
                    i += 1
                else:
                    target_bin = remaining[i]
                    break
            else:
                target_bin = None
        elif first in {"yay", "paru", "pacman"}:
            # Qualquer flag iniciada por -S exceto busca (-Ss) e info (-Si):
            # -S, -Sy, -Syu, -Sw... todos operam no sistema com elevação.
            for tok in argv[1:]:
                if re.match(r"^-S(?![si])", tok):
                    sudo_like = True
                    privilege_type = "package_install"
                    target_bin = first
                    break
        elif first == "systemctl":
            # Verbos de mutação em qualquer posição; --user nunca é privilégio de sistema.
            verbs = {"start", "stop", "restart", "enable", "disable", "mask", "unmask"}
            if "--user" not in argv[1:] and any(t in verbs for t in argv[1:]):
                sudo_like = True
                privilege_type = "systemctl"
                target_bin = "systemctl"

    return ParsedCommand(
        argv=argv,
        raw_cmd=cmd,
        has_pipe=has_pipe,
        has_redirect=has_redirect,
        redirect_ops=redirect_ops,
        background=background,
        sudo_like=sudo_like,
        privilege_type=privilege_type,
        target_bin=target_bin,
    )


# ---------------------------------------------------------------------------
# Split de shell e detecção semântica de destruição
# ---------------------------------------------------------------------------

def _shell_split_commands(cmd: str) -> list[str]:
    """
    Divide uma linha de comando shell em comandos individuais, separando por
    operadores de controle (; && || | &) e novas linhas, respeitando aspas e
    escapes. Sub-shells $(...) e crases são cobertos pelo fallback de regex.
    """
    segments: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(cmd)
    quote: str | None = None
    while i < n:
        ch = cmd[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            elif ch == "\\" and quote == '"' and i + 1 < n:
                i += 1
                buf.append(cmd[i])
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "\\":
            buf.append(ch)
            if i + 1 < n:
                i += 1
                buf.append(cmd[i])
            i += 1
            continue
        if ch == "\n":
            segments.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        if ch == ";":
            segments.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        if ch == "|":
            if i + 1 < n and cmd[i + 1] == "|":
                segments.append("".join(buf).strip())
                buf = []
                i += 2
                continue
            segments.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        if ch == "&":
            if i + 1 < n and cmd[i + 1] == "&":
                segments.append("".join(buf).strip())
                buf = []
                i += 2
                continue
            segments.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    segments.append("".join(buf).strip())
    return [s for s in segments if s]


# ---------------------------------------------------------------------------
# Superfície de casamento para regex (fim dos falsos positivos por aspas)
# ---------------------------------------------------------------------------

def _read_substitution(cmd: str, start: int) -> tuple[str, int]:
    """Lê `$( ... )` balanceado a partir de `start` (cmd[start] == '$').

    Retorna (trecho, próximo_índice). Nunca lança exceção.
    """
    depth = 0
    i = start + 1  # aponta para '('
    n = len(cmd)
    quote: str | None = None
    while i < n:
        ch = cmd[i]
        if quote:
            if ch == quote:
                quote = None
            elif ch == "\\" and i + 1 < n:
                i += 1
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return cmd[start:i + 1], i + 1
        i += 1
    return cmd[start:], n


def _regex_surface(cmd: str) -> str:
    """Devolve a parte do comando relevante para execução de regex.

    Remove strings literais entre aspas (que o shell não interpreta como
    sintaxe), preservando substituições de comando `$(...)` e crases, que são
    efetivamente avaliadas pelo shell. Assim `git commit -m "rm -rf /"` não é
    mais vetado, mas `echo "$(rm -rf /)"` continua sendo.
    """
    out: list[str] = []
    i = 0
    n = len(cmd)
    quote: str | None = None
    while i < n:
        ch = cmd[i]
        if quote == "'":
            if ch == "'":
                quote = None
            i += 1
            continue
        if quote == '"':
            if ch == '"':
                quote = None
                i += 1
                continue
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == "`":
                j = cmd.find("`", i + 1)
                if j != -1:
                    out.append(cmd[i:j + 1])
                    i = j + 1
                    continue
                i += 1
                continue
            if ch == "$" and i + 1 < n and cmd[i + 1] == "(":
                sub, i = _read_substitution(cmd, i)
                out.append(sub)
                continue
            i += 1
            continue
        # Fora de aspas: preserva tudo (inclui $(...) e crases já literais).
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(cmd[i:i + 2])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _unwrap_privilege_prefix(argv: list[str]) -> list[str]:
    """
    Remove prefixos de elevação (sudo/doas/pkexec/run0/command/env) e suas
    flags, retornando o argv a partir do binário real.
    """
    skip_with_value = {"-u", "--user", "-g", "--group", "-h", "--host", "-p", "-C", "-D"}
    i = 0
    n = len(argv)
    while i < n:
        tok = argv[i]
        if tok in {"sudo", "doas", "pkexec", "run0", "command", "busybox"}:
            i += 1
            continue
        if tok == "env":
            i += 1
            while i < n and "=" in argv[i] and not argv[i].startswith("-"):
                i += 1
            continue
        if tok == "--":
            i += 1
            break
        if tok in skip_with_value:
            i += 1
            if i < n and not argv[i].startswith("-"):
                i += 1
            continue
        if tok.startswith("-") and tok != "-":
            i += 1
            continue
        break
    return argv[i:]


# Diretórios vitais do sistema (RULE-02). A raiz do home (~) também é tratada
# como vital em `_VITAL_GLOB_TARGETS`/`_is_vital_path`, não subdiretórios do usuário.
# v4.4.x: inclui root/opt/srv/mnt (dados de sistema, serviços e pontos de montagem).
VITAL_TOP_DIRS = {
    "boot", "etc", "usr", "var", "sys", "proc", "dev", "bin", "sbin",
    "lib", "lib64", "root", "opt", "srv", "mnt",
}

# Arquivos vitais específicos: deletá-los é sempre destrutivo, mesmo sem a flag
# recursiva (RULE-02). A raiz do home também é protegida por "home" em _is_vital_path.
VITAL_FILES = {
    "/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/group",
    "/etc/fstab", "/etc/crypttab", "/etc/sudoers", "/etc/sudoers.d",
    "/etc/hostname", "/etc/hosts", "/etc/resolv.conf",
    "/boot/grub/grub.cfg", "/boot/grub2/grub.cfg",
    "/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
}

# Para casamento de globs na primeira componente, "home" também é tratado como
# vital (a raiz de um home é protegida), evitando bypass tipo /h?me.
_VITAL_GLOB_TARGETS = frozenset(VITAL_TOP_DIRS | {"home"})


def _normalize_path(arg: str, cwd: Path) -> str:
    """Expande ~, torna absoluto relativo ao cwd e normaliza .. (sem exigir existência)."""
    p = Path(arg).expanduser()
    if not p.is_absolute():
        p = cwd / p
    return os.path.normpath(str(p))


def _has_glob(arg: str) -> bool:
    """True se o argumento contém metacaracteres de glob do shell (? [] {} *)."""
    return any(ch in arg for ch in "?[]{}*")


def _path_component_matches_vital(comp: str) -> bool:
    """
    True se a primeira componente do caminho (podendo conter globs) pode casar
    com um diretório vital. Cobre ? [] * via fnmatch e {} via expansão de chaves.
    """
    alts = [comp]
    m = re.match(r'^([^{}]*)\{([^{}]*)\}(.*)$', comp)
    if m:
        prefix, body, suffix = m.groups()
        alts = [prefix + part + suffix for part in body.split(",")]
    for alt in alts:
        for vital in _VITAL_GLOB_TARGETS:
            if fnmatch.fnmatch(vital, alt):
                return True
    return False


def _is_vital_path(arg: str) -> bool:
    """True se o caminho (já normalizado) aponta para a raiz ou um diretório vital."""
    if arg in {"/", "/*"}:
        return True
    if arg.startswith("/"):
        rest = arg.lstrip("/")
        top = rest.split("/", 1)[0]
        if _has_glob(top):
            return _path_component_matches_vital(top)
        if top in VITAL_TOP_DIRS:
            return True
        # /home exatamente ou /home/<usuario> (raiz de um home) é vital;
        # subdiretórios de home (/home/<usuario>/...) não são.
        if top == "home":
            rest2 = rest[len("home"):].lstrip("/")
            if not rest2 or "/" not in rest2:
                return True
        return False
    return False


def _is_recursive_flag(a: str) -> bool:
    """True para flags recursivas de rm: -r, -R, --recursive e combinações (-rf, -fr, -Rf...)."""
    if a == "--recursive":
        return True
    if a.startswith("-") and not a.startswith("--"):
        return "r" in a or "R" in a
    return False


def _rm_is_destructive(args: list[str], cwd: Path) -> bool:
    """rm é destrutivo quando o alvo aponta para caminho/arquivo vital."""
    targets = [a for a in args if not a.startswith("-")]
    if not targets:
        return False
    # Variável não resolvida (pré-bash) em alvo de rm: conservador, veta.
    if any("$" in a for a in targets):
        return True
    recursive = any(_is_recursive_flag(a) for a in args)
    for a in targets:
        norm = _normalize_path(a, cwd)
        # Arquivo vital específico é vetado mesmo sem recursão.
        if norm in VITAL_FILES:
            return True
        # Recursivo: qualquer subárvore de diretório vital é vetada.
        if recursive and _is_vital_path(norm):
            return True
    return False


def _find_is_destructive(args: list[str]) -> bool:
    """find é destrutivo com -delete ou com -exec/-execdir/-ok rodando rm/dd/shred."""
    for i, a in enumerate(args):
        if a == "-delete" or a.startswith("-delete"):
            return True
        if a in {"-exec", "-execdir", "-ok"}:
            if i + 1 < len(args):
                inner = args[i + 1].split("/")[-1]
                if inner in {"rm", "shred", "dd"}:
                    return True
    return False


def _shred_is_destructive(args: list[str], cwd: Path) -> bool:
    """shred só é vetado para dispositivos de bloco (/dev/*) ou caminhos vitais."""
    targets = [a for a in args if not a.startswith("-")]
    if not targets:
        return False
    if any("$" in a for a in targets):
        return True
    for a in targets:
        norm = _normalize_path(a, cwd)
        if norm.startswith("/dev/") or a.startswith("/dev/"):
            return True
        if _is_vital_path(norm):
            return True
    return False


def _dd_is_destructive(args: list[str], cwd: Path) -> bool:
    """dd é destrutivo quando grava (of=) em dispositivo de bloco ou caminho vital."""
    for a in args:
        if a.startswith("of="):
            dest = a[len("of="):]
            if dest.startswith("/dev/"):
                return True
            if _path_is_vital(dest, cwd):
                return True
    return False


# Intérpretes de shell: `bash -c "<cmd>"` é analisado recursivamente.
SHELL_BINS = {"bash", "sh", "dash", "zsh", "ksh", "mksh", "busybox"}
_MAX_RECURSION = 3


def _detect_destructive(cmd: str, cwd: Path, depth: int = 0) -> str | None:
    """
    Detecção semântica de comandos destrutivos (RULE-02).
    Divide a linha em comandos, remove prefixos de privilégio e verifica o
    binário alvo e seus argumentos. Retorna o binário destrutivo ou None.
    A checagem de variáveis não resolvidas ($) é aplicada apenas a comandos
    destrutivos confirmados (rm/find/shred/dd), nunca a comandos inofensivos
    como `echo $PATH`.

    Mutações diretas (`mv`, `cp`, `truncate`, `tee`, `ln`, redirecionamentos)
    são cobertas por `_detect_mutation`. `bash -c "..."` é reanalisado.
    """
    if depth > _MAX_RECURSION:
        return None
    for seg in _shell_split_commands(cmd):
        argv = _unwrap_privilege_prefix(_safe_split(seg))
        if not argv:
            continue
        binary = argv[0].split("/")[-1]
        args = argv[1:]
        # Reanalisa o interior de shells `-c` (escape clássico do parser).
        if binary in SHELL_BINS and "-c" in args:
            inner = " ".join(args[args.index("-c") + 1:])
            if _detect_destructive(inner, cwd, depth + 1) or _detect_mutation(inner, cwd):
                return binary
        if binary == "rm":
            if _rm_is_destructive(args, cwd):
                return "rm"
        elif binary == "find":
            if _find_is_destructive(args):
                return "find"
        elif binary == "shred":
            if _shred_is_destructive(args, cwd):
                return "shred"
        elif binary == "dd":
            if _dd_is_destructive(args, cwd):
                return "dd"
    return None


# ---------------------------------------------------------------------------
# RULE-02 estendida: mutação direta de caminhos vitais
# (mv, cp, install, truncate, tee, ln e redirecionamentos > / >>)
# ---------------------------------------------------------------------------

# Nós de dispositivo benignos: redirecionar saída para eles não é destrutivo.
_REDIRECT_SAFE_DEV = frozenset({
    "/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom",
    "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/tty",
})

_MUTATION_BINS = {"mv", "cp", "install", "truncate", "tee", "ln"}


def _redirect_targets(surface: str) -> list[str]:
    """Alvos de redirecionamento de saída (`>`, `>>`) que criam/truncam arquivos.

    Ignora duplicações de descritor (`2>`, `2>&1`, `>&2`) — o `>` precedido por
    dígito é excluído pelo lookbehind.
    """
    targets: list[str] = []
    for m in re.finditer(r'(?<![0-9])>{1,2}\s*([^\s;&|<>()]+)', surface):
        tok = m.group(1).strip("'\"")
        if tok:
            targets.append(tok)
    return targets


def _path_is_vital(arg: str, cwd: Path) -> bool:
    """True se `arg` aponta para caminho vital (nunca para nós de dispositivo benignos)."""
    if "$" in arg:
        return True  # variável não resolvida: conservador
    norm = _normalize_path(arg, cwd)
    if norm in _REDIRECT_SAFE_DEV:
        return False
    return _is_vital_path(norm)


def _mutation_is_destructive(binary: str, args: list[str], cwd: Path) -> bool:
    operands = [a for a in args if not a.startswith("-")]
    if binary == "mv":
        # mv remove a origem vital (perda real do arquivo original).
        return any(_path_is_vital(a, cwd) for a in operands)
    if binary in {"cp", "install", "tee", "ln"}:
        # Somente o destino importa: ler/symlinkar a partir de caminho vital
        # (backup, `ln -s /usr/bin/x ~/.local/bin/`) é legítimo; sobrescrever
        # um caminho vital não é.
        dest = operands[-1] if operands else ""
        return bool(dest) and _path_is_vital(dest, cwd)
    if binary == "truncate":
        return any(_path_is_vital(a, cwd) for a in operands)
    return False


def _detect_mutation(cmd: str, cwd: Path) -> str | None:
    """Retorna o binário/operador quando há mutação direta de caminho vital."""
    surface = _regex_surface(cmd)
    for target in _redirect_targets(surface):
        if _path_is_vital(target, cwd):
            return "redirect"
    for seg in _shell_split_commands(surface):
        argv = _unwrap_privilege_prefix(_safe_split(seg))
        if not argv:
            continue
        binary = argv[0].split("/")[-1]
        if binary in _MUTATION_BINS and _mutation_is_destructive(binary, argv[1:], cwd):
            return binary
    return None


# ---------------------------------------------------------------------------
# Detecção semântica de abuso de permissões (RULE-05, v4.4.0)
# Substitui o casamento posicional de regex, que era burlado por ordem de
# flags ("chmod 777 -R /etc"), variantes de modo ("a+w") e "--recursive".
# ---------------------------------------------------------------------------

def _is_recursive_perm_flag(a: str) -> bool:
    """True para -R, --recursive e combinações (-Rf, -vR...)."""
    if a == "--recursive":
        return True
    return a.startswith("-") and not a.startswith("--") and "R" in a


_WORLD_WRITABLE_SYMBOLIC = {
    "a+w", "o+w", "go+w", "ugo+w",
    "a=rwx", "a+rwx", "ugo+rwx", "ugo=rwx", "o=rwx", "go=rwx",
}


def _mode_is_world_writable(tok: str) -> bool:
    """True para modos que concedem escrita a 'others' (777, 757, a+w, o=rwx...)."""
    t = tok.lower()
    if t in _WORLD_WRITABLE_SYMBOLIC:
        return True
    if t.isdigit() and len(t) >= 3:
        # Último dígito octal = permissão de "others"; bit 2 = escrita.
        return bool(int(t[-1]) & 2)
    return False


def _looks_like_mode(tok: str) -> bool:
    return tok.isdigit() or "+" in tok or "=" in tok


def _is_system_path_norm(norm: str) -> bool:
    """True se o caminho normalizado é a raiz ou tem topo vital do SO (sem home)."""
    if norm == "/":
        return True
    if norm.startswith("/"):
        top = norm.lstrip("/").split("/", 1)[0]
        return top in VITAL_TOP_DIRS
    return False


def _chmod_is_abusive(args: list[str], cwd: Path) -> bool:
    """chmod abusivo: recursivo + modo world-writable (qualquer alvo) ou
    recursivo com qualquer modo sobre caminho do sistema."""
    if not any(_is_recursive_perm_flag(a) for a in args):
        return False
    targets: list[str] = []
    for a in args:
        if a.startswith("-"):
            continue
        if _mode_is_world_writable(a):
            return True
        if not _looks_like_mode(a):
            targets.append(a)
    for a in targets:
        if "$" in a:
            return True
        if _is_system_path_norm(_normalize_path(a, cwd)):
            return True
    return False


def _chown_is_abusive(args: list[str], cwd: Path) -> bool:
    """chown abusivo: recursivo sobre a raiz ou diretórios vitais do SO."""
    if not any(_is_recursive_perm_flag(a) for a in args):
        return False
    operands = [a for a in args if not a.startswith("-")]
    # operands[0] é o dono (user[:group]); o resto são alvos.
    for a in operands[1:]:
        if "$" in a:
            return True
        if _is_system_path_norm(_normalize_path(a, cwd)):
            return True
    return False


def _detect_perm_abuse(cmd: str, cwd: Path) -> str | None:
    """Retorna 'chmod'/'chown' se algum segmento do comando abusa de permissões."""
    for seg in _shell_split_commands(cmd):
        argv = _unwrap_privilege_prefix(_safe_split(seg))
        if not argv:
            continue
        binary = argv[0].split("/")[-1]
        if binary == "chmod" and _chmod_is_abusive(argv[1:], cwd):
            return "chmod"
        if binary == "chown" and _chown_is_abusive(argv[1:], cwd):
            return "chown"
    return None


# ---------------------------------------------------------------------------
# Intenção de escrita em monitores (RULE-01, v4.4.0)
# Leitura de monitors.lua/monitors.conf é diagnóstico livre (RULE-09); apenas
# edição/escrita retém para confirmação.
# ---------------------------------------------------------------------------

READ_ONLY_BINS = {
    "cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "rg",
    "find", "ls", "ll", "file", "stat", "wc", "strings", "xxd", "od",
    "hexdump", "bat", "diff", "cmp", "sort", "uniq", "tr", "cut", "jq", "awk",
}


def _monitor_write_intent(cmd: str) -> bool:
    """True se o comando implica escrita/edição (não mera leitura)."""
    if WRITE_OPS_PATTERN.search(cmd):
        return True
    for seg in _shell_split_commands(cmd):
        argv = _unwrap_privilege_prefix(_safe_split(seg))
        if not argv:
            continue
        binary = argv[0].split("/")[-1]
        if binary in READ_ONLY_BINS:
            continue
        # Binário desconhecido/editor sobre arquivo de monitor: conservador, retém.
        return True
    return False


# ---------------------------------------------------------------------------
# Detecção de privilégio por segmento (RULE-15, v4.4.0)
# Elimina o falso positivo do regex global ("echo su") e cobre "x; sudo y".
# ---------------------------------------------------------------------------

def _cmd_is_privileged(cmd: str) -> tuple[bool, str | None]:
    """True se algum segmento do comando é uma elevação de privilégio."""
    for seg in _shell_split_commands(cmd):
        p = parse_command(seg)
        if p.sudo_like:
            return True, p.privilege_type
    return False, None


# ---------------------------------------------------------------------------
# Validação segura de comando para cache (Quick Win #1)
# ---------------------------------------------------------------------------

CACHEABLE_BINS = {"lscpu", "uname", "lspci", "lsusb", "pacman", "yay", "paru"}

# Arquivos estáticos permitidos para cache via `cat` (sem reabrir brechas para
# arquivos sensíveis como /etc/passwd ou /etc/shadow).
STATIC_CAT_PATHS = {"/etc/os-release", "/proc/cpuinfo"}

DANGEROUS_ARGS = {
    "-exec", "-delete", "-ok", "-execdir",
    ";", "&", "|", ">", "<", "`",
    "$(", "${", "rm", "dd", "mkfs", "shred",
}


def _is_cacheable(cmd: str) -> bool:
    """Retorna True se o comando pode ser safely wrapado para cache."""
    try:
        argv = shlex.split(cmd, posix=True)
    except ValueError:
        return False
    if not argv:
        return False
    if argv[0] in CACHEABLE_BINS:
        # Rejeitar argumentos perigosos
        for arg in argv[1:]:
            if arg in DANGEROUS_ARGS:
                return False
        return True
    # cat de arquivos estáticos permitidos (somente esses caminhos exatos)
    if argv[0] == "cat" and len(argv) == 2 and argv[1] in STATIC_CAT_PATHS:
        return True
    return False


def safe_cache_wrap(cmd: str, cache_file: Path, pipe_suffix: str | None = None) -> str:
    """
    Wrap seguro de comando para cache.
    Apenas comandos na whitelist CACHEABLE_BINS são wrapados.
    Reconstrução segura com shlex.quote para cada argumento.
    pipe_suffix (ex.: "head -n 25") é embutido DENTRO do sub-shell, para que o
    cache já armazene a saída comprimida (compressor + cache na mesma etapa).
    """
    if not _is_cacheable(cmd):
        return cmd  # Não wrapar — executa direto sem cache

    try:
        argv = shlex.split(cmd, posix=True)
    except ValueError:
        return cmd

    safe_cmd = " ".join(shlex.quote(arg) for arg in argv)
    if pipe_suffix:
        safe_cmd = f"{safe_cmd} | {pipe_suffix}"
    return f"( {safe_cmd} ) | tee {shlex.quote(str(cache_file))}"


# ---------------------------------------------------------------------------
# Sanitização de TargetFile (Quick Win #2)
# ---------------------------------------------------------------------------

def resolve_target_safely(target: str, cwd: Path) -> Path | None:
    """
    Resolve o caminho alvo de forma segura, prevenindo path traversal.
    Retorna None se o caminho estiver fora do escopo permitido.
    """
    if not target:
        return None
    try:
        target_path = (cwd / target).resolve()
        # Raízes permitidas: cwd, HOME/projects, /tmp
        allowed_roots = [cwd.resolve(), (HOME / "projects").resolve(), Path("/tmp").resolve()]
        for root in allowed_roots:
            try:
                target_path.relative_to(root)
                return target_path
            except ValueError:
                continue
        return None  # Fora do escopo
    except (ValueError, RuntimeError, OSError):
        return None


# ---------------------------------------------------------------------------
# Regras de segurança
# ---------------------------------------------------------------------------

# Prefixo de fronteira: início da linha, separador de shell, crase ou $(.
_BOUNDARY = r'(?:^|[;&|\s]|`|\$\()\s*'

# RULE-06: Veto ao sudo_runner legado
SUDO_RUNNER_PATTERN = re.compile(
    r'(^|[;&|`\$\(\)])\s*((sudo|doas|exec|env|bash|sh|source|\.)\s+)?(\S+/)?sudo_runner(\.sh)?(\s|$)'
)

# Terminador de caminho: espaço, separador de shell, parêntese, crase ou fim.
_END = r'(?=[\s;&|()`]|$)'
_VITAL_ALT = "|".join(sorted(VITAL_TOP_DIRS))

# RULE-02: Anti-destruição (fallback rápido para sub-shells que o parser não alcança)
DESTRUCTIVE_PATTERN = re.compile(
    _BOUNDARY +
    r'(?:'
    rf'rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(?:/\*|/(?:{_VITAL_ALT})\b(?:/.*)?|/{_END}|~(?:(?:{_END})|/{_END})|\.\./?(?:{_END}))'
    r'|find\s+[^;&|\n]*\s+(?:-delete|-(?:exec|execdir|ok)\s+rm\b)'
    rf'|shred\b[^;&|\n]*(?:/dev/|/(?:{_VITAL_ALT})\b)'
    r'|dd\s+[^;&|\n]*\bof=/dev/'
    r')'
)

# RULE-03: Operações de disco/formatação — exigem confirmação explícita (force_ask)
DISK_PATTERN = re.compile(
    _BOUNDARY +
    r'(?:mkfs\b|fdisk\b|parted\b|umount\b|wipefs\b|losetup\b'
    r'|cryptsetup\b|sgdisk\b|gdisk\b|cfdisk\b'
    r'|mount\s+(?:-[a-zA-Z]|\S+))'
)

# RULE-05: Preservação de permissões — fallback regex para sub-shells $(...)
# (a detecção primária é semântica: _detect_perm_abuse)
PERM_PATTERN = re.compile(
    _BOUNDARY +
    r'(?:chmod\s+-R\s+(?:0?777|777|a\+rwx|ugo\+rwx|a=rwx)\b'
    rf'|chown\s+-R\s+\S+\s+(?:/|/(?:{_VITAL_ALT})(?:/.*)?))'
)

# RULE-07: Estabilidade de serviços essenciais — veto a derrubar a sessão ativa
# (restart incluído: reiniciar o display manager/compositor também derruba a sessão)
SERVICE_PATTERN = re.compile(
    _BOUNDARY +
    r'(?:systemctl\s+(?:--user\s+)?(?:stop|disable|mask|kill|restart)\s+(?:--user\s+)?(?:sddm|gdm|ly|lightdm|display-manager|getty\S*|hyprland)'
    r'|(?:pkill|killall|kill)\s+-?\w*\s*(?:hyprland|Hyprland|wayland|Xorg|Xwayland|sddm|gdm|sddm-helper|gnome-shell|sway)'
    r'|kill\s+-9\s+1\b)'
)

# RULE-07 (classe de energia/sessão, v4.4.0): desligar, reiniciar ou suspender a
# máquina/sessão NUNCA é operação silenciosa — sempre force_ask (sem cache de grant).
POWER_PATTERN = re.compile(
    _BOUNDARY +
    r'(?:systemctl\s+(?:--\S+\s+)*(?:reboot|poweroff|halt|suspend-then-hibernate|suspend|hibernate|hybrid-sleep|kexec)(?:\s|$)'
    r'|loginctl\s+(?:reboot|poweroff|suspend|hibernate|lock-session|lock-sessions|terminate-user|kill-user)(?:\s|$)'
    r'|(?:shutdown|reboot|poweroff|halt|telinit)(?:\s|$)'
    r'|init\s+[06](?:\s|$))'
)

# RULE-01: Monitores
MONITOR_PATTERN = re.compile(r'monitors\.lua|hyprland/.*monitors?\.conf')

# RULE-15: fallback para elevação escondida em sub-shells $(...) ou crases.
# A detecção primária é semântica por segmento (_cmd_is_privileged).
SUBSHELL_PRIV_PATTERN = re.compile(
    r'\$\([^)]*(?:sudo|doas|pkexec|run0|\bsu\b)[^)]*\)'
    r'|`[^`]*(?:sudo|doas|pkexec|run0|\bsu\b)[^`]*`'
)

# RULE-11 e RULE-12: Proteção da infraestrutura de governança.
# Cobre o plugin, as políticas, o config e TODOS os pontos de registro de hooks
# (global e workspace), para que o próprio gate não possa ser desligado/substituído.
GOV_PATTERN = re.compile(
    r'plugins/bash-sudo-agents/|scratch/security/|\.gemini/config/config\.json'
    r'|\.gemini/config/hooks\.json|\.agents/hooks\.json'
)
WRITE_OPS_PATTERN = re.compile(
    r'(>(?!&)'
    r'|\btee\b'
    r'|\bsed\s+-i'
    r'|\bdd\b[^;&|\n]*\bof='
    r'|\brsync\b'
    r'|\btar\s+(?:-[a-zA-Z]*x|--extract)'
    r'|(^|[;&|\s])(chmod|chown|chattr|rm|mv|cp|install|shred|ln|unlink)(\s|$))'
)

# ---------------------------------------------------------------------------
# Interpretadores inline (`python3 -c`, `perl -e`, ...): escape do parser de shell
# ---------------------------------------------------------------------------

INLINE_INTERPRETERS = frozenset({
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs",
    "php", "lua", "osascript", "pwsh", "powershell", "Rscript",
})
EVAL_FLAGS = frozenset({"-c", "-e", "-r", "--eval", "--print"})

# Menção a caminho protegido dentro do código passado ao interpretador.
_PROTECTED_MENTION = re.compile(
    r'/(?:' + _VITAL_ALT + r'|home)(?:/|\b)'
    r'|/dev/|\b(?:passwd|shadow|gshadow|sudoers|fstab|crypttab)\b'
    r'|scratch/security|bash-sudo-agents|hooks\.json'
)


def _detect_inline_interpreter(cmd: str) -> str | None:
    """
    Interpretadores inline (`python3 -c "..."`, `perl -e "..."`) escapam da
    análise semântica baseada em argv. Se o código referenciar caminhos
    protegidos, retorna:
      - "deny":      referência à infraestrutura de governança;
      - "force_ask": referência a caminho vital do sistema.
    """
    for seg in _shell_split_commands(cmd):
        argv = _unwrap_privilege_prefix(_safe_split(seg))
        if not argv:
            continue
        binary = argv[0].split("/")[-1]
        if binary not in INLINE_INTERPRETERS:
            continue
        if not any(a in EVAL_FLAGS for a in argv[1:]):
            continue
        code = " ".join(argv[1:])
        if GOV_PATTERN.search(code):
            return "deny"
        if _PROTECTED_MENTION.search(code):
            return "force_ask"
    return None


# ---------------------------------------------------------------------------
# Auditoria constitucional principal
# ---------------------------------------------------------------------------

def _resolve_gov_target(target_raw: str, cwd: Path) -> str:
    """Normaliza o alvo cru para checagem de governança (absoluto ou relativo ao cwd)."""
    if not target_raw:
        return ""
    try:
        cand = Path(target_raw).expanduser()
        if not cand.is_absolute():
            cand = Path(cwd) / cand
        return str(cand)
    except Exception:
        return target_raw


def audit_command(parsed: ParsedCommand, target_path: Path | None,
                  cwd: Path, target_raw: str | None = None) -> tuple[str, str | None, dict | None]:
    """
    Executa a auditoria de segurança sobre um comando já parseado.
    Retorna (decision, reason, overwrite).
    """
    cmd = parsed.raw_cmd
    target_str = target_raw or ""
    resolved_target = _resolve_gov_target(target_str, cwd)
    # Superfície de casamento: remove strings literais entre aspas, mas preserva
    # substituições $() e crases. Evita falsos positivos (ex.: mensagens de commit)
    # sem abrir mão da detecção dentro de sub-shells.
    surface = _regex_surface(cmd)

    # RULE-06: Veto irreversível ao sudo_runner
    if SUDO_RUNNER_PATTERN.search(surface):
        return "deny", "[governance-gate / RULE-06] sudo_runner.sh foi descontinuado.", None

    # RULE-02: Veto sumário anti-destruição (semântico + regex fallback)
    destructive_bin = _detect_destructive(cmd, cwd)
    if destructive_bin or DESTRUCTIVE_PATTERN.search(surface):
        return "deny", "[governance-gate / RULE-02] Veto sumário: comando destrutivo detectado.", None

    # RULE-02 estendida: mutação direta de caminho vital (mv/cp/truncate/tee/ln/redirect)
    mutation_bin = _detect_mutation(cmd, cwd)
    if mutation_bin:
        return "deny", (
            f"[governance-gate / RULE-02] Veto: mutação direta de caminho vital "
            f"detectada ({mutation_bin})."
        ), None

    # RULE-07: Estabilidade de serviços essenciais (anti-crash)
    if SERVICE_PATTERN.search(surface):
        return "deny", "[governance-gate / RULE-07] Tentativa de interromper serviço crítico da sessão.", None

    # RULE-05: Preservação da árvore de permissões (semântica + regex fallback)
    if _detect_perm_abuse(cmd, cwd) or PERM_PATTERN.search(surface):
        return "deny", "[governance-gate / RULE-05] Alteração recursiva de permissões em diretório protegido.", None

    # RULE-01: Soberania do Display — leitura é livre (RULE-09); escrita retém.
    if MONITOR_PATTERN.search(target_str) \
            or (target_path and MONITOR_PATTERN.search(str(target_path))):
        return "force_ask", "[governance-gate / RULE-01] Alteração em configuração de monitores detectada.", None
    if MONITOR_PATTERN.search(surface) and _monitor_write_intent(surface):
        return "force_ask", "[governance-gate / RULE-01] Alteração em configuração de monitores detectada.", None

    # RULE-03: Operações de disco e formatação controladas
    if DISK_PATTERN.search(surface):
        return "force_ask", "[governance-gate / RULE-03] Operação de disco/formatação exige confirmação explícita.", None

    # RULE-07 (classe de energia): reboot/poweroff/suspend sempre exigem confirmação.
    if POWER_PATTERN.search(surface):
        return "force_ask", "[governance-gate / RULE-07] Desligamento/reinício/suspensão da máquina ou da sessão exige confirmação explícita.", None

    # RULE-11 e RULE-12: Proteção de governança — avaliada ANTES da taxonomia de
    # privilégio, para que "sudo rm <arquivo do gate>" seja veto, não mero ask.
    # Usa o comando BRUTO (não a superfície): falso positivo em path de governança
    # entre aspas é aceitável; deixar passar não é.
    if resolved_target and GOV_PATTERN.search(resolved_target):
        return "deny", "[governance-gate / RULE-12] Escrita em arquivo de governança detectada.", None
    if GOV_PATTERN.search(cmd) and WRITE_OPS_PATTERN.search(cmd):
        return "deny", "[governance-gate / RULE-12] Comando tenta modificar arquivo de governança.", None

    # Interpretadores inline sobre caminhos protegidos (escape do parser argc).
    inline = _detect_inline_interpreter(cmd)
    if inline == "deny":
        return "deny", "[governance-gate / RULE-12] Interpretador inline tentando manipular a infraestrutura de governança.", None
    if inline == "force_ask":
        return "force_ask", "[governance-gate / RULE-02] Interpretador inline referenciando caminho vital exige confirmação explícita.", None

    # RULE-15: Elevação de privilégio rotineira — decisão "ask" (respeita o
    # "Always Allow" nativo: aprova uma vez por recurso e não é mais perguntado).
    privileged, ptype = _cmd_is_privileged(cmd)
    if privileged or SUBSHELL_PRIV_PATTERN.search(surface):
        return "ask", (
            f"[governance-gate / RULE-15] Elevação de privilégio ({ptype or 'privileged'}). "
            "Aprove e marque 'Always Allow' para não ser perguntado novamente."
        ), None

    return "allow", "", None


def _emit_overwrite(new_cmd: str, rule: str, target_path: Path | None, cwd: Path,
                    latency_ms: int, cwd_str: str) -> None:
    """
    Emite um overwrite de comando re-auditando o comando modificado (Seção 5.5).
    Se a re-validação reprovar, o overwrite é negado (nunca emitido). O motivo
    (regra) é registrado em `audit.log`.
    """
    parsed_mod = parse_command(new_cmd)
    mod_decision, mod_reason, _ = audit_command(parsed_mod, target_path, cwd)
    if mod_decision != "allow":
        audit_log("deny", f"Overwrite rejeitado: {mod_reason}", "OVERWRITE_REVALIDATION",
                  new_cmd, cwd_str, latency_ms)
        out("deny", f"Comando otimizado rejeitado na re-validação: {mod_reason}")
    audit_log("allow", f"overwrite:{rule}", rule, new_cmd, cwd_str, latency_ms)
    out("allow", "", overwrite={"CommandLine": new_cmd})


def audit_and_optimize() -> None:
    start_ms = _now_ms()

    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            out("allow", "")
        data = json.loads(raw_input)
    except Exception as e:
        out("force_ask", f"Failsafe: payload malformado ({str(e)}) — confirmação humana exigida.")

    tool_call = data.get("toolCall", {})
    if not isinstance(tool_call, dict):
        tool_call = {}
    args = tool_call.get("args", {})
    if not isinstance(args, dict):
        args = {}

    tool_name = (tool_call.get("name") or data.get("tool") or data.get("toolName") or "").strip()
    cmd = (args.get("CommandLine") or args.get("command") or data.get("command") or "").strip()
    target_raw = (args.get("TargetFile") or args.get("file_path")
                  or data.get("target") or data.get("file_path") or "").strip()
    # Contrato de cwd: aceita data.cwd (topo) e toolCall.args.Cwd / cwd.
    cwd_str = (data.get("cwd") or args.get("Cwd") or args.get("cwd") or str(HOME))
    cwd = Path(cwd_str)

    cmd_hash = hashlib.sha256(f"{cwd_str}:{cmd}".encode("utf-8")).hexdigest()[:16]

    # Incluir LANG e LC_ALL no hash (Quick Win #5)
    env_snapshot = f"{cmd_hash}:{os.environ.get('LANG', '')}:{os.environ.get('LC_ALL', '')}"
    env_hash = hashlib.sha256(env_snapshot.encode("utf-8")).hexdigest()[:16]

    # Sanitizar TargetFile (Quick Win #2)
    target_path = resolve_target_safely(target_raw, cwd)

    # Parser semântico (Seções 5.1 e 8.3)
    parsed = parse_command(cmd)

    # =========================================================================
    # 1. AUDITORIA CONSTITUCIONAL
    # =========================================================================
    decision, reason, overwrite = audit_command(parsed, target_path, cwd, target_raw)

    # RULE-10: contador de recusas CONSECUTIVAS. `deny` incrementa; qualquer
    # outra decisão (allow/ask/force_ask) interrompe a sequência e zera.
    consecutive_denials = _record_decision(decision, cmd)

    if decision == "deny":
        latency_ms = _now_ms() - start_ms
        audit_log(decision, reason, "RULE-02/05/06/07/12", cmd, cwd_str, latency_ms)
        if consecutive_denials >= REJECTION_LIMIT:
            out("deny", _escalation_reason(reason, cwd_str))
        out("deny", reason)

    if decision == "force_ask":
        latency_ms = _now_ms() - start_ms
        audit_log(decision, reason, "RULE-01/02/03/07", cmd, cwd_str, latency_ms)
        out("force_ask", reason)

    if decision == "ask":
        latency_ms = _now_ms() - start_ms
        audit_log(decision, reason, "RULE-15", cmd, cwd_str, latency_ms)
        out("ask", reason)

    # FAIL-CLOSED: payload válido, mas sem `CommandLine` reconhecível.
    # Ferramentas de leitura/escrita conhecidas prosseguem (o `TargetFile` já foi
    # auditado em `audit_command`); qualquer schema inesperado exige confirmação
    # humana em vez de `allow` silencioso.
    if not cmd:
        latency_ms = _now_ms() - start_ms
        if tool_name in NON_COMMAND_TOOLS:
            audit_log("allow", "Ferramenta sem CommandLine (TargetFile auditado).",
                      None, "", cwd_str, latency_ms)
            out("allow", "")
        audit_log("force_ask", "Payload sem CommandLine reconhecível (fail-closed).",
                  "FAILSAFE_SCHEMA", "", cwd_str, latency_ms)
        out("force_ask",
            "[governance-gate] Chamada sem `CommandLine` reconhecível — schema inesperado; confirmação humana exigida (fail-closed).")

    # =========================================================================
    # 2. CACHE LOCAL COM TTL (Quick Wins #1, #5, #7 — diretório 0700)
    # =========================================================================
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(CACHE_DIR, 0o700)
    except Exception:
        pass

    CACHE_RULES = [
        (re.compile(r'^(lscpu|uname(\s+-[a-zA-Z]+)?|lspci|lsusb|cat\s+/etc/os-release|cat\s+/proc/cpuinfo)$'), 3600),
        (re.compile(r'^(pacman|yay|paru)\s+-Ss\s+'), 600),
    ]

    ttl = 0
    for pattern, rule_ttl in CACHE_RULES:
        if pattern.search(cmd):
            ttl = rule_ttl
            break

    cache_file = CACHE_DIR / f"{env_hash}.cache"

    if ttl > 0:
        # Leitura do cache com TTL (proteção real: diretório 0700 da conta do usuário)
        if cache_file.exists() and cache_file.stat().st_size > 0:
            try:
                mtime = cache_file.stat().st_mtime
                if (time.time() - mtime) < ttl:
                    _emit_overwrite(f"cat {shlex.quote(str(cache_file))}", "CACHE_HIT",
                                    target_path, cwd, _now_ms() - start_ms, cwd_str)
            except Exception:
                pass

        # Escrever no cache com wrap seguro (Quick Win #1). Buscas de pacote já
        # gravam a saída comprimida (compressor embutido no wrap — Seção 5.5).
        if ">" not in cmd and "|" not in cmd:
            suffix = "head -n 25" if re.match(r'^(pacman|yay|paru)\s+-Ss\s+', cmd) else None
            wrapped_cmd = safe_cache_wrap(cmd, cache_file, pipe_suffix=suffix)
            if wrapped_cmd != cmd:
                _emit_overwrite(wrapped_cmd, "CACHE_WRITE", target_path, cwd,
                                _now_ms() - start_ms, cwd_str)
            else:
                # Comando não-cacheável cai para o fluxo normal (allow)
                pass

    # =========================================================================
    # 3. AUTO-COMPRESSOR SINTÁTICO
    # =========================================================================
    if not parsed.has_redirect and not parsed.has_pipe:
        if cmd.startswith("journalctl") and not re.search(
                r'(-n\s*\d+|--lines(=|\s*)\d+|-[a-zA-Z]*f\b|--follow)', cmd):
            _emit_overwrite(f"{cmd} --no-pager -n 35", "COMPRESS_JOURNALCTL",
                            target_path, cwd, _now_ms() - start_ms, cwd_str)
        elif cmd.startswith("dmesg") and not re.search(r'\b(tail|head)\b|-w\b|--follow', cmd):
            _emit_overwrite(f"{cmd} --color=never | tail -n 35", "COMPRESS_DMESG",
                            target_path, cwd, _now_ms() - start_ms, cwd_str)
        elif cmd.startswith("git log") and not re.search(r'(-\d+|-n\s*\d+)', cmd):
            _emit_overwrite(f"{cmd} -n 15", "COMPRESS_GIT_LOG",
                            target_path, cwd, _now_ms() - start_ms, cwd_str)
        elif re.match(r'^(pacman|yay|paru)\s+-Ss\s+', cmd):
            _emit_overwrite(f"{cmd} | head -n 25", "COMPRESS_PACMAN",
                            target_path, cwd, _now_ms() - start_ms, cwd_str)

    latency_ms = _now_ms() - start_ms
    audit_log("allow", "", None, cmd, cwd_str, latency_ms)
    out("allow", "")


def main() -> None:
    try:
        audit_and_optimize()
    except SystemExit:
        raise
    except Exception as e:
        try:
            log_dir = CACHE_DIR
            log_dir.mkdir(parents=True, exist_ok=True)
            with open(log_dir / "governance_failsafe.log", "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Failsafe: {str(e)}\n")
        except Exception:
            pass
        out("force_ask", f"Failsafe: erro interno ({str(e)}) — confirmação humana exigida.")


if __name__ == "__main__":
    main()
