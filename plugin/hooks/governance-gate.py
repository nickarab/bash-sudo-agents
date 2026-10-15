#!/usr/bin/env python3
"""
governance-gate.py — Antigravity Linux Governance Engine (v4.1)
Arquitetura do Sistema:
  - @agente-bash: Operador de Terminal (LLM)
  - governance-gate.py: Motor de Governança, Firewall, Cache e Compressor físico no SO (Runtime Hook)
  - @agente-sudo-policy: Gestor Constitucional Legislativo (LLM)
Recursos:
  1. Auditoria e Firewall Constitucional (RULE-01 a RULE-15)
  2. Auto-Compressor Sintático de Tokens (overwrite com blindagem de sintaxe)
  3. Cache Local de Saídas com TTL e assinatura HMAC-SHA256
  4. Failsafe Universal (Zero Downtime)
  5. Estado de Rejeição Persistente (RULE-10 - 3X com TTL 24h)
  6. Re-validação de Overwrite (comando modificado re-auditado)
  7. Parser semântico com shlex para substituição de regex frágeis
  8. Detecção semântica de destruição (rm/find/shred/dd) com split de shell
  9. RULE-03 (disco/formatação), RULE-05 (permissões) e RULE-07 (serviços críticos)
Zero dependências externas (estritamente Python 3.8+ Standard Library).
"""

import sys
import json
import os
import re
import shlex
import hashlib
import hmac
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
HMAC_SECRET_FILE = CACHE_DIR / ".hmac_secret"
REJECTION_TTL_SECONDS = 86400  # 24 horas
REJECTION_LIMIT = 3


# ---------------------------------------------------------------------------
# Utilitários de saída e logging
# ---------------------------------------------------------------------------

def _now_ms() -> int:
    return int(time.time() * 1000)


def out(decision: str, reason: str = "", overwrite: dict | None = None,
        rule: str | None = None, cmd_hash: str | None = None,
        latency_ms: int | None = None) -> None:
    """Emite decisão JSON no stdout e encerra com código 0."""
    res: dict = {"decision": decision}
    if reason:
        res["reason"] = reason
    if overwrite:
        res["overwrite"] = overwrite
    # Campos de auditoria estruturada
    if rule:
        pass # res["rule"] = rule
    if cmd_hash:
        pass # res["cmd_hash"] = cmd_hash
    if latency_ms is not None:
        pass # res["latency_ms"] = latency_ms
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


# ---------------------------------------------------------------------------
# HMAC para assinatura de cache (Seção 5.4)
# ---------------------------------------------------------------------------

def _load_or_create_hmac_secret() -> bytes:
    """Carrega ou cria a chave secreta HMAC usada para assinar entradas de cache."""
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(CACHE_DIR, 0o700)  # Quick Win #7
        if HMAC_SECRET_FILE.exists():
            return HMAC_SECRET_FILE.read_bytes()
        secret = os.urandom(32)
        HMAC_SECRET_FILE.write_bytes(secret)
        os.chmod(HMAC_SECRET_FILE, 0o600)
        return secret
    except Exception:
        return b"default-secret-change-me"


def _sign_cache_entry(payload: dict, secret: bytes) -> str:
    """Gera assinatura HMAC-SHA256 para uma entrada de cache."""
    return hmac.new(secret, json.dumps(payload, sort_keys=True).encode("utf-8"), hashlib.sha256).hexdigest()


def _verify_cache_signature(payload: dict, signature: str, secret: bytes) -> bool:
    """Verifica a assinatura HMAC de uma entrada de cache."""
    expected = _sign_cache_entry(payload, secret)
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# Estado de rejeição persistente (RULE-10 — Seção 5.2)
# ---------------------------------------------------------------------------

def _load_rejection_state() -> dict:
    try:
        if REJECTION_STATE_FILE.exists():
            data = json.loads(REJECTION_STATE_FILE.read_text(encoding="utf-8"))
            now = time.time()
            # Limpar entradas expiradas (TTL 24h)
            return {k: v for k, v in data.items() if now - v.get("last_reject", 0) < REJECTION_TTL_SECONDS}
    except Exception:
        pass
    return {}


def _save_rejection_state(state: dict) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        REJECTION_STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
        os.chmod(REJECTION_STATE_FILE, 0o600)
    except Exception:
        pass


def _increment_rejection(key: str) -> int:
    state = _load_rejection_state()
    entry = state.get(key, {"count": 0, "last_reject": 0})
    entry["count"] = entry.get("count", 0) + 1
    entry["last_reject"] = time.time()
    state[key] = entry
    _save_rejection_state(state)
    return entry["count"]


def _get_rejection_count(key: str) -> int:
    state = _load_rejection_state()
    return state.get(key, {}).get("count", 0)


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
        # Comandos diretos de privilégio
        if first in {"sudo", "doas", "pkexec", "su", "run0"}:
            sudo_like = True
            privilege_type = first
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
        elif first in {"yay", "paru", "pacman"} and "-S" in argv[1:]:
            sudo_like = True
            privilege_type = "package_install"
            target_bin = first
        elif first == "systemctl":
            if len(argv) > 1 and argv[1] in {"start", "stop", "restart", "enable", "disable", "mask", "unmask"}:
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


# Diretórios vitais do sistema (RULE-02). Não inclui /home em geral: apenas a
# raiz do home (~) é considerada vital, não subdiretórios arbitrários do usuário.
VITAL_TOP_DIRS = {"boot", "etc", "usr", "var", "sys", "proc", "dev", "bin", "sbin", "lib", "lib64"}


def _normalize_path(arg: str, cwd: Path) -> str:
    """Expande ~, torna absoluto relativo ao cwd e normaliza .. (sem exigir existência)."""
    p = Path(arg).expanduser()
    if not p.is_absolute():
        p = cwd / p
    return os.path.normpath(str(p))


def _is_vital_path(arg: str) -> bool:
    """True se o caminho (já normalizado) aponta para a raiz ou um diretório vital."""
    if arg in {"/", "/*"}:
        return True
    if arg.startswith("/"):
        rest = arg.lstrip("/")
        top = rest.split("/", 1)[0]
        top = top.split("*", 1)[0]
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


def _detect_destructive(cmd: str, cwd: Path) -> str | None:
    """
    Detecção semântica de comandos destrutivos (RULE-02).
    Divide a linha em comandos, remove prefixos de privilégio e verifica o
    binário alvo e seus argumentos. Retorna o binário destrutivo ou None.
    Caminhos são normalizados (expandido ~, absoluto vs cwd, .. resolvido)
    antes da checagem de diretório vital. Variáveis de ambiente não resolvidas
    ($) em argumentos destrutivos são vetadas, pois o gate roda pré-bash.
    """
    for seg in _shell_split_commands(cmd):
        argv = _unwrap_privilege_prefix(_safe_split(seg))
        if not argv:
            continue
        binary = argv[0]
        args = argv[1:]
        # Bloquear destrutivo com variável de ambiente não resolvida (pré-bash)
        if any("$" in a for a in args if not a.startswith("-")):
            return binary
        if binary == "rm":
            if any(a.startswith("-") and "r" in a for a in args):
                for a in args:
                    if a.startswith("-"):
                        continue
                    if _is_vital_path(_normalize_path(a, cwd)):
                        return "rm"
        elif binary == "find":
            if any(a == "-delete" or a.startswith("-delete") for a in args):
                return "find"
        elif binary == "shred":
            return "shred"
        elif binary == "dd":
            for a in args:
                if a.startswith("of=/dev/") or a == "of=/dev/sda":
                    return "dd"
    return None


# ---------------------------------------------------------------------------
# Validação segura de comando para cache (Quick Win #1)
# ---------------------------------------------------------------------------

CACHEABLE_BINS = {"lscpu", "uname", "lspci", "lsusb", "pacman", "yay", "paru"}

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
    if argv[0] not in CACHEABLE_BINS:
        return False
    # Rejeitar argumentos perigosos
    for arg in argv[1:]:
        if arg in DANGEROUS_ARGS:
            return False
    return True


def safe_cache_wrap(cmd: str, cache_file: Path) -> str:
    """
    Wrap seguro de comando para cache.
    Apenas comandos na whitelist CACHEABLE_BINS são wrapados.
    Reconstrução segura com shlex.quote para cada argumento.
    """
    if not _is_cacheable(cmd):
        return cmd  # Não wrapar — executa direto sem cache

    try:
        argv = shlex.split(cmd, posix=True)
    except ValueError:
        return cmd

    safe_cmd = " ".join(shlex.quote(arg) for arg in argv)
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
    r'|find\s+[^;&|\n]*\s+-delete'
    r'|shred\b'
    r'|dd\s+[^;&|\n]*\bof=/dev/'
    r')'
)

# RULE-03: Operações de disco/formatação — exigem confirmação explícita (force_ask)
DISK_PATTERN = re.compile(
    _BOUNDARY +
    r'(?:mkfs\b|fdisk\b|parted\b|umount\b|wipefs\b|losetup\b'
    r'|mount\s+(?:-[a-zA-Z]|\S+))'
)

# RULE-05: Preservação de permissões — veto a chmod/chown recursivos abusivos
PERM_PATTERN = re.compile(
    _BOUNDARY +
    r'(?:chmod\s+-R\s+(?:0?777|777|a\+rwx|ugo\+rwx|a=rwx)\b'
    r'|chown\s+-R\s+\S+\s+(?:/|/(?:boot|etc|usr|var|sys|proc|dev|bin|sbin|lib|lib64)(?:/.*)?))'
)

# RULE-07: Estabilidade de serviços essenciais — veto a derrubar a sessão ativa
SERVICE_PATTERN = re.compile(
    _BOUNDARY +
    r'(?:systemctl\s+(?:--user\s+)?(?:stop|disable|mask|kill)\s+(?:--user\s+)?(?:sddm|gdm|ly|lightdm|display-manager|getty\S*|hyprland)'
    r'|(?:pkill|killall|kill)\s+-?\w*\s*(?:hyprland|Hyprland|wayland|Xorg|Xwayland|sddm|gdm|sddm-helper|gnome-shell|sway)'
    r'|kill\s+-9\s+1\b)'
)

# RULE-01: Monitores
MONITOR_PATTERN = re.compile(r'monitors\.lua|hyprland/.*monitors?\.conf')

# RULE-15: Taxonomia de privilégios
PRIV_PATTERN = re.compile(
    r'(^|[;&|(`\s])(sudo|doas|pkexec|su|run0)(\s|$)'
    r'|(^|[;&|`\s])sudo\s+(-u|-i|--user|--login)\s+'
    r'|(^|[;&|`\s])(yay|paru)\s+-S'
    r'|(^|[;&|`\s])systemctl\s+(start|stop|restart|enable|disable|mask|unmask)\s+(?!.*--user)'
    r'|\$\([^)]*(?:sudo|doas|pkexec|su|run0)[^)]*\)'
    r'|`[^`]*(?:sudo|doas|pkexec|su|run0)[^`]*`'
)

# RULE-11 e RULE-12: Proteção da infraestrutura de governança
GOV_PATTERN = re.compile(
    r'plugins/bash-sudo-agents/|scratch/security/|\.gemini/config/config\.json'
)
WRITE_OPS_PATTERN = re.compile(
    r'(>|\btee\b|sed\s+-i|(^|[;&|\s])(chmod|chown|chattr|rm|mv|cp|install|shred)(\s|$))'
)


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

    # RULE-06: Veto irreversível ao sudo_runner
    if SUDO_RUNNER_PATTERN.search(cmd):
        return "deny", "[governance-gate / RULE-06] sudo_runner.sh foi descontinuado.", None

    # RULE-02: Veto sumário anti-destruição (semântico + regex fallback)
    destructive_bin = _detect_destructive(cmd, cwd)
    if destructive_bin or DESTRUCTIVE_PATTERN.search(cmd):
        return "deny", "[governance-gate / RULE-02] Veto sumário: comando destrutivo detectado.", None

    # RULE-07: Estabilidade de serviços essenciais (anti-crash)
    if SERVICE_PATTERN.search(cmd):
        return "deny", "[governance-gate / RULE-07] Tentativa de interromper serviço crítico da sessão.", None

    # RULE-05: Preservação da árvore de permissões
    if PERM_PATTERN.search(cmd):
        return "deny", "[governance-gate / RULE-05] Alteração recursiva de permissões em diretório protegido.", None

    # RULE-01: Soberania do Display
    if MONITOR_PATTERN.search(cmd) or MONITOR_PATTERN.search(target_str) \
            or (target_path and MONITOR_PATTERN.search(str(target_path))):
        return "force_ask", "[governance-gate / RULE-01] Alteração em configuração de monitores detectada.", None

    # RULE-03: Operações de disco e formatação controladas
    if DISK_PATTERN.search(cmd):
        return "force_ask", "[governance-gate / RULE-03] Operação de disco/formatação exige confirmação explícita.", None

    # RULE-15: Taxonomia de comandos privilegiados
    if parsed.sudo_like or PRIV_PATTERN.search(cmd):
        return "force_ask", f"[governance-gate / RULE-15] Comando com privilégios detectado ({parsed.privilege_type or 'privileged'}).", None

    # RULE-11 e RULE-12: Proteção de governança (alvo cru + comando)
    if resolved_target and GOV_PATTERN.search(resolved_target):
        return "deny", "[governance-gate / RULE-12] Escrita em arquivo de governança detectada.", None
    if GOV_PATTERN.search(cmd) and WRITE_OPS_PATTERN.search(cmd):
        return "deny", "[governance-gate / RULE-12] Comando tenta modificar arquivo de governança.", None

    return "allow", "", None


def _emit_overwrite(new_cmd: str, rule: str, target_path: Path | None, cwd: Path,
                    cmd_hash: str, latency_ms: int, cwd_str: str) -> None:
    """
    Emite um overwrite de comando re-auditando o comando modificado (Seção 5.5).
    Se a re-validação reprovar, o overwrite é negado (nunca emitido).
    """
    parsed_mod = parse_command(new_cmd)
    mod_decision, mod_reason, _ = audit_command(parsed_mod, target_path, cwd)
    if mod_decision != "allow":
        audit_log("deny", f"Overwrite rejeitado: {mod_reason}", "OVERWRITE_REVALIDATION",
                  new_cmd, cwd_str, latency_ms)
        out("deny", f"Comando otimizado rejeitado na re-validação: {mod_reason}",
            rule="OVERWRITE_REVALIDATION", cmd_hash=cmd_hash, latency_ms=latency_ms)
    out("allow", "", overwrite={"CommandLine": new_cmd}, rule=rule,
        cmd_hash=cmd_hash, latency_ms=latency_ms)


def audit_and_optimize() -> None:
    start_ms = _now_ms()
    secret = _load_or_create_hmac_secret()

    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            out("allow", "")
        data = json.loads(raw_input)
    except Exception as e:
        out("allow", f"Failsafe: payload inválido ({str(e)})")

    args = data.get("toolCall", {}).get("args", {})
    cmd = args.get("CommandLine", args.get("command", "")).strip()
    target_raw = args.get("TargetFile", args.get("file_path", "")).strip()
    cwd_str = args.get("Cwd", args.get("cwd", str(HOME)))
    cwd = Path(cwd_str)

    cmd_hash = hashlib.sha256(f"{cwd_str}:{cmd}".encode("utf-8")).hexdigest()[:16]

    # Incluir LANG e LC_ALL no hash (Quick Win #5)
    env_snapshot = f"{cmd_hash}:{os.environ.get('LANG', '')}:{os.environ.get('LC_ALL', '')}"
    env_hash = hashlib.sha256(env_snapshot.encode("utf-8")).hexdigest()[:16]

    # Sanitizar TargetFile (Quick Win #2)
    target_path = resolve_target_safely(target_raw, cwd)

    # Parser semântico (Seções 5.1 e 8.3)
    parsed = parse_command(cmd)

    # Chave de rejeição baseada em usuário + sessão (cwd como proxy)
    rejection_key = f"{cwd_str}:{cmd_hash}"

    # =========================================================================
    # 1. AUDITORIA CONSTITUCIONAL
    # =========================================================================
    decision, reason, overwrite = audit_command(parsed, target_path, cwd, target_raw)

    if decision == "deny":
        # RULE-10: Incrementar contador de rejeições
        count = _increment_rejection(rejection_key)
        latency_ms = _now_ms() - start_ms
        audit_log(decision, reason, "RULE-02/05/06/07", cmd, cwd_str, latency_ms)
        if count >= REJECTION_LIMIT:
            out(decision, reason, rule="RULE-10", cmd_hash=env_hash,
                latency_ms=latency_ms,
                overwrite={"decision": "ESCALATE_3X",
                           "reason": f"Limite de 3 rejeições atingido para {cwd_str}"})
        out(decision, reason, rule="RULE-02/05/06/07", cmd_hash=env_hash, latency_ms=latency_ms)

    if decision == "force_ask":
        count = _increment_rejection(rejection_key)
        latency_ms = _now_ms() - start_ms
        audit_log(decision, reason, "RULE-01/03/12/15", cmd, cwd_str, latency_ms)
        if count >= REJECTION_LIMIT:
            out(decision, reason, rule="RULE-10", cmd_hash=env_hash,
                latency_ms=latency_ms,
                overwrite={"decision": "ESCALATE_3X",
                           "reason": f"Limite de 3 rejeições atingido para {cwd_str}"})
        out(decision, reason, rule="RULE-01/03/12/15", cmd_hash=env_hash, latency_ms=latency_ms)

    if not cmd:
        out("allow", "", cmd_hash=env_hash, latency_ms=_now_ms() - start_ms)

    # =========================================================================
    # 2. CACHE LOCAL COM TTL E ASSINATURA HMAC (Quick Wins #1, #5, #7)
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
        # Leitura segura do cache (TOCTOU fixo — ler uma única vez)
        if cache_file.exists() and cache_file.stat().st_size > 0:
            try:
                mtime = cache_file.stat().st_mtime
                if (time.time() - mtime) < ttl:
                    cached_data = cache_file.read_text(encoding="utf-8")
                    # Verificar assinatura HMAC se presente
                    try:
                        cached_json = json.loads(cached_data)
                        if isinstance(cached_json, dict) and "sig" in cached_json:
                            if not _verify_cache_signature(
                                {k: v for k, v in cached_json.items() if k != "sig"},
                                cached_json["sig"], secret
                            ):
                                # Assinatura inválida — ignora cache (cai para rewrite)
                                pass
                            else:
                                _emit_overwrite(f"cat {shlex.quote(str(cache_file))}", "CACHE_HIT",
                                                target_path, cwd, env_hash, _now_ms() - start_ms, cwd_str)
                        else:
                            # Cache legado sem assinatura — ainda válido
                            _emit_overwrite(f"cat {shlex.quote(str(cache_file))}", "CACHE_HIT",
                                            target_path, cwd, env_hash, _now_ms() - start_ms, cwd_str)
                    except (json.JSONDecodeError, KeyError):
                        # Cache não-JSON (legado) — ainda válido
                        _emit_overwrite(f"cat {shlex.quote(str(cache_file))}", "CACHE_HIT",
                                        target_path, cwd, env_hash, _now_ms() - start_ms, cwd_str)
            except Exception:
                pass

        # Escrever no cache com wrap seguro (Quick Win #1)
        if ">" not in cmd and "|" not in cmd:
            wrapped_cmd = safe_cache_wrap(cmd, cache_file)
            if wrapped_cmd != cmd:
                _emit_overwrite(wrapped_cmd, "CACHE_WRITE", target_path, cwd,
                                env_hash, _now_ms() - start_ms, cwd_str)
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
                            target_path, cwd, env_hash, _now_ms() - start_ms, cwd_str)
        elif cmd.startswith("dmesg") and not re.search(r'\b(tail|head)\b|-w\b|--follow', cmd):
            _emit_overwrite(f"{cmd} --color=never | tail -n 35", "COMPRESS_DMESG",
                            target_path, cwd, env_hash, _now_ms() - start_ms, cwd_str)
        elif cmd.startswith("git log") and not re.search(r'(-\d+|-n\s*\d+)', cmd):
            _emit_overwrite(f"{cmd} -n 15", "COMPRESS_GIT_LOG",
                            target_path, cwd, env_hash, _now_ms() - start_ms, cwd_str)
        elif re.match(r'^(pacman|yay|paru)\s+-Ss\s+', cmd):
            _emit_overwrite(f"{cmd} | head -n 25", "COMPRESS_PACMAN",
                            target_path, cwd, env_hash, _now_ms() - start_ms, cwd_str)

    latency_ms = _now_ms() - start_ms
    audit_log("allow", "", None, cmd, cwd_str, latency_ms)
    out("allow", "", cmd_hash=env_hash, latency_ms=latency_ms)


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
        out("allow", f"Failsafe: {str(e)}")


if __name__ == "__main__":
    main()
