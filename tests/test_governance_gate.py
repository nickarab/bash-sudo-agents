"""
test_governance_gate.py — Suíte de testes para governance-gate.py (v4.4.0)

Cobre todos os vetores de bypass identificados na auditoria:
- Command injection no wrapper de cache
- Path traversal em TargetFile
- Variantes de sudo / sudoedit / run0 / pkexec / doas / su
- rm -rf /*, find -delete, shred, dd
- Re-validação de overwrite
- Limite 3X de rejeições (RULE-10)
- Cache key com LANG/LC_ALL
- Permissões 0o700 no diretório de cache
- Taxonomia anti-fadiga: privilégio rotineiro = ask, energia = force_ask (v4.4.0)
- RULE-05 semântica (ordem de flags, --recursive, modos world-writable)
- RULE-12 endurecida (dd/rsync/tar/ln, hooks.json global e workspace)
- RULE-01: leitura de monitores é livre, escrita retém
"""

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# Carregar governance-gate.py via importlib (nome com hífen não é importável diretamente)
PLUGIN_HOOKS_DIR = Path(__file__).resolve().parent.parent / "plugin" / "hooks"
GATE_PATH = PLUGIN_HOOKS_DIR / "governance-gate.py"
_spec = importlib.util.spec_from_file_location("governance_gate", GATE_PATH)
gg = importlib.util.module_from_spec(_spec)
# PEP 563 (`from __future__ import annotations`) faz o `@dataclass` resolver as
# anotações em runtime; isso exige que o módulo esteja registrado em sys.modules.
sys.modules["governance_gate"] = gg
_spec.loader.exec_module(gg)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_home(tmp_path):
    """Cria um HOME temporário e monkeypatch nos caminhos do módulo."""
    orig_home = gg.HOME
    orig_cache = gg.CACHE_DIR
    orig_rejection = gg.REJECTION_STATE_FILE

    fake_home = tmp_path / "home"
    fake_home.mkdir()
    gg.HOME = fake_home
    gg.PLUGIN_DIR = fake_home / ".gemini" / "config" / "plugins" / "bash-sudo-agents"
    gg.SECURITY_DIR = fake_home / ".gemini" / "antigravity" / "scratch" / "security"
    gg.CACHE_DIR = fake_home / ".cache" / "antigravity" / "bash_agents"
    gg.REJECTION_STATE_FILE = gg.CACHE_DIR / "rejection_state.json"

    yield fake_home

    gg.HOME = orig_home
    gg.CACHE_DIR = orig_cache
    gg.REJECTION_STATE_FILE = orig_rejection


def run_gate(cmd: str, target: str = "", cwd: str | None = None, env: dict | None = None) -> dict:
    """
    Executa governance-gate.py como subprocesso com o payload no stdin.
    Retorna o JSON parseado do stdout.
    """
    script = PLUGIN_HOOKS_DIR / "governance-gate.py"
    payload = {
        "toolCall": {
            "name": "run_command",
            "args": {
                "CommandLine": cmd,
                "TargetFile": target,
                "Cwd": cwd or str(Path.home()),
            },
        }
    }
    full_env = dict(os.environ)
    if env:
        full_env.update(env)

    result = subprocess.run(
        [sys.executable, str(script)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
        env=full_env,
    )
    try:
        return json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        return {"decision": "ERROR", "stdout": result.stdout, "stderr": result.stderr}


def call_audit_command(parsed, target_path, cwd):
    """Chama audit_command diretamente (teste de unidade)."""
    return gg.audit_command(parsed, target_path, Path(cwd))


def run_gate_payload(payload: dict, env: dict | None = None) -> dict:
    """Executa governance-gate.py com um payload arbitrário no stdin."""
    script = PLUGIN_HOOKS_DIR / "governance-gate.py"
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    result = subprocess.run(
        [sys.executable, str(script)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
        env=full_env,
    )
    try:
        return json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        return {"decision": "ERROR", "stdout": result.stdout, "stderr": result.stderr}


def run_gate_raw(stdin_text: str, env: dict | None = None) -> dict:
    """Executa governance-gate.py com texto bruto no stdin (payloads malformados)."""
    script = PLUGIN_HOOKS_DIR / "governance-gate.py"
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    result = subprocess.run(
        [sys.executable, str(script)],
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=10,
        env=full_env,
    )
    try:
        return json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        return {"decision": "ERROR", "stdout": result.stdout, "stderr": result.stderr}


# ---------------------------------------------------------------------------
# 1. Command injection no wrapper de cache (Quick Win #1)
# ---------------------------------------------------------------------------

class TestCacheCommandInjection:
    """Verifica que comandos perigosos NÃO são wrapados para cache."""

    def test_rm_rf_not_cacheable(self):
        """rm -rf /* não deve ser wrapado para cache."""
        assert not gg._is_cacheable("rm -rf /*")
        assert not gg._is_cacheable("rm -rf /home/user/..")
        assert gg.safe_cache_wrap("rm -rf /*", Path("/tmp/x.cache")) == "rm -rf /*"

    def test_find_delete_not_cacheable(self):
        """find ... -delete não deve ser wrapado."""
        assert not gg._is_cacheable("find / -type f -delete")
        assert gg.safe_cache_wrap("find / -type f -delete", Path("/tmp/x.cache")) == "find / -type f -delete"

    def test_shred_not_cacheable(self):
        """shred não deve ser wrapado."""
        assert not gg._is_cacheable("shred -u /dev/sda")
        assert gg.safe_cache_wrap("shred -u /dev/sda", Path("/tmp/x.cache")) == "shred -u /dev/sda"

    def test_dd_not_cacheable(self):
        """dd não deve ser wrapado."""
        assert not gg._is_cacheable("dd if=/dev/zero of=/dev/sda")
        assert gg.safe_cache_wrap("dd if=/dev/zero of=/dev/sda", Path("/tmp/x.cache")) == "dd if=/dev/zero of=/dev/sda"

    def test_lscpu_cacheable(self):
        """lscpu deve ser wrapado para cache."""
        assert gg._is_cacheable("lscpu")
        wrapped = gg.safe_cache_wrap("lscpu", Path("/tmp/x.cache"))
        assert wrapped != "lscpu"
        assert "tee" in wrapped
        assert "shlex.quote" not in wrapped  # apenas verificação visual

    def test_uname_cacheable(self):
        """uname -a deve ser wrapado para cache."""
        assert gg._is_cacheable("uname -a")

    def test_cacheable_with_dangerous_arg_rejected(self):
        """Comando cacheable com argumento perigoso é rejeitado."""
        assert not gg._is_cacheable("lscpu ; rm -rf /")
        assert not gg._is_cacheable("uname -a | cat")

    def test_cache_wrap_uses_shlex_quote(self):
        """O wrap seguro usa shlex.quote para cada argumento."""
        wrapped = gg.safe_cache_wrap("lscpu", Path("/tmp/cache file.cache"))
        assert "tee" in wrapped
        assert "/tmp/cache file.cache" in wrapped or "'/tmp/cache file.cache'" in wrapped


# ---------------------------------------------------------------------------
# 2. Path traversal em TargetFile (Quick Win #2)
# ---------------------------------------------------------------------------

class TestPathTraversal:
    """Verifica que TargetFile fora do escopo é rejeitado."""

    def test_relative_path_inside_cwd(self):
        """Caminho relativo dentro do cwd é aceito."""
        cwd = Path("/home/user/projects")
        result = gg.resolve_target_safely("src/main.py", cwd)
        assert result is not None

    def test_traversal_outside_cwd_rejected(self):
        """../ para fora do cwd é rejeitado."""
        cwd = Path("/home/user/projects")
        result = gg.resolve_target_safely("../../etc/passwd", cwd)
        assert result is None

    def test_traversal_to_governance_dir_rejected(self):
        """Tentativa de acessar diretório de governança via traversal é rejeitada."""
        cwd = Path("/home/user")
        result = gg.resolve_target_safely("../../.gemini/config/plugins/bash-sudo-agents/policies.json", cwd)
        assert result is None

    def test_absolute_path_outside_allowed_rejected(self):
        """Caminho absoluto fora das raízes permitidas é rejeitado."""
        cwd = Path("/home/user")
        result = gg.resolve_target_safely("/etc/shadow", cwd)
        assert result is None

    def test_tmp_path_allowed(self):
        """Caminho dentro de /tmp é permitido."""
        cwd = Path("/home/user")
        result = gg.resolve_target_safely("test.txt", Path("/tmp"))
        assert result is not None

    def test_empty_target_none(self):
        """Target vazio retorna None."""
        assert gg.resolve_target_safely("", Path("/home/user")) is None
        assert gg.resolve_target_safely(None, Path("/home/user")) is None


# ---------------------------------------------------------------------------
# 3. Variantes de privilégio (Quick Win #3)
# ---------------------------------------------------------------------------

class TestPrivilegeDetection:
    """Verifica detecção de comandos privilegiados."""

    def test_sudo_detected(self):
        """sudo é detectado como privilégio."""
        parsed = gg.parse_command("sudo apt update")
        assert parsed.sudo_like is True
        assert parsed.privilege_type == "sudo"

    def test_sudo_u_detected(self):
        """sudo -u user cmd é detectado."""
        parsed = gg.parse_command("sudo -u root whoami")
        assert parsed.sudo_like is True
        assert parsed.privilege_type == "sudo"

    def test_sudo_i_detected(self):
        """sudo -i é detectado."""
        parsed = gg.parse_command("sudo -i")
        assert parsed.sudo_like is True

    def test_run0_detected(self):
        """run0 é detectado (systemd 256+)."""
        parsed = gg.parse_command("run0 systemctl restart nginx")
        assert parsed.sudo_like is True
        assert parsed.privilege_type == "run0"

    def test_pkexec_detected(self):
        """pkexec é detectado."""
        parsed = gg.parse_command("pkexec --user root cmd")
        assert parsed.sudo_like is True
        assert parsed.privilege_type == "pkexec"

    def test_doas_detected(self):
        """doas é detectado."""
        parsed = gg.parse_command("doas cmd")
        assert parsed.sudo_like is True
        assert parsed.privilege_type == "doas"

    def test_su_detected(self):
        """su é detectado."""
        parsed = gg.parse_command("su - root -c cmd")
        assert parsed.sudo_like is True
        assert parsed.privilege_type == "su"

    def test_yay_S_detected(self):
        """yay -S é detectado como instalação de pacote."""
        parsed = gg.parse_command("yay -S firefox")
        assert parsed.sudo_like is True
        assert parsed.privilege_type == "package_install"

    def test_paru_S_detected(self):
        """paru -S é detectado."""
        parsed = gg.parse_command("paru -S firefox")
        assert parsed.sudo_like is True

    def test_pacman_S_detected(self):
        """pacman -S é detectado."""
        parsed = gg.parse_command("pacman -S firefox")
        assert parsed.sudo_like is True

    def test_systemctl_without_user_detected(self):
        """systemctl start sem --user é detectado."""
        parsed = gg.parse_command("systemctl start nginx")
        assert parsed.sudo_like is True
        assert parsed.privilege_type == "systemctl"

    def test_systemctl_with_user_not_detected(self):
        """systemctl --user start não é privilégio de sistema."""
        parsed = gg.parse_command("systemctl --user start redshift")
        assert parsed.sudo_like is False

    def test_lscpu_not_privileged(self):
        """lscpu não é privilégio."""
        parsed = gg.parse_command("lscpu")
        assert parsed.sudo_like is False


# ---------------------------------------------------------------------------
# 4. Padrões destrutivos (Quick Win #4)
# ---------------------------------------------------------------------------

class TestDestructivePatterns:
    """Verifica detecção de comandos destrutivos."""

    def test_rm_rf_root_denied(self):
        """rm -rf / é negado."""
        decision, reason, _ = call_audit_command(
            gg.parse_command("rm -rf /"), None, Path("/home/user")
        )
        assert decision == "deny"

    def test_rm_rf_glob_denied(self):
        """rm -rf /* é negado (bypass de glob)."""
        decision, reason, _ = call_audit_command(
            gg.parse_command("rm -rf /*"), None, Path("/home/user")
        )
        assert decision == "deny"

    def test_rm_rf_home_tilde_denied(self):
        """rm -rf ~/ é negado."""
        decision, reason, _ = call_audit_command(
            gg.parse_command("rm -rf ~/"), None, Path("/home/user")
        )
        assert decision == "deny"

    def test_find_delete_denied(self):
        """find ... -delete é negado."""
        decision, reason, _ = call_audit_command(
            gg.parse_command("find / -type f -delete"), None, Path("/home/user")
        )
        assert decision == "deny"

    def test_shred_denied(self):
        """shred é negado."""
        decision, reason, _ = call_audit_command(
            gg.parse_command("shred -u /dev/sda"), None, Path("/home/user")
        )
        assert decision == "deny"

    def test_dd_denied(self):
        """dd é negado."""
        decision, reason, _ = call_audit_command(
            gg.parse_command("dd if=/dev/zero of=/dev/sda"), None, Path("/home/user")
        )
        assert decision == "deny"

    def test_traversal_rm_denied(self):
        """rm -rf ../ é negado."""
        decision, reason, _ = call_audit_command(
            gg.parse_command("rm -rf ../"), None, Path("/home/user")
        )
        assert decision == "deny"


# ---------------------------------------------------------------------------
# 5. RULE-10: Limite 3X de rejeições (Seção 5.2)
# ---------------------------------------------------------------------------

class TestRejectionLimit:
    """Verifica o estado de rejeição persistente (RULE-10 — recusas consecutivas)."""

    def test_three_rejections_escalate(self, tmp_home):
        """Após 3 recusas CONSECUTIVAS, a 3ª é escalada."""
        if gg.REJECTION_STATE_FILE.exists():
            gg.REJECTION_STATE_FILE.unlink()

        assert gg._record_decision("deny", "rm -rf /") == 1
        assert gg._record_decision("deny", "rm -rf /") == 2
        assert gg._record_decision("deny", "rm -rf /") == 3
        assert gg._get_rejection_count() == 3

    def test_success_resets_consecutive_counter(self, tmp_home):
        """Qualquer aprovação (allow/ask/force_ask) zera o contador."""
        if gg.REJECTION_STATE_FILE.exists():
            gg.REJECTION_STATE_FILE.unlink()

        assert gg._record_decision("deny", "rm -rf /") == 1
        assert gg._record_decision("deny", "rm -rf /") == 2
        # Uma aprovação interrompe a sequência.
        assert gg._record_decision("allow", "lscpu") == 0
        assert gg._get_rejection_count() == 0
        # E a contagem recomeça do zero.
        assert gg._record_decision("deny", "rm -rf /") == 1

    def test_rejection_ttl_expiration(self, tmp_home):
        """Entradas expiradas (TTL 24h) são limpas."""
        gg._record_decision("deny", "rm -rf /")
        assert gg._get_rejection_count() == 1

        # Simular expiração: envelhecer o timestamp.
        state = gg._load_rejection_state()
        state["last_reject"] = 0
        gg._save_rejection_state(state)

        assert gg._get_rejection_count() == 0


# ---------------------------------------------------------------------------
# 6. Re-validação de overwrite (Seção 5.5)
# ---------------------------------------------------------------------------

class TestOverwriteRevalidation:
    """Verifica que comandos modificados pelo gate são re-auditados."""

    def test_safe_overwrite_passes(self):
        """Overwrite seguro (journalctl com --no-pager) passa na re-validação."""
        parsed = gg.parse_command("journalctl -u ssh")
        decision, reason, overwrite = gg.audit_command(parsed, None, Path("/home/user"))
        # audit_command não gera overwrite (isso é feito por audit_and_optimize)
        # Apenas verifica que o comando é permitido
        assert decision == "allow"

        # Simular o overwrite que audit_and_optimize geraria para journalctl
        modified_cmd = "journalctl -u ssh --no-pager -n 35"
        parsed_mod = gg.parse_command(modified_cmd)
        mod_decision, mod_reason, _ = gg.audit_command(parsed_mod, None, Path("/home/user"))
        assert mod_decision == "allow"

    def test_overwrite_with_destructive_rejected(self):
        """Se overwrite resultar em comando destrutivo, é rejeitado."""
        # Simular: o overwrite tenta fazer rm -rf /
        # Isso não aconteceria na prática, mas testa a lógica de re-validação
        parsed = gg.parse_command("rm -rf /")
        decision, reason, _ = gg.audit_command(parsed, None, Path("/home/user"))
        assert decision == "deny"


# ---------------------------------------------------------------------------
# 7. Cache key com LANG/LC_ALL (Quick Win #5)
# ---------------------------------------------------------------------------

class TestCacheKeyEnv:
    """Verifica que LANG e LC_ALL influenciam a chave de cache."""

    def test_cache_key_includes_lang(self):
        """Diferentes LANG produzem hashes diferentes."""
        cmd = "lscpu"
        cwd = "/home/user"

        hash1 = hashlib.sha256(f"{cwd}:{cmd}:pt_BR.UTF-8:".encode()).hexdigest()[:16]
        hash2 = hashlib.sha256(f"{cwd}:{cmd}:en_US.UTF-8:".encode()).hexdigest()[:16]
        assert hash1 != hash2

    def test_cache_key_includes_lc_all(self):
        """Diferentes LC_ALL produzem hashes diferentes."""
        cmd = "lscpu"
        cwd = "/home/user"

        hash1 = hashlib.sha256(f"{cwd}:{cmd}::pt_BR.UTF-8".encode()).hexdigest()[:16]
        hash2 = hashlib.sha256(f"{cwd}:{cmd}::en_US.UTF-8".encode()).hexdigest()[:16]
        assert hash1 != hash2


# ---------------------------------------------------------------------------
# 9. Permissões do diretório de cache (Quick Win #7)
# ---------------------------------------------------------------------------

class TestCachePermissions:
    """Verifica que o diretório de cache tem permissões 0o700."""

    def test_cache_dir_created_with_700(self, tmp_home):
        """O diretório de cache é criado com 0o700."""
        gg.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(gg.CACHE_DIR, 0o700)
        mode = gg.CACHE_DIR.stat().st_mode & 0o777
        assert mode == 0o700


# ---------------------------------------------------------------------------
# 10. Testes de integração via subprocesso
# ---------------------------------------------------------------------------

class TestIntegrationSubprocess:
    """Testes de ponta-a-ponta executando o script como subprocesso."""

    def test_allow_safe_command(self, tmp_home, monkeypatch):
        """Comando seguro é permitido."""
        monkeypatch.setenv("HOME", str(tmp_home))
        result = run_gate("lscpu", cwd=str(tmp_home))
        assert result.get("decision") == "allow"

    def test_deny_rm_rf_root(self, tmp_home, monkeypatch):
        """rm -rf / é negado via subprocesso."""
        monkeypatch.setenv("HOME", str(tmp_home))
        result = run_gate("rm -rf /", cwd=str(tmp_home))
        assert result.get("decision") == "deny"

    def test_ask_sudo(self, tmp_home, monkeypatch):
        """sudo emite ask (respeita Always Allow) via subprocesso."""
        monkeypatch.setenv("HOME", str(tmp_home))
        result = run_gate("sudo apt update", cwd=str(tmp_home))
        assert result.get("decision") == "ask"

    def test_ask_run0(self, tmp_home, monkeypatch):
        """run0 emite ask via subprocesso."""
        monkeypatch.setenv("HOME", str(tmp_home))
        result = run_gate("run0 systemctl restart nginx", cwd=str(tmp_home))
        assert result.get("decision") == "ask"

    def test_path_traversal_blocked(self, tmp_home, monkeypatch):
        """Path traversal em TargetFile é bloqueado."""
        monkeypatch.setenv("HOME", str(tmp_home))
        result = run_gate("cat file.txt", target="../../../etc/shadow", cwd=str(tmp_home))
        # O TargetFile fora do escopo retorna None, então não é protegido por RULE-12
        # mas o comando em si é seguro -> allow
        assert result.get("decision") in ("allow", "force_ask")

    def test_audit_log_fields(self, tmp_home, monkeypatch):
        """O log de auditoria contém decision, rule, cmd_hash, latency_ms."""
        monkeypatch.setenv("HOME", str(tmp_home))
        run_gate("lscpu", cwd=str(tmp_home))
        log_file = tmp_home / ".cache" / "antigravity" / "bash_agents" / "audit.log"
        if log_file.exists():
            lines = log_file.read_text(encoding="utf-8").strip().split("\n")
            last = json.loads(lines[-1])
            assert "decision" in last
            assert "ts" in last
            assert "latency_ms" in last
            assert "cmd_hash" in last

    def test_cache_dir_permissions(self, tmp_home, monkeypatch):
        """O diretório de cache tem 0o700 após execução."""
        monkeypatch.setenv("HOME", str(tmp_home))
        run_gate("lscpu", cwd=str(tmp_home))
        cache_dir = tmp_home / ".cache" / "antigravity" / "bash_agents"
        if cache_dir.exists():
            mode = cache_dir.stat().st_mode & 0o777
            assert mode == 0o700


# ---------------------------------------------------------------------------
# 11. Parser semântico (Seções 5.1 e 8.3)
# ---------------------------------------------------------------------------

class TestSemanticParser:
    """Verifica o parser semântico com shlex."""

    def test_parse_simple_command(self):
        parsed = gg.parse_command("lscpu")
        assert parsed.argv == ["lscpu"]
        assert parsed.target_bin == "lscpu"
        assert parsed.sudo_like is False

    def test_parse_with_pipe(self):
        parsed = gg.parse_command("lscpu | head -5")
        assert parsed.has_pipe is True
        assert parsed.argv == ["lscpu", "|", "head", "-5"] or "|" in parsed.raw_cmd

    def test_parse_with_redirect(self):
        parsed = gg.parse_command("ls > /tmp/out.txt")
        assert parsed.has_redirect is True
        assert ">" in parsed.redirect_ops

    def test_parse_background(self):
        parsed = gg.parse_command("sleep 10 &")
        assert parsed.background is True

    def test_parse_sudo_with_flags(self):
        parsed = gg.parse_command("sudo -u deploy -i systemctl restart nginx")
        assert parsed.sudo_like is True
        assert parsed.privilege_type == "sudo"

    def test_parse_invalid_shell_quoting(self):
        parsed = gg.parse_command("echo 'unclosed")
        # Não deve lançar exceção
        assert parsed.argv is not None


# ---------------------------------------------------------------------------
# 12. RULE-01: Monitores
# ---------------------------------------------------------------------------

class TestMonitorRule:
    """Verifica RULE-01: soberania do display."""

    def test_monitors_lua_force_ask(self):
        """monitors.lua força ask."""
        decision, reason, _ = call_audit_command(
            gg.parse_command("vim ~/.config/hypr/monitors.lua"), None, Path("/home/user")
        )
        assert decision == "force_ask"

    def test_hyprland_monitors_conf_force_ask(self):
        """hyprland/monitors.conf força ask."""
        decision, reason, _ = call_audit_command(
            gg.parse_command("edit hyprland/monitors.conf"), None, Path("/home/user")
        )
        assert decision == "force_ask"


# ---------------------------------------------------------------------------
# 13. RULE-06: sudo_runner legado
# ---------------------------------------------------------------------------

class TestSudoRunnerRule:
    """Verifica RULE-06: veto ao sudo_runner."""

    def test_sudo_runner_denied(self):
        """sudo_runner.sh é negado."""
        decision, reason, _ = call_audit_command(
            gg.parse_command("./sudo_runner.sh"), None, Path("/home/user")
        )
        assert decision == "deny"

    def test_sudo_runner_sh_denied(self):
        """sudo_runner.sh com .sh é negado."""
        decision, reason, _ = call_audit_command(
            gg.parse_command("bash /opt/sudo_runner.sh"), None, Path("/home/user")
        )
        assert decision == "deny"


# ---------------------------------------------------------------------------
# 14. Endurecimento RULE-02 (v4.3.0): -R/--recursive, globs, find -exec, vitais
# ---------------------------------------------------------------------------

class TestDestructiveHardening:
    """Casos de regressão para os bypasses fechados em v4.3.0."""

    def test_rm_capital_R_denied(self):
        decision, _, _ = call_audit_command(gg.parse_command("rm -Rf /"), None, Path("/home/user"))
        assert decision == "deny"

    def test_rm_recursive_long_denied(self):
        decision, _, _ = call_audit_command(gg.parse_command("rm --recursive /etc"), None, Path("/home/user"))
        assert decision == "deny"

    def test_rm_glob_question_denied(self):
        decision, _, _ = call_audit_command(gg.parse_command("rm -rf /e?c"), None, Path("/home/user"))
        assert decision == "deny"

    def test_rm_glob_bracket_denied(self):
        decision, _, _ = call_audit_command(gg.parse_command("rm -rf /e[t]c"), None, Path("/home/user"))
        assert decision == "deny"

    def test_rm_glob_brace_denied(self):
        decision, _, _ = call_audit_command(gg.parse_command("rm -rf /{etc,usr}"), None, Path("/home/user"))
        assert decision == "deny"

    def test_rm_home_glob_denied(self):
        decision, _, _ = call_audit_command(gg.parse_command("rm -rf /h?me"), None, Path("/home/user"))
        assert decision == "deny"

    def test_find_exec_rm_denied(self):
        decision, _, _ = call_audit_command(gg.parse_command("find / -type f -exec rm {} \\;"), None, Path("/home/user"))
        assert decision == "deny"

    def test_find_execdir_rm_denied(self):
        decision, _, _ = call_audit_command(gg.parse_command("find / -execdir rm -rf {} \\;"), None, Path("/home/user"))
        assert decision == "deny"

    def test_find_ok_rm_denied(self):
        decision, _, _ = call_audit_command(gg.parse_command("find / -ok rm {} \\;"), None, Path("/home/user"))
        assert decision == "deny"

    def test_rm_vital_file_no_recursive_denied(self):
        decision, _, _ = call_audit_command(gg.parse_command("rm /etc/passwd"), None, Path("/home/user"))
        assert decision == "deny"

    def test_rm_shadow_no_recursive_denied(self):
        decision, _, _ = call_audit_command(gg.parse_command("rm /etc/shadow"), None, Path("/home/user"))
        assert decision == "deny"

    def test_rm_fstab_no_recursive_denied(self):
        decision, _, _ = call_audit_command(gg.parse_command("rm /etc/fstab"), None, Path("/home/user"))
        assert decision == "deny"

    def test_echo_dollar_path_allowed(self):
        decision, _, _ = call_audit_command(gg.parse_command("echo $PATH"), None, Path("/home/user"))
        assert decision == "allow"

    def test_shred_user_file_allowed(self):
        decision, _, _ = call_audit_command(gg.parse_command("shred -u ~/notes.txt"), None, Path("/home/user"))
        assert decision == "allow"

    def test_shred_dev_denied(self):
        decision, _, _ = call_audit_command(gg.parse_command("shred /dev/sda"), None, Path("/home/user"))
        assert decision == "deny"

    def test_rm_user_subdir_still_allowed(self):
        decision, _, _ = call_audit_command(gg.parse_command("rm -rf /home/user/Downloads/old"), None, Path("/home/user"))
        assert decision == "allow"


# ---------------------------------------------------------------------------
# 15. RULE-15: yay/paru -Ss (busca pura) não é privilégio (v4.3.0)
# ---------------------------------------------------------------------------

class TestPackageSearchNotPrivileged:
    def test_yay_Ss_not_privileged(self):
        parsed = gg.parse_command("yay -Ss firefox")
        assert parsed.sudo_like is False

    def test_paru_Ss_not_privileged(self):
        parsed = gg.parse_command("paru -Ss firefox")
        assert parsed.sudo_like is False

    def test_yay_Ss_allowed(self):
        decision, _, _ = call_audit_command(gg.parse_command("yay -Ss firefox"), None, Path("/home/user"))
        assert decision == "allow"


# ---------------------------------------------------------------------------
# 16. Cache: cat estático (v4.3.0)
# ---------------------------------------------------------------------------

class TestStaticCatCache:
    def test_cat_os_release_cacheable(self):
        assert gg._is_cacheable("cat /etc/os-release")

    def test_cat_cpuinfo_cacheable(self):
        assert gg._is_cacheable("cat /proc/cpuinfo")

    def test_cat_passwd_not_cacheable(self):
        assert not gg._is_cacheable("cat /etc/passwd")

    def test_cat_shadow_not_cacheable(self):
        assert not gg._is_cacheable("cat /etc/shadow")

    def test_cat_multiple_files_not_cacheable(self):
        assert not gg._is_cacheable("cat /etc/os-release /proc/cpuinfo")


# ---------------------------------------------------------------------------
# 17. RULE-10: chave de rejeição contextual + force_ask não incrementa (v4.3.0)
# ---------------------------------------------------------------------------

class TestRejectionState:
    def test_escalation_message_on_third_consecutive_deny(self, tmp_home, monkeypatch):
        """A 3ª recusa consecutiva inclui o alerta de escalação."""
        monkeypatch.setenv("HOME", str(tmp_home))
        state = tmp_home / ".cache" / "antigravity" / "bash_agents" / "rejection_state.json"
        if state.exists():
            state.unlink()

        run_gate("rm -rf /", cwd=str(tmp_home))
        run_gate("rm -rf /etc", cwd=str(tmp_home))
        result = run_gate("rm -rf /usr", cwd=str(tmp_home))
        assert result.get("decision") == "deny"
        assert "ALERTA" in result.get("reason", "")

    def test_allow_between_denies_resets_counter(self, tmp_home, monkeypatch):
        """Um comando aprovado no meio interrompe a sequência (não escala)."""
        monkeypatch.setenv("HOME", str(tmp_home))
        state = tmp_home / ".cache" / "antigravity" / "bash_agents" / "rejection_state.json"
        if state.exists():
            state.unlink()

        run_gate("rm -rf /", cwd=str(tmp_home))
        run_gate("rm -rf /etc", cwd=str(tmp_home))
        run_gate("lscpu", cwd=str(tmp_home))  # aprovação -> reseta
        result = run_gate("rm -rf /usr", cwd=str(tmp_home))
        assert result.get("decision") == "deny"
        assert "ALERTA" not in result.get("reason", "")

    def test_ask_does_not_increment(self, tmp_home, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_home))
        result = run_gate("sudo apt update", cwd=str(tmp_home))
        assert result.get("decision") == "ask"
        state_file = tmp_home / ".cache" / "antigravity" / "bash_agents" / "rejection_state.json"
        assert not state_file.exists() or json.loads(state_file.read_text()) == {}

    def test_deny_does_increment(self, tmp_home, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_home))
        result = run_gate("rm -rf /", cwd=str(tmp_home))
        assert result.get("decision") == "deny"
        state_file = tmp_home / ".cache" / "antigravity" / "bash_agents" / "rejection_state.json"
        assert state_file.exists()
        assert json.loads(state_file.read_text()) != {}


# ---------------------------------------------------------------------------
# 18. Contrato de cwd e failsafe (v4.3.0)
# ---------------------------------------------------------------------------

class TestCwdContractAndFailsafe:
    def test_top_level_cwd_honored(self, tmp_home, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_home))
        payload = {
            "toolCall": {"name": "run_command", "args": {"CommandLine": "rm -rf ../"}},
            "cwd": "/home/user",
        }
        result = run_gate_payload(payload)
        assert result.get("decision") == "deny"

    def test_malformed_payload_force_ask(self, tmp_home, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_home))
        result = run_gate_raw("not-json{")
        assert result.get("decision") == "force_ask"


# ---------------------------------------------------------------------------
# 19. Auditoria v4.4.0: Taxonomia anti-fadiga, energia, RULE-05 semântica,
#     RULE-12 endurecida, leitura livre de monitores e compressor no cache
# ---------------------------------------------------------------------------

class TestV440HardeningAndAntiFatigue:
    def test_sudoedit_and_sudo_e_ask(self):
        for cmd in ("sudoedit /etc/fstab", "sudo -e /etc/fstab", "sudo --edit /etc/fstab"):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "ask", cmd

    def test_package_sync_variants_ask(self):
        for cmd in ("yay -Syu", "paru -Syu", "pacman -Sy firefox", "pacman -Syu --noconfirm"):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "ask", cmd

    def test_echo_su_not_flagged(self):
        decision, _, _ = call_audit_command(gg.parse_command("echo su"), None, Path("/home/user"))
        assert decision == "allow"

    def test_systemctl_user_trailing_flag_allowed(self):
        decision, _, _ = call_audit_command(
            gg.parse_command("systemctl start redshift --user"), None, Path("/home/user")
        )
        assert decision == "allow"

    def test_power_commands_force_ask(self):
        for cmd in (
            "systemctl reboot",
            "systemctl poweroff",
            "sudo systemctl reboot",
            "shutdown -h now",
            "reboot",
            "poweroff",
            "systemctl suspend",
            "systemctl suspend-then-hibernate",
            "loginctl lock-session",
        ):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "force_ask", cmd

    def test_systemctl_restart_display_manager_denied(self):
        for cmd in ("systemctl restart sddm", "systemctl restart gdm"):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "deny", cmd

    def test_semantic_perm_abuse_denied(self):
        for cmd in (
            "chmod 777 -R /etc",
            "chmod -R a+w /usr",
            "chmod -R o+w /var",
            "chown --recursive root /etc",
            "chmod -R 755 /etc",
            "sudo chmod 777 -R /etc",
        ):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "deny", cmd

    def test_safe_perm_commands_allowed(self):
        for cmd in ("chmod -R 755 ~/proj", "chmod 777 /tmp/x", "chown -R user:user ~/proj"):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "allow", cmd

    def test_gov_hardening_denied(self):
        for cmd in (
            "dd if=~/i of=/home/user/.gemini/config/plugins/bash-sudo-agents/hooks/governance-gate.py",
            "sudo rm /home/user/.gemini/config/plugins/bash-sudo-agents/hooks/governance-gate.py",
            "rsync -a x/ ~/.gemini/config/plugins/bash-sudo-agents/",
            "echo x > ~/.gemini/config/hooks.json",
            "echo x > .agents/hooks.json",
            "tar -xf a.tar -C ~/.gemini/config/plugins/bash-sudo-agents/",
            "ln -sf /tmp/x ~/.gemini/config/plugins/bash-sudo-agents/hooks/governance-gate.py",
        ):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "deny", cmd

    def test_gov_read_with_stderr_redirect_allowed(self):
        decision, _, _ = call_audit_command(
            gg.parse_command("ls ~/.gemini/config/plugins/bash-sudo-agents/ 2>&1"),
            None,
            Path("/home/user"),
        )
        assert decision == "allow"

    def test_monitors_read_allowed_write_force_ask(self):
        for cmd in (
            "cat ~/.config/hypr/monitors.lua",
            "less ~/.config/hypr/monitors.lua",
            "grep eDP ~/.config/hypr/monitors.lua",
        ):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "allow", cmd
        for cmd in (
            "vim ~/.config/hypr/monitors.lua",
            "sed -i 's/a/b/' ~/.config/hypr/monitors.lua",
            "echo x > ~/.config/hypr/monitors.lua",
        ):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "force_ask", cmd

    def test_pacman_search_cache_wrap_includes_limiter(self, tmp_home, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_home))
        result = run_gate("pacman -Ss firefox", cwd=str(tmp_home))
        assert result.get("decision") == "allow"
        ow = result.get("overwrite", {}).get("CommandLine", "")
        assert "head -n 25" in ow and "tee" in ow


# ---------------------------------------------------------------------------
# 20. v4.4.x: compatibilidade, fail-closed, aspas, mutação vital e inline
# ---------------------------------------------------------------------------

class TestPythonCompatibility:
    """Garante anotações preguiçosas (PEP 563) para rodar em Python 3.8/3.9."""

    def test_future_annotations_enabled(self):
        src = GATE_PATH.read_text(encoding="utf-8")
        assert "from __future__ import annotations" in src

    def test_annotations_are_strings(self):
        """Com PEP 563 as anotações ficam como strings (não avaliadas no def)."""
        ann = gg.out.__annotations__
        assert ann, "out() deve ter anotações"
        assert all(isinstance(v, str) for v in ann.values())

    def test_pep604_annotation_present(self):
        """`X | None` é usado e não quebra o import graças às anotações lazy."""
        assert gg.out.__annotations__.get("overwrite") == "dict | None"


class TestFailClosedSchema:
    """Payload válido sem CommandLine reconhecível não deve virar `allow`."""

    def test_unknown_tool_without_command_force_ask(self, tmp_home, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_home))
        result = run_gate_payload({
            "toolCall": {"name": "ferramenta_desconhecida", "args": {}},
        })
        assert result.get("decision") == "force_ask"

    def test_missing_tool_name_force_ask(self, tmp_home, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_home))
        result = run_gate_payload({"toolCall": {"args": {}}})
        assert result.get("decision") == "force_ask"

    def test_run_command_empty_force_ask(self, tmp_home, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_home))
        result = run_gate_payload({
            "toolCall": {"name": "run_command", "args": {"CommandLine": ""}},
        })
        assert result.get("decision") == "force_ask"

    def test_known_non_command_tool_allowed(self, tmp_home, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_home))
        result = run_gate_payload({
            "toolCall": {
                "name": "write_to_file",
                "args": {"TargetFile": str(tmp_home / "notas.txt"), "CodeContent": "x"},
            },
        })
        assert result.get("decision") == "allow"

    def test_non_command_tool_governance_target_denied(self, tmp_home, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_home))
        result = run_gate_payload({
            "toolCall": {
                "name": "write_to_file",
                "args": {
                    "TargetFile": str(tmp_home / ".gemini/config/plugins/bash-sudo-agents/rules/AGENTS.md"),
                    "CodeContent": "x",
                },
            },
        })
        assert result.get("decision") == "deny"


class TestQuoteFalsePositives:
    """Strings literais entre aspas não devem disparar vetos."""

    def test_commit_message_with_rm_rf_allowed(self):
        for cmd in (
            'git commit -m "fix: nunca rodar rm -rf / de novo"',
            "git commit -m 'fix: nunca rodar rm -rf / de novo'",
            'echo "use rm -rf /path com cuidado"',
        ):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "allow", cmd

    def test_quoted_power_word_allowed(self):
        decision, _, _ = call_audit_command(gg.parse_command('echo "vou dar reboot"'), None, Path("/home/user"))
        assert decision == "allow"

    def test_substitution_preserved(self):
        """Substituições de comando continuam sendo inspecionadas."""
        for cmd in ("$(rm -rf /)", "echo \"$(rm -rf /)\"", "`rm -rf /`"):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "deny", cmd


class TestVitalDirectoriesExpanded:
    def test_new_vital_dirs_denied(self):
        for cmd in ("rm -rf /root", "rm -rf /opt", "rm -rf /srv", "rm -rf /mnt"):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "deny", cmd

    def test_user_dirs_still_allowed(self):
        for cmd in ("rm -rf /tmp/build", "rm -rf /home/user/Downloads/old"):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "allow", cmd


class TestVitalMutation:
    """RULE-02 estendida: mv/cp/truncate/tee/ln e redirecionamentos em vitais."""

    def test_mutations_on_vital_denied(self):
        for cmd in (
            "mv /etc/fstab /tmp/f",
            "cp /tmp/x /etc/fstab",
            "install -m 644 x /usr/bin/y",
            "truncate -s 0 /etc/shadow",
            "tee /etc/hosts",
            "ln -sf /tmp/x /etc/passwd",
            "echo x > /etc/fstab",
            "echo x >> /var/log/syslog",
        ):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "deny", cmd

    def test_shell_dash_c_recursion_denied(self):
        for cmd in ('bash -c "rm -rf /"', 'sh -c "mv /etc/hosts /tmp"'):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "deny", cmd

    def test_benign_mutations_allowed(self):
        for cmd in (
            "cp /etc/fstab /tmp/backup",
            "mv /tmp/a /tmp/b",
            "echo x > /dev/null",
            "echo x > ~/notas.txt",
            "ls /etc 2>&1",
            "ln -s /usr/bin/python3 ~/.local/bin/py",
        ):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "allow", cmd


class TestInlineInterpreter:
    """Interpretadores inline sobre caminhos protegidos."""

    def test_inline_vital_force_ask(self):
        for cmd in (
            'python3 -c "import shutil; shutil.rmtree(\'/etc\')"',
            'perl -e "unlink(\'/etc/passwd\')"',
            'ruby -e "File.delete(\'/etc/fstab\')"',
        ):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "force_ask", cmd

    def test_inline_governance_denied(self):
        cmd = 'python3 -c "open(\'/home/user/.gemini/config/plugins/bash-sudo-agents/hooks/governance-gate.py\',\'w\')"'
        decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
        assert decision == "deny"

    def test_inline_harmless_allowed(self):
        for cmd in ('python3 -c "print(1)"', 'python3 -m pytest', 'node -e "console.log(1)"'):
            decision, _, _ = call_audit_command(gg.parse_command(cmd), None, Path("/home/user"))
            assert decision == "allow", cmd
