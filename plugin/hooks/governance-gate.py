#!/usr/bin/env python3
"""
governance-gate.py — Antigravity Linux Governance Engine (v4.0)
Arquitetura Multi-Agente: @agente-bash, @agente-sudo, @agente-sudo-policy, @agente-meta.
Recursos:
  1. Auditoria e Firewall Constitucional (RULE-01 a RULE-15)
  2. Auto-Compressor Sintático de Tokens (overwrite com blindagem de sintaxe)
  3. Cache Local de Saídas com TTL
  4. Failsafe Universal (Zero Downtime)
Zero dependências externas (estritamente Python 3.8+ Standard Library).
"""

import sys
import json
import os
import re
import shlex
import hashlib
import time
from pathlib import Path


def out(decision: str, reason: str = "", overwrite: dict = None):
    res = {"decision": decision, "reason": reason}
    if overwrite:
        res["overwrite"] = overwrite
    print(json.dumps(res, ensure_ascii=False))
    sys.exit(0)


def audit_and_optimize():
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            out("allow", "")
        data = json.loads(raw_input)
    except Exception as e:
        out("allow", f"Failsafe: payload inválido ({str(e)})")

    args = data.get("toolCall", {}).get("args", {})
    cmd = args.get("CommandLine", "").strip()
    target = args.get("TargetFile", "").strip()
    cwd = args.get("Cwd", str(Path.home()))

    # =========================================================================
    # 1. AUDITORIA CONSTITUCIONAL DE SEGURANÇA (PRETOOLUSE GATE)
    # =========================================================================

    # RULE-06: Veto irreversível ao sudo_runner legado
    if "sudo_runner" in cmd:
        out("deny", "sudo_runner.sh foi descontinuado. Utilize o fluxo nativo ou NOPASSWD configurado.")

    # RULE-02: Veto sumário anti-destruição em diretórios vitais do sistema
    DESTRUCTIVE_PATTERN = re.compile(
        r'(^|[;&|[:space:]])rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(/(boot|etc|usr|var|sys|proc|dev)?(/)?(\s|$)|~(\s|$))'
    )
    if DESTRUCTIVE_PATTERN.search(cmd):
        out(
            "deny",
            "[@agente-sudo / RULE-02] Veto sumário: remoção recursiva na raiz (/) ou em diretórios vitais do sistema é terminantemente proibida."
        )

    # RULE-01: Soberania do Display e monitores.lua
    MONITOR_PATTERN = re.compile(r'monitors\.lua|hyprland/.*monitors?\.conf')
    if MONITOR_PATTERN.search(cmd) or MONITOR_PATTERN.search(target):
        out(
            "force_ask",
            "[@agente-sudo / RULE-01] Alteração em configuração de monitores detectada (monitors.lua). Confirme apenas se solicitou expressamente."
        )

    # RULE-15: Taxonomia de Comandos com Privilégios Elevados
    PRIV_PATTERN = re.compile(
        r'(^|[;&|(`\s])(sudo|doas|pkexec|su)(\s|$)|(^|[;&|\s])(yay|paru)\s+-S'
    )
    if PRIV_PATTERN.search(cmd):
        out(
            "force_ask",
            "[@agente-sudo / RULE-15] Comando com privilégios de superusuário detectado. Confirme se atende estritamente à sua demanda."
        )

    # RULE-11 e RULE-12: Proteção da Infraestrutura de Governança
    GOV_PATTERN = re.compile(r'plugins/bash-sudo-agents/|scratch/security/|\.gemini/config/config\.json')
    WRITE_OPS_PATTERN = re.compile(
        r'(>|tee|sed\s+-i|chmod|chown|chattr|rm|mv|cp|install|shred)'
    )
    if target and GOV_PATTERN.search(target):
        out(
            "force_ask",
            "[@agente-meta / RULE-12] Escrita em arquivo de governança detectada. Confirme se você solicitou a alteração ao @agente-sudo-policy."
        )
    if GOV_PATTERN.search(cmd) and WRITE_OPS_PATTERN.search(cmd):
        out(
            "force_ask",
            "[@agente-meta / RULE-12] Comando tenta modificar arquivo de governança. Confirme se solicitou ao @agente-sudo-policy."
        )

    if not cmd:
        out("allow", "")

    # =========================================================================
    # 2. CACHE LOCAL DE SAÍDAS COM TTL (ECONOMIA DE TOKENS E PROCESSAMENTO)
    # =========================================================================
    cache_dir = Path.home() / ".cache" / "antigravity" / "bash_agents"
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    CACHE_RULES = [
        # Comandos estáticos de hardware/distro: TTL = 1 hora (3600s)
        (re.compile(r'^(lscpu|uname(\s+-[a-zA-Z]+)?|lspci|lsusb|cat\s+/etc/os-release|cat\s+/proc/cpuinfo)$'), 3600),
        # Buscas em repositórios de pacotes: TTL = 10 minutos (600s)
        (re.compile(r'^(pacman|yay|paru)\s+-Ss\s+'), 600),
    ]

    ttl = 0
    for pattern, rule_ttl in CACHE_RULES:
        if pattern.search(cmd):
            ttl = rule_ttl
            break

    cmd_hash = hashlib.sha256(f"{cwd}:{cmd}".encode("utf-8")).hexdigest()[:16]
    cache_file = cache_dir / f"{cmd_hash}.cache"

    if ttl > 0:
        if cache_file.exists():
            try:
                mtime = cache_file.stat().st_mtime
                if (time.time() - mtime) < ttl and cache_file.stat().st_size > 0:
                    out("allow", "", overwrite={"CommandLine": f"cat {shlex.quote(str(cache_file))}"})
            except Exception:
                pass

        if ">" not in cmd and "|" not in cmd:
            wrapped_cmd = f"( {cmd} ) | tee {shlex.quote(str(cache_file))}"
            out("allow", "", overwrite={"CommandLine": wrapped_cmd})

    # =========================================================================
    # 3. AUTO-COMPRESSOR SINTÁTICO DE TERMINAL (OVERWRITE INTELIGENTE)
    # =========================================================================
    has_redirect = bool(re.search(r'[>|&]', cmd))

    if not has_redirect:
        if cmd.startswith("journalctl") and not re.search(r'(-n\s*\d+|--lines(=|\s*)\d+)', cmd):
            out("allow", "", overwrite={"CommandLine": f"{cmd} --no-pager -n 35"})
        elif cmd.startswith("dmesg") and not re.search(r'(tail|head)', cmd):
            out("allow", "", overwrite={"CommandLine": f"{cmd} --color=never | tail -n 35"})
        elif cmd.startswith("git log") and not re.search(r'(-\d+|-n\s*\d+)', cmd):
            out("allow", "", overwrite={"CommandLine": f"{cmd} -n 15"})
        elif re.match(r'^(pacman|yay|paru)\s+-Ss\s+', cmd):
            out("allow", "", overwrite={"CommandLine": f"{cmd} | head -n 25"})

    out("allow", "")


def main():
    try:
        audit_and_optimize()
    except Exception as e:
        try:
            with open("/tmp/governance_failsafe.log", "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Failsafe: {str(e)}\n")
        except Exception:
            pass
        out("allow", f"Failsafe: {str(e)}")


if __name__ == "__main__":
    main()
