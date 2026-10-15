#!/usr/bin/env python3
"""
verify_fixes.py — verificação standalone das correções no governance-gate.py.
Executa o motor como subprocesso com payloads no stdin (mesmo contrato do hook)
e valida as decisões esperadas. Sem dependência de pytest.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

GATE = Path(__file__).resolve().parent.parent / "plugin" / "hooks" / "governance-gate.py"


def run_gate(cmd, target="", cwd=None, env=None):
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
    full_env = dict(__import__("os").environ)
    if env:
        full_env.update(env)
    r = subprocess.run(
        [sys.executable, str(GATE)],
        input=json.dumps(payload),
        capture_output=True, text=True, timeout=10, env=full_env,
    )
    try:
        return json.loads(r.stdout.strip())
    except json.JSONDecodeError:
        return {"decision": "ERROR", "stdout": r.stdout, "stderr": r.stderr}


def check(name, cmd, expected, **kw):
    result = run_gate(cmd, **kw)
    got = result.get("decision")
    ok = got == expected
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name:55s} esperado={expected!r:12s} obtido={got!r}")
    return ok


def main():
    with tempfile.TemporaryDirectory() as td:
        os = __import__("os")
        os.environ["HOME"] = td  # isola cache/estado em tmp

        results = []

        # --- RULE-02: destructive (deny) ---
        results += [check("rm -rf /", "rm -rf /", "deny")]
        results += [check("rm -rf /*", "rm -rf /*", "deny")]
        results += [check("rm -rf /etc/*", "rm -rf /etc/*", "deny")]
        results += [check("rm -rf --no-preserve-root /", "rm -rf --no-preserve-root /", "deny")]
        results += [check("sudo rm -rf /", "sudo rm -rf /", "deny")]
        results += [check("echo x; rm -rf /", "echo x; rm -rf /", "deny")]
        results += [check("cd / && rm -rf /usr", "cd / && rm -rf /usr", "deny")]
        results += [check("rm -rf ~/", "rm -rf ~/", "deny")]
        results += [check("rm -fr /", "rm -fr /", "deny")]
        results += [check("find / -type f -delete", "find / -type f -delete", "deny")]
        results += [check("shred -u /dev/sda", "shred -u /dev/sda", "deny")]
        results += [check("dd if=/dev/zero of=/dev/sda", "dd if=/dev/zero of=/dev/sda", "deny")]
        results += [check("rm -rf ../", "rm -rf ../", "deny")]
        results += [check("$(rm -rf /)", "$(rm -rf /)", "deny")]
        results += [check("`rm -rf /`", "`rm -rf /`", "deny")]
        results += [check("( rm -rf / )", "( rm -rf / )", "deny")]
        # não-destrutivo: remoção recursiva de subdir do usuário é permitida
        results += [check("rm -rf /home/user/Downloads/old", "rm -rf /home/user/Downloads/old", "allow")]
        results += [check("rm -rf ~/Downloads", "rm -rf ~/Downloads", "allow")]
        # Novos casos de regressão — bypasses C-1 e C-2 corrigidos
        results += [check("rm -rf ~/../../etc", "rm -rf ~/../../etc", "deny")]
        results += [check("sudo rm -rf /home/manoel", "sudo rm -rf /home/manoel", "deny")]

        # --- RULE-06: sudo_runner (deny) ---
        results += [check("./sudo_runner.sh", "./sudo_runner.sh", "deny")]
        results += [check("bash /opt/sudo_runner.sh", "bash /opt/sudo_runner.sh", "deny")]

        # --- RULE-07: serviços críticos (deny) ---
        results += [check("systemctl stop sddm", "systemctl stop sddm", "deny")]
        results += [check("pkill hyprland", "pkill hyprland", "deny")]
        results += [check("kill -9 1", "kill -9 1", "deny")]

        # --- RULE-05: permissões (deny) ---
        results += [check("chmod -R 777 /usr", "chmod -R 777 /usr", "deny")]
        results += [check("chown -R root /etc", "chown -R root /etc", "deny")]

        # --- RULE-01: monitores (force_ask) ---
        results += [check("vim ~/.config/hypr/monitors.lua", "vim ~/.config/hypr/monitors.lua", "force_ask")]

        # --- RULE-03: disco (force_ask) ---
        results += [check("mkfs.ext4 /dev/sdb1", "mkfs.ext4 /dev/sdb1", "force_ask")]
        results += [check("fdisk /dev/sdb", "fdisk /dev/sdb", "force_ask")]
        results += [check("mount /dev/sdb1 /mnt", "mount /dev/sdb1 /mnt", "force_ask")]

        # --- RULE-15: privilégios (force_ask) ---
        results += [check("sudo apt update", "sudo apt update", "force_ask")]
        results += [check("run0 systemctl restart nginx", "run0 systemctl restart nginx", "force_ask")]
        results += [check("yay -S firefox", "yay -S firefox", "force_ask")]

        # --- RULE-12: governança (deny absoluto em arquivos de governança) ---
        results += [check("chmod 777 ~/.gemini/config/plugins/bash-sudo-agents/AGENTS.md",
                          "chmod 777 ~/.gemini/config/plugins/bash-sudo-agents/AGENTS.md", "deny")]
        results += [check("rm ~/.gemini/config/plugins/bash-sudo-agents/hooks/governance-gate.py",
                          "rm ~/.gemini/config/plugins/bash-sudo-agents/hooks/governance-gate.py", "deny")]

        # --- Allow (comandos seguros) ---
        results += [check("lscpu", "lscpu", "allow")]
        results += [check("journalctl -u ssh", "journalctl -u ssh", "allow")]
        results += [check("cat /etc/os-release", "cat /etc/os-release", "allow")]
        results += [check("echo olá mundo", "echo olá mundo", "allow")]

        # --- Compressor não deve pendurar em follow ---
        r = run_gate("journalctl --follow")
        ow = r.get("overwrite", {})
        results += [r.get("decision") == "allow" and "--follow" in ow.get("CommandLine", "--follow")]
        print(f"[{'PASS' if results[-1] else 'FAIL'}] journalctl --follow não é comprimido para tail")

        r = run_gate("dmesg -w")
        ow = r.get("overwrite", {})
        results += [r.get("decision") == "allow" and "tail -n 35" not in ow.get("CommandLine", "")]
        print(f"[{'PASS' if results[-1] else 'FAIL'}] dmesg -w não é comprimido para tail")

        total = len(results)
        passed = sum(1 for x in results if x)
        print(f"\n{passed}/{total} verificações passaram.")
        sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
