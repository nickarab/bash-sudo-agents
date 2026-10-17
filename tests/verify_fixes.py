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
        results += [check("rm -rf /home/user/Downloads/old", "rm -rf /home/user/Downloads/old", "auto_approve")]
        results += [check("rm -rf ~/Downloads", "rm -rf ~/Downloads", "auto_approve")]
        # Novos casos de regressão — bypasses C-1 e C-2 corrigidos
        results += [check("rm -rf ~/../../etc", "rm -rf ~/../../etc", "deny")]
        results += [check("sudo rm -rf /home/manoel", "sudo rm -rf /home/manoel", "deny")]
        # Novos casos de regressão (v4.2.1) — correções C-1, C-2, H-4, H-6
        results += [check("systemctl stop --user hyprland", "systemctl stop --user hyprland", "deny")]
        results += [check("chown -R user:user /bin", "chown -R user:user /bin", "deny")]
        results += [check("$(which sudo) ls /root", "$(which sudo) ls /root", "ask")]
        # H-6: cat /etc/passwd não deve ser cacheado (sem overwrite com tee)
        r = run_gate("cat /etc/passwd")
        ow = r.get("overwrite", {})
        results += [r.get("decision") == "auto_approve" and "tee" not in ow.get("CommandLine", "")]
        print(f"[{'PASS' if results[-1] else 'FAIL'}] cat /etc/passwd não é cacheado")

        # --- Novos casos de regressão (v4.3.0) — RULE-02 hardening ---
        results += [check("rm -Rf /", "rm -Rf /", "deny")]
        results += [check("rm --recursive /etc", "rm --recursive /etc", "deny")]
        results += [check("rm -rf /e?c", "rm -rf /e?c", "deny")]
        results += [check("rm -rf /e[t]c", "rm -rf /e[t]c", "deny")]
        results += [check("rm -rf /{etc,usr}", "rm -rf /{etc,usr}", "deny")]
        results += [check("find / -type f -exec rm {} \\;", "find / -type f -exec rm {} \\;", "deny")]
        results += [check("find / -execdir rm -rf {} \\;", "find / -execdir rm -rf {} \\;", "deny")]
        results += [check("find / -ok rm {} \\;", "find / -ok rm {} \\;", "deny")]
        results += [check("rm /etc/passwd", "rm /etc/passwd", "deny")]
        results += [check("rm /etc/shadow", "rm /etc/shadow", "deny")]
        results += [check("rm /etc/fstab", "rm /etc/fstab", "deny")]
        results += [check("echo $PATH", "echo $PATH", "auto_approve")]
        results += [check("shred -u ~/notes.txt", "shred -u ~/notes.txt", "auto_approve")]
        results += [check("shred /dev/sda", "shred /dev/sda", "deny")]
        # RULE-15: busca pura yay/paru -Ss deve fluir como auto_approve (v4.5.0)
        results += [check("yay -Ss firefox", "yay -Ss firefox", "auto_approve")]
        results += [check("paru -Ss firefox", "paru -Ss firefox", "auto_approve")]
        # cat estático é cacheado (reintegração), sensível não
        r = run_gate("cat /etc/os-release")
        ow = r.get("overwrite", {})
        results += [r.get("decision") == "auto_approve" and "tee" in ow.get("CommandLine", "")]
        print(f"[{'PASS' if results[-1] else 'FAIL'}] cat /etc/os-release é cacheado (tee)")
        r = run_gate("cat /proc/cpuinfo")
        ow = r.get("overwrite", {})
        results += [r.get("decision") == "auto_approve" and "tee" in ow.get("CommandLine", "")]
        print(f"[{'PASS' if results[-1] else 'FAIL'}] cat /proc/cpuinfo é cacheado (tee)")
        # Failsafe: payload malformado → force_ask (nunca allow)
        _bad = subprocess.run(
            [sys.executable, str(GATE)],
            input="not-json{", capture_output=True, text=True, timeout=10,
            env=dict(os.environ),
        )
        try:
            _failsafe_ok = json.loads(_bad.stdout.strip()).get("decision") == "force_ask"
        except Exception:
            _failsafe_ok = False
        results += [_failsafe_ok]
        print(f"[{'PASS' if _failsafe_ok else 'FAIL'}] payload malformado → force_ask")

        # --- RULE-06: sudo_runner (deny) ---
        results += [check("./sudo_runner.sh", "./sudo_runner.sh", "deny")]
        results += [check("bash /opt/sudo_runner.sh", "bash /opt/sudo_runner.sh", "deny")]

        # --- RULE-07: serviços críticos (deny) ---
        results += [check("systemctl stop sddm", "systemctl stop sddm", "deny")]
        results += [check("systemctl restart sddm", "systemctl restart sddm", "deny")]
        results += [check("pkill hyprland", "pkill hyprland", "deny")]
        results += [check("kill -9 1", "kill -9 1", "deny")]

        # --- RULE-07 (energia/sessão, v4.4.0): force_ask ---
        results += [check("systemctl reboot", "systemctl reboot", "force_ask")]
        results += [check("shutdown -h now", "shutdown -h now", "force_ask")]
        results += [check("loginctl lock-session", "loginctl lock-session", "force_ask")]

        # --- RULE-05: permissões semânticas (deny) ---
        results += [check("chmod -R 777 /usr", "chmod -R 777 /usr", "deny")]
        results += [check("chmod 777 -R /etc", "chmod 777 -R /etc", "deny")]
        results += [check("chmod -R a+w /usr", "chmod -R a+w /usr", "deny")]
        results += [check("chown -R root /etc", "chown -R root /etc", "deny")]
        results += [check("chown --recursive root /etc", "chown --recursive root /etc", "deny")]

        # --- RULE-01: monitores (leitura auto_approve, escrita force_ask) ---
        results += [check("cat ~/.config/hypr/monitors.lua", "cat ~/.config/hypr/monitors.lua", "auto_approve")]
        results += [check("vim ~/.config/hypr/monitors.lua", "vim ~/.config/hypr/monitors.lua", "force_ask")]

        # --- RULE-03: disco (force_ask) ---
        results += [check("mkfs.ext4 /dev/sdb1", "mkfs.ext4 /dev/sdb1", "force_ask")]
        results += [check("fdisk /dev/sdb", "fdisk /dev/sdb", "force_ask")]
        results += [check("mount /dev/sdb1 /mnt", "mount /dev/sdb1 /mnt", "force_ask")]
        results += [check("cryptsetup luksFormat /dev/sdb", "cryptsetup luksFormat /dev/sdb", "force_ask")]

        # --- RULE-15: privilégios rotineiros (ask — respeita Always Allow) ---
        results += [check("sudo apt update", "sudo apt update", "ask")]
        results += [check("run0 systemctl restart nginx", "run0 systemctl restart nginx", "ask")]
        results += [check("yay -S firefox", "yay -S firefox", "ask")]
        results += [check("yay -Syu", "yay -Syu", "ask")]
        results += [check("pacman -Sy firefox", "pacman -Sy firefox", "ask")]
        results += [check("sudoedit /etc/fstab", "sudoedit /etc/fstab", "ask")]
        results += [check("sudo -e /etc/fstab", "sudo -e /etc/fstab", "ask")]
        results += [check("echo su (sem falso positivo)", "echo su", "auto_approve")]

        # --- RULE-12: governança (deny absoluto em arquivos de governança) ---
        results += [check("chmod 777 ~/.gemini/config/plugins/bash-sudo-agents/AGENTS.md",
                          "chmod 777 ~/.gemini/config/plugins/bash-sudo-agents/AGENTS.md", "deny")]
        results += [check("rm ~/.gemini/config/plugins/bash-sudo-agents/hooks/governance-gate.py",
                          "rm ~/.gemini/config/plugins/bash-sudo-agents/hooks/governance-gate.py", "deny")]
        results += [check("sudo rm ~/.gemini/config/plugins/bash-sudo-agents/hooks/governance-gate.py",
                          "sudo rm ~/.gemini/config/plugins/bash-sudo-agents/hooks/governance-gate.py", "deny")]
        results += [check("dd of=governance-gate.py",
                          "dd if=~/i of=~/.gemini/config/plugins/bash-sudo-agents/hooks/governance-gate.py", "deny")]
        results += [check("echo x > ~/.gemini/config/hooks.json",
                          "echo x > ~/.gemini/config/hooks.json", "deny")]
        results += [check("ls governança 2>&1 (leitura com redirect fd)",
                          "ls ~/.gemini/config/plugins/bash-sudo-agents/ 2>&1", "auto_approve")]

        # --- Allow (comandos seguros) ---
        results += [check("lscpu", "lscpu", "auto_approve")]
        results += [check("journalctl -u ssh", "journalctl -u ssh", "auto_approve")]
        results += [check("cat /etc/os-release", "cat /etc/os-release", "auto_approve")]
        results += [check("echo olá mundo", "echo olá mundo", "auto_approve")]

        # --- Novos casos (v4.4.x): falsos positivos de aspas ---
        results += [check("git commit com 'rm -rf /' no texto", 'git commit -m "fix: nunca rodar rm -rf / de novo"', "auto_approve")]
        results += [check('echo "vou dar reboot"', 'echo "vou dar reboot"', "auto_approve")]
        results += [check("substituição $() preservada", 'echo "$(rm -rf /)"', "deny")]

        # --- Novos casos (v4.4.x): RULE-02 estendida (mutação de vitais) ---
        results += [check("mv de arquivo vital", "mv /etc/fstab /tmp/f", "deny")]
        results += [check("cp para arquivo vital", "cp /tmp/x /etc/fstab", "deny")]
        results += [check("truncate em arquivo vital", "truncate -s 0 /etc/shadow", "deny")]
        results += [check("tee em arquivo vital", "tee /etc/hosts", "deny")]
        results += [check("redirect > para vital", "echo x > /etc/fstab", "deny")]
        results += [check("redirect > para /dev/null", "echo x > /dev/null", "auto_approve")]
        results += [check("cp lendo de vital (backup)", "cp /etc/fstab /tmp/backup", "auto_approve")]
        results += [check('bash -c "rm -rf /"', 'bash -c "rm -rf /"', "deny")]
        results += [check('sh -c "mv /etc/hosts /tmp"', 'sh -c "mv /etc/hosts /tmp"', "deny")]

        # --- Novos casos (v4.4.x): diretórios vitais expandidos ---
        for d in ("/root", "/opt", "/srv", "/mnt"):
            results += [check(f"rm -rf {d}", f"rm -rf {d}", "deny")]
        results += [check("rm -rf /tmp/build (não vital)", "rm -rf /tmp/build", "auto_approve")]

        # --- Novos casos (v4.4.x): interpretadores inline ---
        results += [check("python3 -c rmtree /etc (destrutivo)", 'python3 -c "import shutil; shutil.rmtree(\'/etc\')"', "deny")]
        results += [check("python3 -c print(1)", 'python3 -c "print(1)"', "auto_approve")]

        # --- Novos casos (v4.4.x): fail-closed de schema ---
        for _bad_payload in (
            {"toolCall": {"name": "ferramenta_desconhecida", "args": {}}},
            {"toolCall": {"name": "run_command", "args": {"CommandLine": ""}}},
        ):
            _r = subprocess.run(
                [sys.executable, str(GATE)],
                input=json.dumps(_bad_payload), capture_output=True, text=True, timeout=10,
                env=dict(os.environ),
            )
            try:
                _ok = json.loads(_r.stdout.strip()).get("decision") == "force_ask"
            except Exception:
                _ok = False
            results += [_ok]
            print(f"[{'PASS' if _ok else 'FAIL'}] fail-closed p/ schema sem CommandLine")

        # --- Compressor não deve pendurar em follow ---
        r = run_gate("journalctl --follow")
        ow = r.get("overwrite", {})
        results += [r.get("decision") == "auto_approve" and "--follow" in ow.get("CommandLine", "--follow")]
        print(f"[{'PASS' if results[-1] else 'FAIL'}] journalctl --follow não é comprimido para tail")

        r = run_gate("dmesg -w")
        ow = r.get("overwrite", {})
        results += [r.get("decision") == "auto_approve" and "tail -n 35" not in ow.get("CommandLine", "")]
        print(f"[{'PASS' if results[-1] else 'FAIL'}] dmesg -w não é comprimido para tail")

        # --- v4.5.0 / P1: anti-fadiga real (auto_approve) já coberto acima ---

        # --- v4.5.0 / P2: interpretadores inline destrutivos (raiz nua) ---
        results += [check("python3 -c os.system rm -rf /",
                          "python3 -c \"import os; os.system('rm -rf /')\"", "deny")]
        results += [check("python3 -c rmtree /",
                          "python3 -c \"import shutil; shutil.rmtree('/')\"", "deny")]
        results += [check("node -e rmSync raiz",
                          "node -e 'require(\"fs\").rmSync(\"/\", {recursive:true})'", "deny")]
        results += [check("python3 script.py (sem -c)", "python3 script.py", "auto_approve")]

        # --- v4.5.0 / P3: governança por caminho resolvido ---
        results += [check("cd gov && rm hooks.json", "cd ~/.gemini/config && rm hooks.json", "deny")]
        results += [check("cd ~ && rm -rf .gemini/config", "cd ~ && rm -rf .gemini/config", "deny")]
        results += [check("rm hooks.json em projeto do usuário (não gov)",
                          "cd ~/projetos && rm hooks.json", "auto_approve")]

        # --- v4.5.0 / P4: mutação vital ampliada (sed -i / tar -x / rsync) ---
        results += [check("sed -i em /etc/hosts", "sed -i 's/a/b/' /etc/hosts", "deny")]
        results += [check("tar xf -C /etc", "tar xf /tmp/x.tar -C /etc", "deny")]
        results += [check("rsync destino /etc", "rsync -a /tmp/src/ /etc/", "deny")]
        results += [check("sed -n (leitura pura)", "sed -n '1,10p' /etc/hosts", "auto_approve")]
        results += [check("tar xf sem -C", "tar xf arquivo.tar", "auto_approve")]
        results += [check("rsync destino ./build", "rsync -a ./src/ ./build/", "auto_approve")]

        # --- v4.5.0 / P5: anti-fadiga ($VAR -> force_ask, /var/log -> ask) ---
        results += [check("cp para $DIST_DIR", "cp app.tar.gz $DIST_DIR/", "force_ask")]
        results += [check("mv com $BUILD", "mv $BUILD/out ./", "force_ask")]
        results += [check("truncate /var/log/syslog", "truncate -s 0 /var/log/syslog", "ask")]
        results += [check("redirect >> /var/log/syslog", "echo x >> /var/log/syslog", "ask")]

        # --- v4.5.0 / P6: stdin vazio -> force_ask (fail-closed) ---
        _empty = subprocess.run(
            [sys.executable, str(GATE)], input="", capture_output=True, text=True,
            timeout=10, env=dict(os.environ),
        )
        try:
            _empty_ok = json.loads(_empty.stdout.strip()).get("decision") == "force_ask"
        except Exception:
            _empty_ok = False
        results += [_empty_ok]
        print(f"[{'PASS' if _empty_ok else 'FAIL'}] stdin vazio → force_ask (fail-closed)")

        total = len(results)
        passed = sum(1 for x in results if x)
        print(f"\n{passed}/{total} verificações passaram.")
        sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
