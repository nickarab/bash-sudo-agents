#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo " Instalador: Sistema de Governança de Agentes (v4.5.0 Python)"
echo "=========================================================="

if ! command -v python3 >/dev/null 2>&1; then
    echo "❌ Erro: python3 não está instalado no sistema."
    exit 1
fi

# O motor usa `from __future__ import annotations`, então PEP 604 (`str | None`)
# e PEP 585 (`list[str]`) são válidos a partir do Python 3.8.
if ! python3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)" 2>/dev/null; then
    echo "❌ Erro: Requer Python 3.8 ou superior."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_PLUGIN_DIR="$HOME/.gemini/config/plugins/bash-sudo-agents"
TARGET_AGENTS_DIR="$HOME/.gemini/config/agents"
TARGET_SECURITY_DIR="$HOME/.gemini/antigravity/scratch/security"
BACKUP_DIR="$HOME/.gemini/antigravity/scratch/backups"

echo "[1/5] Criando diretórios de destino..."
mkdir -p "$TARGET_PLUGIN_DIR/hooks" "$TARGET_PLUGIN_DIR/agents" "$TARGET_AGENTS_DIR" "$TARGET_SECURITY_DIR" "$BACKUP_DIR"

echo "[2/5] Backup atômico das instalações anteriores..."
chmod -R u+rwX "$TARGET_PLUGIN_DIR" 2>/dev/null || true
chmod -R u+rwX "$TARGET_AGENTS_DIR" 2>/dev/null || true
chmod -R u+rwX "$TARGET_SECURITY_DIR" 2>/dev/null || true

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
for src_dir in "$TARGET_PLUGIN_DIR" "$TARGET_SECURITY_DIR" "$TARGET_AGENTS_DIR"; do
    if [ -d "$src_dir" ] && [ "$(ls -A "$src_dir" 2>/dev/null)" ]; then
        name=$(basename "$src_dir")
        cp -a "$src_dir" "$BACKUP_DIR/${name}_$TIMESTAMP" 2>/dev/null || true
    fi
done

echo "[3/5] Instalando plugin de agentes e motor Python..."
cp -r "$SCRIPT_DIR/plugin/"* "$TARGET_PLUGIN_DIR/"
cp -r "$SCRIPT_DIR/plugin/agents/"*.md "$TARGET_AGENTS_DIR/"
find "$TARGET_PLUGIN_DIR" -name "__pycache__" -type d -prune -exec rm -rf {} + 2>/dev/null || true

echo "[4/5] Instalando políticas de segurança e metagovernança..."
cp -r "$SCRIPT_DIR/security/"* "$TARGET_SECURITY_DIR/"

# Resolução determinística do caminho do motor: substitui o placeholder
# `__GATE_PATH__` por um caminho ABSOLUTO, para que o hook não dependa do cwd
# com que o Antigravity o invoque.
GATE_ABS="$TARGET_PLUGIN_DIR/hooks/governance-gate.py"
python3 - "$SCRIPT_DIR/plugin/hooks.json" "$TARGET_PLUGIN_DIR/hooks.json" "$GATE_ABS" <<'PY'
import json
import sys

template, destination, gate = sys.argv[1], sys.argv[2], sys.argv[3]
with open(template, encoding="utf-8") as fh:
    data = json.load(fh)

for entry in data.values():
    if not isinstance(entry, dict):
        continue
    for group in entry.get("PreToolUse", []):
        for hook in group.get("hooks", []):
            if "command" in hook:
                hook["command"] = f"python3 {gate}"

with open(destination, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
PY

echo "[5/5] Verificando o motor e aplicando blindagem somente-leitura (chmod 444)..."

# Smoke test: garante que o motor importa (Python compatível) e responde JSON.
SMOKE_OUTPUT=$(printf '%s' '{"toolCall":{"name":"run_command","args":{"CommandLine":"lscpu","Cwd":"'"$HOME"'"}}}' | python3 "$GATE_ABS" 2>/dev/null || true)
if ! printf '%s' "$SMOKE_OUTPUT" | grep -q '"decision"'; then
    echo "❌ Erro: o motor governance-gate.py não respondeu corretamente (verifique a versão do Python)."
    exit 1
fi

chmod 555 "$GATE_ABS" 2>/dev/null || true
chmod 444 "$TARGET_PLUGIN_DIR/hooks.json" \
          "$TARGET_PLUGIN_DIR/plugin.json" \
          "$TARGET_PLUGIN_DIR/rules/AGENTS.md" \
          "$TARGET_PLUGIN_DIR/agents/"*.md \
          "$TARGET_AGENTS_DIR/"*.md \
          "$TARGET_PLUGIN_DIR/skills/"*"/SKILL.md" \
          "$TARGET_SECURITY_DIR/"*.json \
          "$TARGET_SECURITY_DIR/"*.md 2>/dev/null || true

echo ""
echo "✅ Instalação v4.5.0 (Python Engine + Anti-Fadiga auto_approve) concluída com sucesso!"
echo "Plugin:    $TARGET_PLUGIN_DIR"
echo "Políticas: $TARGET_SECURITY_DIR"
echo "Hook:      $GATE_ABS"
echo "Backup:    $BACKUP_DIR/*_$TIMESTAMP"
