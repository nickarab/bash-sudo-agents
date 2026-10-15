#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo " Instalador: Sistema de Governança de Agentes (v4.1 Python)"
echo "=========================================================="

if ! command -v python3 >/dev/null 2>&1; then
    echo "❌ Erro: python3 não está instalado no sistema."
    exit 1
fi

python3 -c "import sys; assert sys.version_info >= (3, 8)" 2>/dev/null || {
    echo "❌ Erro: Requer Python 3.8 ou superior."
    exit 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_PLUGIN_DIR="$HOME/.gemini/config/plugins/bash-sudo-agents"
TARGET_SECURITY_DIR="$HOME/.gemini/antigravity/scratch/security"
BACKUP_DIR="$HOME/.gemini/antigravity/scratch/backups"

echo "[1/4] Criando diretórios de destino..."
mkdir -p "$TARGET_PLUGIN_DIR/hooks" "$TARGET_SECURITY_DIR" "$BACKUP_DIR"

echo "[2/4] Instalando plugin de agentes e motor Python..."
chmod -R u+rwX "$TARGET_PLUGIN_DIR" 2>/dev/null || true

# Backup atômico antes de sobrescrever (Seção 5.4)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if [ -d "$TARGET_PLUGIN_DIR" ] && [ "$(ls -A "$TARGET_PLUGIN_DIR" 2>/dev/null)" ]; then
    cp -a "$TARGET_PLUGIN_DIR" "$BACKUP_DIR/plugin_$TIMESTAMP" 2>/dev/null || true
fi

cp -r "$SCRIPT_DIR/plugin/"* "$TARGET_PLUGIN_DIR/"
chmod 555 "$TARGET_PLUGIN_DIR/hooks/governance-gate.py" 2>/dev/null || true
chmod 444 "$TARGET_PLUGIN_DIR/hooks.json" 2>/dev/null || true

echo "[3/4] Instalando políticas de segurança e metagovernança..."
if [ -d "$TARGET_SECURITY_DIR" ]; then
    chmod -R u+rwX "$TARGET_SECURITY_DIR" 2>/dev/null || true
fi
cp -r "$SCRIPT_DIR/security/"* "$TARGET_SECURITY_DIR/"

echo "[4/4] Aplicando blindagem de somente-leitura (chmod 444)..."
chmod 444 "$TARGET_PLUGIN_DIR/plugin.json" \
          "$TARGET_PLUGIN_DIR/rules/AGENTS.md" \
          "$TARGET_PLUGIN_DIR/skills/"*"/SKILL.md" \
          "$TARGET_SECURITY_DIR/"*.json \
          "$TARGET_SECURITY_DIR/"*.md 2>/dev/null || true

echo ""
echo "✅ Instalação v4.1 (Python Engine + Segurança Reforçada) concluída com sucesso!"
echo "Plugin:    $TARGET_PLUGIN_DIR"
echo "Políticas: $TARGET_SECURITY_DIR"
echo "Backup:    $BACKUP_DIR/plugin_$TIMESTAMP"
