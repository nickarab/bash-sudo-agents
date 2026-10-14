#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo " Instalador: Sistema de Governança de Agentes Antigravity "
echo "=========================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_PLUGIN_DIR="$HOME/.gemini/config/plugins/bash-sudo-agents"
TARGET_SECURITY_DIR="$HOME/.gemini/antigravity/scratch/security"

echo "[1/4] Criando diretórios de destino..."
mkdir -p "$TARGET_PLUGIN_DIR"
mkdir -p "$TARGET_SECURITY_DIR"

echo "[2/4] Instalando plugin de agentes (@agente-bash & @agente-sudo-policy)..."
# Desbloqueia arquivos se já existirem como read-only
chmod -R 644 "$TARGET_PLUGIN_DIR" 2>/dev/null || true
cp -r "$SCRIPT_DIR/plugin/"* "$TARGET_PLUGIN_DIR/"
chmod 555 "$TARGET_PLUGIN_DIR/hooks/governance-gate.sh" 2>/dev/null || true
chmod 444 "$TARGET_PLUGIN_DIR/hooks.json" 2>/dev/null || true

echo "[3/4] Instalando políticas de segurança e metagovernança..."
if [ -f "$TARGET_SECURITY_DIR/policies.json" ]; then
    chmod 644 "$TARGET_SECURITY_DIR/policies.json" 2>/dev/null || true
fi
cp "$SCRIPT_DIR/security/meta_policies.json" "$TARGET_SECURITY_DIR/"
cp "$SCRIPT_DIR/security/agents_manifest.json" "$TARGET_SECURITY_DIR/"
cp "$SCRIPT_DIR/security/policies.json" "$TARGET_SECURITY_DIR/"
cp "$SCRIPT_DIR/security/README.md" "$TARGET_SECURITY_DIR/" 2>/dev/null || true

echo "[4/4] Aplicando blindagem de somente-leitura (chmod 444)..."
chmod 444 "$TARGET_PLUGIN_DIR/plugin.json" \
          "$TARGET_PLUGIN_DIR/rules/AGENTS.md" \
          "$TARGET_PLUGIN_DIR/skills/"*"/SKILL.md" \
          "$TARGET_SECURITY_DIR/policies.json" \
          "$TARGET_SECURITY_DIR/meta_policies.json" \
          "$TARGET_SECURITY_DIR/agents_manifest.json" \
          "$TARGET_SECURITY_DIR/README.md" 2>/dev/null || true

echo ""
echo "Instalação v3.3 concluída com sucesso!"
echo "Plugin:    $TARGET_PLUGIN_DIR"
echo "Políticas: $TARGET_SECURITY_DIR"
