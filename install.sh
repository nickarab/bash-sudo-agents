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
cp -r "$SCRIPT_DIR/plugin/"* "$TARGET_PLUGIN_DIR/"

echo "[3/4] Instalando políticas de segurança e metagovernança..."
cp "$SCRIPT_DIR/security/meta_policies.json" "$TARGET_SECURITY_DIR/"
cp "$SCRIPT_DIR/security/agents_manifest.json" "$TARGET_SECURITY_DIR/"

# Desbloqueia temporariamente se o policies.json existente estiver em modo read-only
if [ -f "$TARGET_SECURITY_DIR/policies.json" ]; then
    chmod 644 "$TARGET_SECURITY_DIR/policies.json" 2>/dev/null || true
fi
cp "$SCRIPT_DIR/security/policies.json" "$TARGET_SECURITY_DIR/"
chmod 444 "$TARGET_SECURITY_DIR/policies.json"

echo "[4/4] Configurando executor seguro (sudo_runner.sh)..."
if [ -f "$TARGET_SECURITY_DIR/sudo_runner.sh" ]; then
    echo "  -> sudo_runner.sh existente mantido intacto."
else
    echo -n "  Deseja configurar a credencial local para o executor seguro agora? [s/N]: "
    read -r RESP || RESP=""
    if [[ "$RESP" =~ ^[sSyY]$ ]]; then
        echo -n "  Digite a senha do sudo (não será exibida): "
        read -s SUDO_PASS
        echo ""
        ENC_PASS=$(printf "%s" "$SUDO_PASS" | base64)
        sed "s|__ENCODED_SUDO_PASSWORD__|$ENC_PASS|g" "$SCRIPT_DIR/security/sudo_runner.sh.template" > "$TARGET_SECURITY_DIR/sudo_runner.sh"
        chmod 700 "$TARGET_SECURITY_DIR/sudo_runner.sh"
        unset SUDO_PASS
        unset ENC_PASS
        echo "  -> sudo_runner.sh configurado com permissões 700."
    else
        sed "s|__ENCODED_SUDO_PASSWORD__||g" "$SCRIPT_DIR/security/sudo_runner.sh.template" > "$TARGET_SECURITY_DIR/sudo_runner.sh"
        chmod 700 "$TARGET_SECURITY_DIR/sudo_runner.sh"
        echo "  -> sudo_runner.sh criado sem credencial. Configure quando necessário."
    fi
fi

echo ""
echo "Instalação concluída com sucesso!"
echo "Plugin:   $TARGET_PLUGIN_DIR"
echo "Políticas: $TARGET_SECURITY_DIR"
