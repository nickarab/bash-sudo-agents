#!/usr/bin/env bash
# =============================================================================
# Instalador: Sistema de Governança de Agentes (v5.0.0 — Runtime Go Nativo)
# Um único binário estático. Zero Python, zero pip, zero interpretador.
# =============================================================================
set -euo pipefail

echo "=========================================================="
echo " Instalador: Sistema de Governança de Agentes (v5.0.0 Go)"
echo "=========================================================="

# -----------------------------------------------------------------------------
# [1/6] Pré-requisito: toolchain Go >= 1.22 no host de build.
#       (Não baixamos toolchain silenciosamente — apenas documentamos.)
# -----------------------------------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
    echo "❌ Erro: Go não encontrado no PATH (requerido >= 1.22 para build)."
    echo "   Instale o toolchain Go 1.22+ e repita."
    exit 1
fi

GO_VERSION="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
GO_MAJOR="${GO_VERSION%%.*}"
GO_MINOR="$(printf '%s' "$GO_VERSION" | cut -d. -f2)"
if [ -z "$GO_MAJOR" ] || [ "$GO_MAJOR" -lt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 22 ]; }; then
    echo "❌ Erro: Go $GO_VERSION encontrado, mas é requerido Go >= 1.22."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_PLUGIN_DIR="$HOME/.gemini/config/plugins/bash-sudo-agents"
TARGET_AGENTS_DIR="$HOME/.gemini/config/agents"
TARGET_SECURITY_DIR="$HOME/.gemini/antigravity/scratch/security"
BACKUP_DIR="$HOME/.gemini/antigravity/scratch/backups"
BUILD_DIR="$SCRIPT_DIR/build"

# -----------------------------------------------------------------------------
# [2/6] Build estático (CGO desabilitado, stripped, sem path de build).
# -----------------------------------------------------------------------------
echo "[1/6] Compilando o motor Go (estático, CGO_ENABLED=0)..."
mkdir -p "$BUILD_DIR"
GATE_BIN="$BUILD_DIR/governance-gate"
( cd "$SCRIPT_DIR" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$GATE_BIN" ./cmd/governance-gate )

# -----------------------------------------------------------------------------
# [3/6] Diretórios de destino + backup atômico da instalação anterior.
# -----------------------------------------------------------------------------
echo "[2/6] Criando diretórios e fazendo backup atômico..."
mkdir -p "$TARGET_PLUGIN_DIR/hooks" "$TARGET_PLUGIN_DIR/agents" "$TARGET_AGENTS_DIR" "$TARGET_SECURITY_DIR" "$BACKUP_DIR"

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

# -----------------------------------------------------------------------------
# [4/6] Instalação atômica do binário + plugin + políticas.
# -----------------------------------------------------------------------------
echo "[3/6] Instalando binário, plugin e políticas..."
GATE_ABS="$TARGET_PLUGIN_DIR/hooks/governance-gate"

# Escrita atômica: nunca sobrescrever um binário em execução (tmp + rename).
cp -f "$GATE_BIN" "$GATE_ABS.tmp.$$"
chmod 0755 "$GATE_ABS.tmp.$$"
mv -f "$GATE_ABS.tmp.$$" "$GATE_ABS"

cp -r "$SCRIPT_DIR/plugin/"* "$TARGET_PLUGIN_DIR/"
cp -r "$SCRIPT_DIR/plugin/agents/"*.md "$TARGET_AGENTS_DIR/"
cp -r "$SCRIPT_DIR/security/"* "$TARGET_SECURITY_DIR/"

# Purga de qualquer resíduo de instalações anteriores (v4.x): o diretório de
# hooks deve conter apenas o binário do motor.
find "$TARGET_PLUGIN_DIR/hooks" -mindepth 1 -maxdepth 1 ! -name 'governance-gate' -exec rm -rf {} + 2>/dev/null || true

# -----------------------------------------------------------------------------
# [5/6] Registro do hook por template puro (render-hooks do próprio binário).
# -----------------------------------------------------------------------------
echo "[4/6] Registrando hooks.json via 'governance-gate render-hooks'..."
"$GATE_ABS" render-hooks \
    --template "$SCRIPT_DIR/plugin/hooks.json" \
    --out "$TARGET_PLUGIN_DIR/hooks.json" \
    --gate "$GATE_ABS"

# -----------------------------------------------------------------------------
# [6/6] Smoke test sem interpretador + blindagem somente-leitura.
# -----------------------------------------------------------------------------
echo "[5/6] Smoke test do motor (stdin/stdout, fail-closed)..."

SMOKE_OUTPUT=$(printf '%s' '{"toolCall":{"name":"run_command","args":{"CommandLine":"lscpu","Cwd":"'"$HOME"'"}}}' | "$GATE_ABS" 2>/dev/null || true)
if ! printf '%s' "$SMOKE_OUTPUT" | grep -q '"decision"'; then
    echo "❌ Erro: o motor Go não respondeu corretamente."
    exit 1
fi

EMPTY_OUTPUT=$(printf '' | "$GATE_ABS" 2>/dev/null || true)
if ! printf '%s' "$EMPTY_OUTPUT" | grep -q '"force_ask"'; then
    echo "❌ Erro: fail-closed de stdin vazio não está ativo."
    exit 1
fi

echo "[6/6] Aplicando blindagem somente-leitura (chmod 444)..."
chmod 0755 "$GATE_ABS" 2>/dev/null || true
chmod 0444 "$TARGET_PLUGIN_DIR/hooks.json" \
          "$TARGET_PLUGIN_DIR/plugin.json" \
          "$TARGET_PLUGIN_DIR/rules/AGENTS.md" \
          "$TARGET_PLUGIN_DIR/agents/"*.md \
          "$TARGET_AGENTS_DIR/"*.md \
          "$TARGET_PLUGIN_DIR/skills/"*"/SKILL.md" \
          "$TARGET_SECURITY_DIR/"*.json \
          "$TARGET_SECURITY_DIR/"*.md 2>/dev/null || true

# chattr +i é opcional e requer privilégio/FS compatível (documentado).
if command -v chattr >/dev/null 2>&1; then
    chattr +i "$GATE_ABS" 2>/dev/null || true
fi

echo ""
echo "✅ Instalação v5.0.0 (Go Nativo — auto_approve, cache atômico, flock) concluída!"
echo "Plugin:    $TARGET_PLUGIN_DIR"
echo "Políticas: $TARGET_SECURITY_DIR"
echo "Hook:      $GATE_ABS"
echo "Backup:    $BACKUP_DIR/*_$TIMESTAMP"
