#!/usr/bin/env bash
# PreToolUse gate — bash-sudo-agents (v3.3)
input=$(cat)
args=$(jq -c '.toolCall.args // {}' <<<"$input")
cmd=$(jq -r '.CommandLine // ""' <<<"$args")
target=$(jq -r '.TargetFile // ""' <<<"$args")

GOV='plugins/bash-sudo-agents/|scratch/security/|\.gemini/config/config\.json'
WRITE_OPS='(>|\btee\b|sed[[:space:]]+-i|\bchmod\b|\bchown\b|\bchattr\b|\brm\b|\bmv\b|\bcp\b|\binstall\b|\bshred\b)'
PRIV='(^|[;&|(`[:space:]])(sudo|doas|pkexec|su)([[:space:]]|$)|(^|[;&|[:space:]])(yay|paru)[[:space:]]+-S'
MONITOR='monitors\.lua|hyprland/.*monitors?\.conf'
DESTRUCTIVE='(^|[;&|[:space:]])rm[[:space:]]+-[a-zA-Z]*r[a-zA-Z]*f?[[:space:]]+(/(boot|etc|usr|var|sys|proc|dev)?(/)?([[:space:]]|$)|~(/)?([[:space:]]|$))'

out(){ jq -nc --arg d "$1" --arg r "$2" '{decision:$d, reason:$r}'; exit 0; }

# RULE-06: Veto ao sudo_runner descontinuado
grep -q 'sudo_runner' <<<"$cmd" && out deny "sudo_runner.sh foi descontinuado. Utilize o fluxo nativo ou NOPASSWD configurado."

# RULE-02: Veto sumário anti-destruição em diretórios vitais do sistema
grep -Eq "$DESTRUCTIVE" <<<"$cmd" && out deny "[@agente-sudo / RULE-02] Veto sumário: remoção recursiva na raiz (/) ou em diretórios vitais do sistema é terminantemente proibida."

# RULE-01: Soberania do Display e monitores.lua
(grep -Eq "$MONITOR" <<<"$cmd" || grep -Eq "$MONITOR" <<<"$target") && out force_ask "[@agente-sudo / RULE-01] Alteração em configuração de monitores detectada (monitors.lua). Confirme apenas se solicitou expressamente."

# RULE-15: Comandos com privilégios de superusuário
grep -Eq "$PRIV" <<<"$cmd" && out force_ask "[@agente-sudo / RULE-15] Comando com privilégios de superusuário detectado. Confirme se atende estritamente à sua demanda."

# RULE-11 e RULE-12: Proteção da integridade de governança
[ -n "$target" ] && grep -Eq "$GOV" <<<"$target" && out force_ask "[@agente-meta / RULE-12] Escrita em arquivo de governança detectada. Confirme se você solicitou a alteração ao @agente-sudo-policy."
grep -Eq "$GOV" <<<"$cmd" && grep -Eq "$WRITE_OPS" <<<"$cmd" && out force_ask "[@agente-meta / RULE-12] Comando tenta modificar arquivo de governança. Confirme se solicitou ao @agente-sudo-policy."

out allow ""
