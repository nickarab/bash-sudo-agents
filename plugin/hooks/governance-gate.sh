#!/usr/bin/env bash
# PreToolUse gate — bash-sudo-agents
input=$(cat)
args=$(jq -c '.toolCall.args // {}' <<<"$input")
cmd=$(jq -r '.CommandLine // ""' <<<"$args")
target=$(jq -r '.TargetFile // ""' <<<"$args")

GOV='plugins/bash-sudo-agents/|scratch/security/|\.gemini/config/config\.json'
WRITE_OPS='(>|\btee\b|sed[[:space:]]+-i|\bchmod\b|\bchown\b|\bchattr\b|\brm\b|\bmv\b|\bcp\b|\binstall\b|\bshred\b)'
PRIV='(^|[;&|(`[:space:]])(sudo|doas|pkexec|su)([[:space:]]|$)|(^|[;&|[:space:]])(yay|paru)[[:space:]]+-S'

out(){ jq -nc --arg d "$1" --arg r "$2" '{decision:$d, reason:$r}'; exit 0; }

grep -q 'sudo_runner' <<<"$cmd" && out deny "sudo_runner.sh foi descontinuado. Utilize o fluxo nativo ou NOPASSWD configurado."
grep -Eq "$PRIV" <<<"$cmd" && out force_ask "[@agente-sudo] Comando com privilégios de superusuário detectado. Confirme se atende estritamente à sua demanda."
[ -n "$target" ] && grep -Eq "$GOV" <<<"$target" && out force_ask "[@agente-meta] Escrita em arquivo de governança detectada. Confirme se você solicitou a alteração."
grep -Eq "$GOV" <<<"$cmd" && grep -Eq "$WRITE_OPS" <<<"$cmd" && out force_ask "[@agente-meta] Comando tenta modificar arquivo de governança."
out allow ""
