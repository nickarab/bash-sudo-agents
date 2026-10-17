# Sistema de Governança de Agentes de Terminal

Este diretório contém as políticas e manifestos centrais do ecossistema de agentes (v4.0):

## Componentes

1. **`policies.json` (v4.0)**:
   - Políticas constitucionais ativas aplicadas em runtime pelo motor Go `governance-gate` (`PreToolUse`) sobre o `@agente-bash` (camada de governança semântica / guardrail).
   - Gerenciado exclusivamente através do `@agente-sudo-policy`.

2. **`meta_policies.json` (v4.0)**:
   - Políticas de metagovernança para proteção da integridade dos próprios arquivos de agentes e configurações.

3. **`agents_manifest.json` (v4.0)**:
   - Definições e papéis dos 3 pilares do sistema: `@agente-bash` (Operador LLM), `governance-gate` (Motor de Runtime) e `@agente-sudo-policy` (Gestor Constitucional LLM).

## Como Fazer Backup

Para fazer backup completo de tudo em um único comando:
```bash
tar -czf backup_agentes_$(date +%F).tar.gz -C ~/.gemini config/plugins/bash-sudo-agents config/config.json antigravity/scratch/security
```
