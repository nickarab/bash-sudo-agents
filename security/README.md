# Sistema de Agentes Bash + Sudo

Este diretório contém as políticas e manifestos centrais do ecossistema de agentes:

## Componentes

1. **`policies.json` (v3.3)**:
   - Políticas constitucionais ativas aplicadas na auditoria do `@agente-sudo` sobre o `@agente-bash`.
   - Fiscalizadas fisicamente no runtime pelo hook `governance-gate.sh` (`PreToolUse`).
   - Gerenciado exclusivamente através do `@agente-sudo-policy`.

2. **`meta_policies.json`**:
   - Políticas de metagovernança para proteção da integridade dos próprios agentes.

3. **`agents_manifest.json`**:
   - Definições e papéis dos agentes (`@agente-bash`, `@agente-sudo`, `@agente-sudo-policy`).

## Como Fazer Backup

Para fazer backup completo de tudo em um único comando:
```bash
tar -czf backup_agentes_$(date +%F).tar.gz -C ~/.gemini config/plugins/bash-sudo-agents config/config.json antigravity/scratch/security
```
