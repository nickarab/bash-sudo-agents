# Sistema de Governança e Automação Linux: Antigravity Bash-Sudo Agents

Arquitetura agêntica para execução e administração segura de sistemas Linux em ambientes Antigravity, baseada no modelo de **Separação de Poderes, Auditoria Stateless e Compactação de Contexto**.

---

## 1. Instalação Rápida em Nova Máquina

Clone este repositório privado e execute o instalador automatizado:

```bash
git clone git@github.com:nickarab/bash-sudo-agents.git
cd bash-sudo-agents
./install.sh
```

O instalador configura:
1. O plugin em `~/.gemini/config/plugins/bash-sudo-agents/`.
2. As políticas constitucionais em `~/.gemini/antigravity/scratch/security/`.
3. As permissões de segurança (`chmod 444` em `policies.json`).
4. O executor volátil seguro (`sudo_runner.sh`) com permissões restritas `700`.

---

## 2. Estrutura do Repositório

```text
bash-sudo-agents/
├── .gitignore
├── install.sh                  # Instalador automatizado para qualquer máquina Linux
├── README.md                   # Esta documentação
├── plugin/                     # Definições do plugin Antigravity
│   ├── plugin.json
│   ├── rules/
│   │   └── AGENTS.md           # Regras globais carregadas no prompt do sistema
│   └── skills/
│       ├── agente-bash/
│       │   └── SKILL.md        # Skill do operador de terminal
│       └── agente-sudo-policy/
│           └── SKILL.md        # Skill do gestor constitucional
└── security/                   # Políticas de segurança e metagovernança
    ├── policies.json           # Mini Constituição de Segurança v3.0 (chmod 444)
    ├── meta_policies.json      # Políticas de autoproteção do @agente-meta
    ├── agents_manifest.json    # Manifesto dos agentes instalados
    └── sudo_runner.sh.template # Template seguro sem credenciais expostas
```

---

## 3. Matriz de Agentes

| Agente | Tipo / Escopo | Papel Principal | Governança |
| :--- | :--- | :--- | :--- |
| **`@agente-bash`** | Operador de Terminal | Diagnóstico e planejamento de comandos shell. | Pipes limitadores (`head`/`tail`/`grep`), payload JSON minimalista. Proibido de rodar `sudo` diretamente. |
| **`@agente-sudo`** | Auditor de Segurança | Validação stateless e execução autorizada de privilégios. | Leitura estrita de `policies.json`. Teto de 3 rejeições consecutivas (Regra 3X). |
| **`@agente-sudo-policy`** | Gestor Constitucional | Manutenção e versionamento das políticas. | Monopólio legislativo sobre `policies.json`. Mediação flexível. Proibição de executar shell diretamente. |
| **`@agente-meta`** | Metagovernança | Proteção dos próprios agentes contra mutações acidentais da IA. | Princípio da Consulta Pura (Read-Only) e exigência de ordem verbal explícita. |

---

## 4. Contrato de Comunicação entre Agentes

### Solicitação (`@agente-bash` ➔ `@agente-sudo`):
```json
{
  "command": "systemctl restart NetworkManager",
  "objective": "Restaurar conectividade após alteração de DNS.",
  "blast_radius": ["NetworkManager.service", "/etc/resolv.conf"]
}
```

### Resposta (`@agente-sudo` ➔ `@agente-bash`):
```json
{
  "status": "APPROVED | MITIGATED | VETOED | ESCALATED",
  "mitigated_command": null,
  "reason": "Regra violada ou justificativa de mitigação",
  "attempt": 1
}
```

---

## 5. Regras Constitucionais Ativas (`policies.json v3.0`)

* **RULE-01 (Soberania do Display):** Veto a alterações em `monitors.lua` sem consentimento explícito.
* **RULE-02 (Anti-Destruição):** Proibição de remoção recursiva em diretórios vitais (`/`, `/boot`, `/etc`, etc.).
* **RULE-03 (Operações de Disco):** `mkfs`, `fdisk`, `dd` exigem alvo explícito e blindam partições ativas.
* **RULE-04 (Escopo Estrito):** Veto a ações laterais ou instalações não solicitadas.
* **RULE-05 (Preservação de Permissões):** Veto a `chmod -R 777` ou `chown -R` no sistema.
* **RULE-06 (Privacidade):** `HISTFILE=/dev/null` forçado; sigilo de tokens e chaves.
* **RULE-07 (Anti-Crash):** Proibido matar PID 1, Wayland compositor e Display Managers.
* **RULE-08 (Mitigação Ativa):** Remodelação autônoma do bash sem expor falha ao usuário.
* **RULE-09 (Franquia de Diagnóstico):** Leitura de logs e hardware autorizada sem burocracia.
* **RULE-10 (Limite 3X):** Escalação humana obrigatória após 3 recusas consecutivas.
* **RULE-11 (Mediação Flexível):** Consulta de Revisão Constitucional (Cenário A) ou Kill Switch contra a sessão do `@agente-sudo` (Cenário B).
* **RULE-12 (Blindagem Cirúrgica):** Arquivo de políticas mantido em `chmod 444` e atributo imutável (`chattr +i`).
