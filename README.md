<div align="center">

# 🛡️ Antigravity Linux Governance
### *Agentes Autônomos de Terminal com Separação de Poderes, Motor Python Nativo, Auto-Compressão e Cache Local (v4.0)*

[![Architecture](https://img.shields.io/badge/Architecture-Multi--Agent%20Governance-blueviolet?style=for-the-badge&logo=diagramsdotnet)](https://github.com/nickarab/bash-sudo-agents)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Wayland%20%7C%20Hyprland-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://github.com/nickarab/bash-sudo-agents)
[![Security Level](https://img.shields.io/badge/Security-Constitutional%20v4.0-success?style=for-the-badge&logo=shield)](https://github.com/nickarab/bash-sudo-agents)
[![Runtime Gate](https://img.shields.io/badge/Runtime%20Gate-Python%20PreToolUse-darkgreen?style=for-the-badge&logo=python)](https://github.com/nickarab/bash-sudo-agents)
[![Optimizer](https://img.shields.io/badge/Tokens-Auto--Compressor%20%2B%20Cache-blue?style=for-the-badge)](https://github.com/nickarab/bash-sudo-agents)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20Pip%20(Pure%20Stdlib)-orange?style=for-the-badge)](https://github.com/nickarab/bash-sudo-agents)

<p align="center">
  <b>Um framework agêntico de alto desempenho que transforma o terminal Linux em um ambiente autônomo, blindado no runtime e ultra-eficiente no consumo de tokens.</b>
</p>

[Instalação Rápida](#-instalação-express-em-nova-máquina) •
[Arquitetura](#-arquitetura-do-sistema) •
[Otimização de Tokens & Cache](#-otimização-de-tokens--cache-local) •
[Agentes](#-matriz-de-responsabilidades) •
[Constituição](#-mini-constituição-de-segurança-v40)

---

</div>

## 🌟 Destaques da Arquitetura

<table>
  <tr>
    <td width="50%">
      <h3>🛡️ Dupla Barreira & Separação de Poderes</h3>
      O operador de terminal (<code>@agente-bash</code>) é proibido de executar comandos privilegiados diretamente. Toda elevação passa pela auditoria do <code>@agente-sudo</code> e é fisicamente fiscalizada no sistema pelo motor Python <code>governance-gate.py</code>.
    </td>
    <td width="50%">
      <h3>⚡ Auto-Compressor Sintático de Tokens</h3>
      Injeção inteligente de limitadores na fonte (<code>head</code>, <code>tail</code>, <code>--no-pager</code>) via <code>overwrite</code> nativo. Blindagem sintática que respeita redirecionamentos e pipes existentes da IA.
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>💾 Cache Local com TTL</h3>
      Comandos estáticos de diagnóstico (<code>lscpu</code>, <code>uname</code>, <code>lspci</code>) são cacheados localmente com TTL configurável, eliminando re-execuções e saídas duplicadas no histórico do chat.
    </td>
    <td width="50%">
      <h3>🔒 Zero-Pip & Failsafe Universal</h3>
      Construído estritamente com a biblioteca padrão do Python 3.8+ (sem necessidade de <code>pip install</code> ou <code>jq</code>). Envelopamento global com <code>try/except</code> que impede travamentos da IDE.
    </td>
  </tr>
</table>

---

## 🏗️ Arquitetura do Sistema

```mermaid
flowchart TD
    User(["👤 Usuário Administrador"]) <-->|"Comandos e Diagnósticos"| Bash["🖥️ @agente-bash<br/>(Operador de Terminal)"]
    
    subgraph Sandbox["⚙️ Execução e Auditoria em Tempo Real"]
        Bash -->|"1. Leitura e Diagnóstico Livre"| TermBash["Terminal Seguro: Pipes Limitadores"]
        Bash -->|"2. Deliberação e Payload JSON"| Sudo{"🛡️ @agente-sudo<br/>(Auditor Cognitivo)"}
        
        Sudo -->|"Aprovado ou Mitigado"| RunCmd["Disparo via run_command"]
        Sudo -->|"Vetado"| LoopAdapt["Loop de Auto-Adaptação Autônoma"]
        LoopAdapt -->|"Nova Tentativa Segura (até 3)"| Sudo
        
        RunCmd --> Gate{"🚧 governance-gate.py<br/>(Motor Python PreToolUse)"}
        Gate -->|"Cache Hit (TTL Válido)"| CacheRead["Leitura Instantânea de Cache"]
        Gate -->|"allow: seguro / otimizado"| OSExec["Execução no Linux"]
        Gate -->|"force_ask: sudo / privilégios / monitores"| PromptUser["Card Nativo de Senha / Confirmação"]
        Gate -->|"deny: rm -rf raiz / destruição vital"| HardBlock["🛑 Veto Físico Imediato no SO"]
        PromptUser -->|"Aprovado pelo Usuário"| OSExec
        CacheRead --> OSExec
    end
    
    Sudo -->|"Teto de 3 Rejeições Atingido"| Escalation["🛑 Relatório Estruturado de Escalação Humana"]
    Escalation --> User
    
    subgraph Governance["📜 Metagovernança & Políticas"]
        User <-->|"Gestão Legislativa"| Policy["⚖️ @agente-sudo-policy<br/>(Gestor Constitucional)"]
        Policy -.->|"Mediação: Revisão ou Kill Switch"| Sudo
        Policy -->|"Escrita Segura Proposta-Primeiro"| PoliciesFile["policies.json v3.3<br/>chmod 444"]
        MetaGuard{"👁️ @agente-meta<br/>(Guardião de Infraestrutura)"} -.->|"Proteção PreToolUse contra Mutações"| Gate
    end
```

---

## ⚡ Otimização de Tokens & Cache Local

O motor `governance-gate.py` atua ativamente para reduzir o consumo de tokens antes que qualquer texto seja gravado no histórico da sessão:

### 1. Auto-Compressor na Fonte
* **`journalctl`** ➔ Adiciona automaticamente `--no-pager -n 35`.
* **`dmesg`** ➔ Adiciona automaticamente `--color=never | tail -n 35`.
* **`git log`** ➔ Adiciona automaticamente `-n 15`.
* **`pacman -Ss` / `yay -Ss`** ➔ Adiciona automaticamente `| head -n 25`.
* **Blindagem Sintática:** Se a IA já tiver configurado redirecionamentos (`>`, `>>`) ou pipes (`|`), o compressor não interfere, garantindo integridade sintática.

### 2. Cache com TTL (Time-To-Live)
* **Local:** `~/.cache/antigravity/bash_agents/`
* **Hardware/Distro Estático** (`lscpu`, `uname -a`, `lspci`, `lsusb`, `cat /etc/os-release`): TTL de **1 hora**.
* **Buscas em Repositórios** (`pacman -Ss`, `yay -Ss`): TTL de **10 minutos**.
* **Comandos Voláteis** (`git status`, `systemctl`, `ps`, testes): **TTL = 0** (nunca cacheados).

---

## 👥 Matriz de Responsabilidades

| Agente | Identidade | Nível de Acesso | Diretiva Primária |
| :--- | :--- | :--- | :--- |
| **`@agente-bash`** | **Operador de Terminal** | Leitura irrestrita do SO / Shell sem privilégios | Executa diagnósticos ágeis, compacta saídas na fonte e submete comandos de privilégio ao auditor via JSON estruturado. Mantém sessão contínua (*Modo Sticky*). |
| **`@agente-sudo`** | **Auditor de Segurança** | Deliberação crítica em tempo de execução | Avalia requisições em modo *stateless* contra a Constituição. Aplica mitigação automática ou veto preventivo, fiscalizado pelo motor Python. |
| **`@agente-sudo-policy`** | **Gestor Constitucional** | Monopólio legislativo exclusivo | Detém o monopólio exclusivo de legislar sobre as regras em `policies.json`, `meta_policies.json`, `AGENTS.md` e `hooks.json`. Segue o *Rito Proposta-Primeiro*. |
| **`@agente-meta`** | **Guardião de Infraestrutura** | Proteção ativa de integridade | Opera via hook `PreToolUse` bloqueando alterações não autorizadas nos arquivos de governança e plugins. |

---

## 📡 Contrato de Comunicação entre Agentes

A comunicação interna entre o operador e o auditor de segurança segue o schema JSON obrigatório:

### 📤 1. Proposta (`@agente-bash` ➔ `@agente-sudo`)
```json
{
  "command": "systemctl restart bluetooth.service",
  "objective": "Restaurar conectividade do daemon Bluetooth após queda.",
  "blast_radius": [
    "bluetooth.service"
  ],
  "attempt": 1
}
```

### 📥 2. Deliberação (`@agente-sudo` ➔ `@agente-bash`)
```json
{
  "status": "APPROVED | MITIGATED | VETOED | ESCALATED",
  "mitigated_command": null,
  "reason": "Comando em estrita conformidade com a demanda e com a RULE-04.",
  "attempt": 1
}
```

---

## ⚖️ Mini Constituição de Segurança (`v4.0`)

As diretrizes do sistema residem em [`security/policies.json`](security/policies.json) e são fiscalizadas ativamente em tempo de execução pelo motor Python `governance-gate.py`:

<details open>
<summary><b>🔍 Clique para expandir os 15 Artigos Constitucionais</b></summary>
<br>

| Código | Nome da Regra | Severidade | Efeito Prático | Fiscalização |
| :---: | :--- | :---: | :--- | :---: |
| **`RULE-01`** | **Soberania do Display** | `CRITICAL` | Veto a alterações em `monitors.lua` ou resoluções sem prévia confirmação humana. | **Hook `force_ask`** |
| **`RULE-02`** | **Anti-Destruição** | `CRITICAL` | Bloqueio de deleção recursiva indiscriminada na raiz (`/`) e em diretórios vitais (`/boot`, `/etc`, etc.). | **Hook `deny` sumário** |
| **`RULE-03`** | **Operações de Disco** | `CRITICAL` | Comandos `mkfs`, `fdisk`, `dd` exigem alvo explícito e blindam partições ativas (`/`, `/boot`). | Auditoria Sudo |
| **`RULE-04`** | **Escopo Estrito** | `HIGH` | O comando com privilégio deve ater-se exclusivamente à necessidade da tarefa solicitada. | Auditoria Sudo |
| **`RULE-05`** | **Preservação de Permissões** | `HIGH` | Veto a permissões globais abusivas (`chmod -R 777` ou `chown -R` no sistema). | Auditoria Sudo |
| **`RULE-06`** | **Sigilo de Credenciais** | `HIGH` | Enforce de `HISTFILE=/dev/null`. Descontinuação e veto permanente a runners com senhas locais. | **Hook `deny`** |
| **`RULE-07`** | **Anti-Crash** | `HIGH` | Proibido matar processos que derrubem a sessão gráfica ativa (Hyprland, Wayland, SDDM, PID 1). | Auditoria Sudo |
| **`RULE-08`** | **Mitigação Ativa** | `MEDIUM` | Remodelação autônoma orientada pelo parecer técnico de veto sem transferir ruído ao usuário. | Loop Auto-Adaptação |
| **`RULE-09`** | **Franquia de Diagnóstico** | `INFO` | Acesso instantâneo e livre para ler métricas, sensores, hardware e logs da máquina. | Execução Livre |
| **`RULE-10`** | **Regra 3X (Teto de Recusas)** | `CRITICAL` | Limite de 3 rejeições consecutivas. Na 3ª recusa, suspensão imediata e alerta de escalação. | Sudo + Alerta |
| **`RULE-11`** | **Monopólio Legislativo** | `CRITICAL` | Exclusividade legislativa do `@agente-sudo-policy`. Veto de escrita nos caminhos de governança. | **Hook `force_ask`** |
| **`RULE-12`** | **Blindagem de Governança** | `CRITICAL` | Arquivos mantidos em `chmod 444`, protegidos no runtime pelo hook `PreToolUse` (`governance-gate.py`). | **Hook PreToolUse** |
| **`RULE-13`** | **Modo Sticky Automático** | `MANDATORY` | O `@agente-bash` assume a sessão contínua até saída explícita ou invocação de outro agente. | Sessão Contínua |
| **`RULE-14`** | **Rito Proposta-Primeiro** | `CRITICAL` | Propostas de regras geram apenas texto no chat; modificações em disco exigem autorização expressa. | **Hook + Política** |
| **`RULE-15`** | **Taxonomia Privilegiada** | `HIGH` | Gatilhos obrigatórios de retenção: `sudo`, `doas`, `pkexec`, `su`, `yay/paru -S`, `mount`, etc. | **Hook `force_ask`** |

</details>

---

## 🚀 Instalação Express em Nova Máquina

Para replicar todo o ecossistema em qualquer máquina Linux em segundos (requer apenas Python 3.8+ padrão, **zero pip**):

```bash
# 1. Clonar o repositório
git clone git@github.com:nickarab/bash-sudo-agents.git
cd bash-sudo-agents

# 2. Executar o instalador automatizado
./install.sh
```

### O que o instalador faz automaticamente:
* 📁 Cria as estruturas em `~/.gemini/config/plugins/bash-sudo-agents` e `~/.gemini/antigravity/scratch/security`.
* 📦 Instala as Skills e as Regras Constitucionais (`AGENTS.md`).
* 🚧 Instala e registra o motor Python `governance-gate.py` (`PreToolUse`) em `hooks.json` com `chmod 555`.
* 🔒 Aplica isolamento de leitura estrita (`chmod 444`) em todos os arquivos de governança.

---

## 📂 Árvore de Diretórios

```text
bash-sudo-agents/
├── 📄 .gitignore                  # Proteção contra vazamento de arquivos locais
├── ⚙️ install.sh                  # Instalador universal automatizado (Zero-Pip)
├── 📘 README.md                   # Esta documentação executiva
├── 🧩 plugin/
│   ├── plugin.json                # Manifesto oficial do plugin Antigravity (v1.3.0)
│   ├── hooks.json                 # Registro do hook chamando python3 ./hooks/governance-gate.py
│   ├── hooks/
│   │   └── governance-gate.py     # 🌟 Motor Python: Segurança, Cache e Auto-Compressor
│   ├── rules/
│   │   └── AGENTS.md              # Mini Constituição injetada no prompt do sistema
│   └── skills/
│       ├── agente-bash/
│       │   └── SKILL.md           # Definição e rotina operacional do Operador
│       └── agente-sudo-policy/
│           └── SKILL.md           # Diretivas e procedimentos do Gestor Constitucional
└── 🔐 security/
    ├── policies.json              # Políticas constitucionais ativas (v3.3)
    ├── meta_policies.json         # Políticas de autodefesa e metagovernança
    ├── agents_manifest.json       # Manifesto de integridade de agentes
    └── README.md                  # Guia de segurança e procedimentos de backup
```

---

<div align="center">

Desenvolvido para máxima segurança, produtividade e confiabilidade operacional no **Antigravity**.  
*Zero dependências externas • Zero vazamento de contexto • 100% Autonomia auditada no runtime.*

</div>
