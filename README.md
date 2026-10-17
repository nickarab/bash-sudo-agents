<div align="center">

# 🛡️ Antigravity Linux Governance
### *Agentes Autônomos de Terminal com Separação de Poderes, Motor Python Nativo, Auto-Compressão e Cache Local (v4.4.0)*

[![Architecture](https://img.shields.io/badge/Architecture-Multi--Agent%20Governance-blueviolet?style=for-the-badge&logo=diagramsdotnet)](https://github.com/nickarab/bash-sudo-agents)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Wayland%20%7C%20Hyprland-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://github.com/nickarab/bash-sudo-agents)
[![Security Level](https://img.shields.io/badge/Governance-Semantic%20%2B%20Policy--as--Code-success?style=for-the-badge&logo=shield)](https://github.com/nickarab/bash-sudo-agents)
[![Runtime Gate](https://img.shields.io/badge/Runtime%20Gate-Python%20PreToolUse-darkgreen?style=for-the-badge&logo=python)](https://github.com/nickarab/bash-sudo-agents)
[![Optimizer](https://img.shields.io/badge/Tokens-Auto--Compressor%20%2B%20Cache-blue?style=for-the-badge)](https://github.com/nickarab/bash-sudo-agents)
[![Tests](https://img.shields.io/badge/Tests-224%2F224%20Passed-brightgreen?style=for-the-badge&logo=pytest)](https://github.com/nickarab/bash-sudo-agents)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20Pip%20(Pure%20Stdlib)-orange?style=for-the-badge)](https://github.com/nickarab/bash-sudo-agents)

<p align="center">
  <b>Um framework agêntico de alto desempenho que transforma o terminal Linux em um ambiente autônomo, governado no runtime e ultra-eficiente no consumo de tokens.</b>
</p>

<p align="center">
  <b>Camada de Governança Semântica, Guardrail em Runtime e Policy-as-Code</b> — não um sandbox de isolamento de kernel.
  <a href="#-escopo-e-limites-não-é-um-sandbox">Ver escopo e limites »</a>
</p>

[Instalação Rápida](#-instalação-express-em-nova-máquina) •
[Arquitetura](#-arquitetura-do-sistema) •
[Escopo & Limites](#-escopo-e-limites-não-é-um-sandbox) •
[Otimização de Tokens & Cache](#-otimização-de-tokens--cache-local) •
[Agentes](#-matriz-de-responsabilidades) •
[Constituição](#-mini-constituição-de-segurança-v40)

---

</div>

## 🌟 Destaques da Arquitetura

<table>
  <tr>
    <td width="50%">
      <h3>🛡️ Camada de Governança Semântica & Taxonomia Anti-Fadiga</h3>
      O operador de terminal (<code>@agente-bash</code>) é orientado por princípios estritos. Elevação rotineira usa <code>ask</code> (respeitando <i>Always Allow</i>), alto impacto usa <code>force_ask</code> e destruição real recebe <code>deny</code> via <code>governance-gate.py</code>.
    </td>
    <td width="50%">
      <h3>⚡ Auto-Compressor Sintático de Tokens</h3>
      Injeção inteligente de limitadores na fonte (<code>head</code>, <code>tail</code>, <code>--no-pager</code>) via <code>overwrite</code> nativo. Blindagem sintática que respeita redirecionamentos e pipes existentes da IA.
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>💾 Cache Local com TTL (Isolado 0700)</h3>
      Comandos estáticos de diagnóstico (<code>lscpu</code>, <code>uname</code>, <code>lspci</code>, <code>pacman -Ss</code> já comprimido) são cacheados localmente com TTL configurável em diretório restrito (<code>0700</code>).
    </td>
    <td width="50%">
      <h3>🔒 Zero-Pip & Failsafe Universal</h3>
      Construído estritamente com a biblioteca padrão do Python 3.8+ (sem necessidade de <code>pip install</code> ou <code>jq</code>) — anotações preguiçosas (PEP 563) mantêm PEP 604/585 compatíveis com 3.8/3.9. Envelopamento global com <code>try/except</code> que impede travamentos da IDE.
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>🧱 Endurecimento Semântico (v4.4.x)</h3>
      <code>deny</code> também para mutação direta de caminhos vitais (<code>mv</code>, <code>cp</code>, <code>install</code>, <code>truncate</code>, <code>tee</code>, <code>ln</code>, <code>&gt;</code>/<code>&gt;&gt;</code>) e recursão em <code>bash -c "..."</code>. Interpretadores inline (<code>python3 -c</code>, <code>perl -e</code>) referenciando caminhos protegidos são retidos.
    </td>
    <td width="50%">
      <h3>🚦 Fail-Closed & Superfície sem Aspas</h3>
      Payload válido sem <code>CommandLine</code> reconhecível vira <code>force_ask</code> (nunca <code>allow</code> silencioso). Padrões de regex operam sobre uma superfície com strings literais removidas — sem falsos positivos em mensagens de commit — preservando substituições <code>$(...)</code> e crases.
    </td>
  </tr>
</table>

---

## 🏗️ Arquitetura do Sistema

```mermaid
flowchart TD
    User(["👤 Usuário Administrador"]) <-->|"Comandos e Diagnósticos"| Bash["🖥️ @agente-bash<br/>(Operador de Terminal)"]
    
    subgraph Governed["⚙️ Execução e Governança no Runtime"]
        Bash -->|"1. Leitura e Diagnóstico Livre"| TermBash["Terminal Seguro: Pipes Limitadores"]
        Bash -->|"2. Disparo de Operação"| Gate{"🚧 governance-gate.py<br/>(Motor Python PreToolUse)"}
        
        Gate -->|"Cache Hit (TTL Válido)"| CacheRead["Leitura Instantânea de Cache"]
        Gate -->|"allow: seguro / leitura livre"| OSExec["Execução no Linux"]
        Gate -->|"ask: sudo / privilégio rotineiro"| AskGrant["Card Nativo c/ Always Allow"]
        Gate -->|"force_ask: disco / monitores / energia"| PromptUser["Confirmação Explícita Sempre"]
        Gate -->|"deny: rm -rf raiz / chmod 777 -R / gov"| HardBlock["🛑 Veto Imediato no Runtime (deny)"]
        
        HardBlock -.->|"Veto / Erro"| LoopAdapt["Loop de Auto-Adaptação (até 3x)"]
        LoopAdapt --> Bash
        LoopAdapt -->|"Teto de 3 Rejeições"| Escalation["🛑 Relatório Estruturado de Escalação Humana"]
        Escalation --> User
        
        AskGrant -->|"Aprovado / Always Allow"| OSExec
        PromptUser -->|"Aprovado pelo Usuário"| OSExec
        CacheRead --> OSExec
    end
    
    subgraph Governance["📜 Governança Constitucional"]
        User <-->|"Gestão Legislativa"| Policy["⚖️ @agente-sudo-policy<br/>(Gestor Constitucional)"]
        Policy -.->|"Mediação Constitucional"| Gate
        Policy -->|"Escrita Segura Proposta-Primeiro"| PoliciesFile["policies.json v4.0<br/>chmod 444"]
    end
```

---

## ⚠️ Escopo e Limites (não é um sandbox)

Este projeto é uma **Camada de Governança Semântica / guardrail de autonomia** para agentes de LLM **cooperativos**. O objetivo é evitar acidentes, reduzir a fadiga de aprovações e economizar tokens — **não** é uma fronteira de isolamento de kernel nem um sandbox contra um agente hostil (jailbroken/injetado).

**O que ele garante:**

* Contenção consistente e auditável das operações de altíssimo risco (`rm -rf /`, `chmod -R 777 /etc`, formatação, energia, derrubada de sessão, edição dos arquivos de governança).
* Taxonomia de decisão previsível (`allow` / `ask` / `force_ask` / `deny`) e registro em `audit.log`.
* Compressão de saída na fonte e cache local com TTL.

**O que ele NÃO garante:**

* Isolamento de processo, usuário, sistema de arquivos ou rede. Um comando que **não** case com as heurísticas (interpretadores, binários não cobertos, `mv`/`cp` para caminhos não mapeados, execução remota) pode passar. A escrita em arquivo vital via redirecionamento com **alvo entre aspas** e o uso de interpretadores sobre caminhos não mapeados são lacunas conhecidas.
* Proteção contra engenharia social do LLM: aprovar **"Always Allow"** em um prompt `ask` de `sudo` libera as próximas elevações daquele recurso.

Se você precisa de isolamento real, combine este guardrail com `bubblewrap`/`firejail`, `systemd-run`/cgroups, usuário dedicado, montagens read-only e/ou containers.

---

## ⚡ Otimização de Tokens & Cache Local

O motor `governance-gate.py` atua ativamente para reduzir o consumo de tokens antes que qualquer texto seja gravado no histórico da sessão:

### 1. Auto-Compressor na Fonte
* **`journalctl`** ➔ Adiciona automaticamente `--no-pager -n 35`.
* **`dmesg`** ➔ Adiciona automaticamente `--color=never | tail -n 35`.
* **`git log`** ➔ Adiciona automaticamente `-n 15`.
* **`pacman -Ss` / `yay -Ss` / `paru -Ss`** ➔ Embute `| head -n 25` diretamente dentro do wrapper de cache.
* **Blindagem Sintática:** Se a IA já tiver configurado redirecionamentos (`>`, `>>`) ou pipes (`|`), o compressor não interfere, garantindo integridade sintática.

### 2. Cache com TTL (Time-To-Live)
* **Local:** `~/.cache/antigravity/bash_agents/` (permissão estrita `0700`)
* **Hardware/Distro Estático** (`lscpu`, `uname -a`, `lspci`, `lsusb`, `cat /etc/os-release`): TTL de **1 hora**.
* **Buscas em Repositórios** (`pacman -Ss`, `yay -Ss`): TTL de **10 minutos** (armazena a saída já truncada em 25 linhas).
* **Comandos Voláteis** (`git status`, `systemctl`, `ps`, testes): **TTL = 0** (nunca cacheados).

---

## 👥 Matriz de Responsabilidades

| Componente | Identidade | Nível de Acesso | Diretiva Primária |
| :--- | :--- | :--- | :--- |
| **`@agente-bash`** | **Operador de Terminal** (LLM) | Leitura irrestrita do SO / Shell sem privilégios | Executa diagnósticos ágeis, compacta saídas na fonte e conduz comandos no terminal. Mantém sessão contínua (*Modo Sticky*). |
| **`governance-gate.py`** | **Motor de Runtime** (Hook SO) | Interceptador nativo `PreToolUse` no SO | Aplica em runtime as regras (RULE-01 a RULE-15), veto sumário a destruição (`deny`), retenção de alto impacto (`force_ask`), elevação com *Always Allow* (`ask`), auto-compressão e cache com TTL. Fail-closed em schema desconhecido. |
| **`@agente-sudo-policy`** | **Gestor Constitucional** (LLM) | Monopólio legislativo exclusivo | Detém o monopólio exclusivo de legislar sobre as regras em `policies.json`, `meta_policies.json`, `AGENTS.md` e `hooks.json`. Segue o *Rito Proposta-Primeiro*. |

---

## 📡 Contrato de Runtime do Motor PreToolUse

O motor `governance-gate.py` opera como camada de governança interceptando cada chamada de ferramenta enviada pelo Antigravity:

### 📥 Entrada (Stdin: Payload do Antigravity)
```json
{
  "toolCall": {
    "name": "run_command",
    "args": {
      "CommandLine": "systemctl restart bluetooth.service",
      "Cwd": "/home/user"
    }
  },
  "stepIdx": 1
}
```

### 📤 Saída (Stdout: Deliberação do Motor no Runtime)
```json
{
  "decision": "allow | ask | force_ask | deny",
  "reason": "Justificativa constitucional ou aviso de retenção (force_ask)",
  "overwrite": {
    "CommandLine": "comando otimizado ou redirecionado para cache"
  }
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
| **`RULE-01`** | **Soberania do Display** | `CRITICAL` | Leitura de `monitors.lua` é livre (`allow`); edição/escrita exige confirmação humana. | **Hook `force_ask`** |
| **`RULE-02`** | **Anti-Destruição** | `CRITICAL` | Bloqueio de deleção recursiva indiscriminada na raiz (`/`) e em diretórios vitais (`/boot`, `/etc`, `/root`, `/opt`, `/srv`, `/mnt`, ...). Cobre também mutação direta (`mv`, `cp`, `truncate`, `tee`, `ln`, `>`/`>>`) e recursão em `bash -c "..."`. | **Hook `deny` sumário** |
| **`RULE-03`** | **Operações de Disco** | `CRITICAL` | Comandos `mkfs`, `fdisk`, `cryptsetup`, `dd` exigem alvo explícito e blindam partições ativas (`/`, `/boot`). | **Hook `force_ask`** |
| **`RULE-04`** | **Escopo Estrito** | `HIGH` | O comando com privilégio deve ater-se exclusivamente à necessidade da tarefa solicitada. | `governance-gate` |
| **`RULE-05`** | **Preservação de Permissões** | `HIGH` | Veto semântico a permissões recursivas abusivas (`chmod -R 777`, `chmod 777 -R`, `a+w` ou `chown -R` no sistema). | **Hook `deny`** |
| **`RULE-06`** | **Sigilo de Credenciais** | `HIGH` | Enforce de `HISTFILE=/dev/null`. Descontinuação e veto permanente a runners com senhas locais. | **Hook `deny`** |
| **`RULE-07`** | **Anti-Crash & Energia** | `HIGH` | Proibido derrubar/reiniciar sessão gráfica (`deny`); `reboot`/`poweroff`/`suspend` exigem confirmação (`force_ask`). | **Hook `deny` / `force_ask`** |
| **`RULE-08`** | **Mitigação Ativa** | `MEDIUM` | Remodelação autônoma orientada pelo parecer técnico de veto sem transferir ruído ao usuário. | Loop Auto-Adaptação |
| **`RULE-09`** | **Franquia de Diagnóstico** | `INFO` | Acesso instantâneo e livre para ler métricas, sensores, hardware e logs da máquina. | Execução Livre |
| **`RULE-10`** | **Regra 3X (Teto de Recusas)** | `CRITICAL` | Limite de 3 rejeições consecutivas. Na 3ª recusa, suspensão imediata e alerta de escalação. | Loop Auto-Adaptação (3X) |
| **`RULE-11`** | **Monopólio Legislativo** | `CRITICAL` | Exclusividade legislativa do `@agente-sudo-policy`. Veto de escrita nos caminhos de governança. | **Hook `deny`** |
| **`RULE-12`** | **Blindagem de Governança** | `CRITICAL` | Arquivos e `hooks.json` mantidos em `chmod 444`, protegidos por `deny` no hook `PreToolUse` (`governance-gate.py`). | **Hook `deny`** |
| **`RULE-13`** | **Modo Sticky Automático** | `MANDATORY` | O `@agente-bash` assume a sessão contínua até saída explícita ou invocação de outro agente. | Sessão Contínua |
| **`RULE-14`** | **Rito Proposta-Primeiro** | `CRITICAL` | Propostas de regras geram apenas texto no chat; modificações em disco exigem autorização expressa. | **Hook + Política** |
| **`RULE-15`** | **Taxonomia Privilegiada** | `HIGH` | Elevação rotineira (`sudo`, `sudoedit`, `doas`, `pkexec`, `su`, `run0`, `yay/pacman -S*`) com suporte a *Always Allow*. | **Hook `ask`** |

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
* 💾 Realiza **backup atômico** com timestamp das instalações anteriores (plugin, políticas e agentes) em `~/.gemini/antigravity/scratch/backups/`.
* 📦 Instala as Skills e as Regras Constitucionais (`AGENTS.md`).
* 🚧 Instala o motor Python `governance-gate.py` (`chmod 555`), executa um **smoke test** e grava o `hooks.json` com o **caminho absoluto** do motor (resolução determinística, independente do `cwd`).
* 🔒 Aplica isolamento de leitura estrita (`chmod 444`) em todos os arquivos de governança.

---

## 🧪 Suíte de Testes e Validação

O framework conta com **224 verificações automatizadas** cobrindo injeção de comandos, recursão destrutiva, mutação de caminhos vitais, interpretadores inline, fail-closed de schema, falsos positivos de aspas, taxonomia `ask`/`force_ask`/`deny`, caminhos de governança, permissões semânticas e compressão:

```bash
# 1. Executar verificador rápido de bypass e regressão (104 testes Zero-Pip / Stdlib pura)
python3 tests/verify_fixes.py

# 2. Executar suíte completa de testes unitários (120 testes via pytest)
pytest tests/test_governance_gate.py
```

---

## 📂 Árvore de Diretórios

```text
bash-sudo-agents/
├── 📄 .gitignore                  # Proteção contra vazamento de arquivos locais
├── ⚙️ install.sh                  # Instalador universal automatizado com backup atômico
├── 📘 README.md                   # Esta documentação executiva
├── 🧪 tests/                      # Suíte de testes automatizados (224 verificações)
│   ├── test_governance_gate.py    # 120 testes unitários (pytest)
│   └── verify_fixes.py            # 104 testes de segurança sem dependências externas
├── 🧩 plugin/
│   ├── plugin.json                # Manifesto oficial do plugin Antigravity (v4.4.0)
│   ├── hooks.json                 # Template do hook (`__GATE_PATH__` -> caminho absoluto na instalação)
│   ├── agents/                    # Agentes nativos declarados no ecossistema Antigravity
│   │   ├── agente-bash.md         # Agente nativo: Operador de Terminal
│   │   └── agente-sudo-policy.md  # Agente nativo: Gestor Constitucional
│   ├── hooks/
│   │   └── governance-gate.py     # 🌟 Motor Python: Firewall Semântico, Cache TTL e Auto-Compressor
│   ├── rules/
│   │   └── AGENTS.md              # Mini Constituição injetada no prompt do sistema
│   └── skills/
│       ├── agente-bash/
│       │   └── SKILL.md           # Definição e rotina operacional do Operador
│       └── agente-sudo-policy/
│           └── SKILL.md           # Diretivas e procedimentos do Gestor Constitucional
└── 🔐 security/
    ├── policies.json              # Políticas constitucionais ativas (v4.0)
    ├── meta_policies.json         # Políticas de autodefesa e metagovernança
    ├── agents_manifest.json       # Manifesto de integridade de agentes
    └── README.md                  # Guia de segurança e procedimentos de backup
```

---

<div align="center">

Desenvolvido para máxima segurança, produtividade e confiabilidade operacional no **Antigravity**.  
*Zero dependências externas • Zero vazamento de contexto • 100% Autonomia auditada no runtime.*

</div>
