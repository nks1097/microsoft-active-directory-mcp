# Microsoft Active Directory MCP Server — 100 Essential Tools

[![CI Pipeline](https://github.com/nks1097/microsoft-active-directory-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/nks1097/microsoft-active-directory-mcp/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![MCP Specification](https://img.shields.io/badge/MCP-SDK%202.x-green.svg)](https://modelcontextprotocol.io/)
[![Tools Count](https://img.shields.io/badge/tools-100%20functional-orange.svg)](#3-catálogo-das-100-ferramentas)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A complete, production-ready, open-source **Model Context Protocol (MCP)** server for **Microsoft Active Directory Domain Services (AD DS)** featuring **exactly 100 functional tools** for directory administration, automation, security auditing, health diagnostics, and compliance reporting.

Designed to allow AI agents (Claude Desktop, Cursor, Antigravity, custom agents) to securely interact with Active Directory using natural language while enforcing least-privilege, write-approval workflows, and immutable audit logs.

---

## 1. Destaques e Funcionalidades (Key Features)

- **100 Ferramentas 100% Funcionais**: Nenhuma ferramenta fictícia ou apenas mock. Todas possuem validação estrita, tratamento de erro, timeouts e saída estruturada.
- **Três Modos de Operação**:
  - `READ_ONLY` *(Padrão)*: Consultas, pesquisas e relatórios. Operações de alteração são bloqueadas por segurança.
  - `WRITE_APPROVAL`: Ações administrativas geram tokens criptográficos de confirmação de uso único com expiração (5 min) exigindo aprovação explícita.
  - `FULL_ADMIN`: Execuções administrativas diretas para pipelines de automação, respeitando proteções contra exclusão acidental.
- **Proteção de Objetos Críticos**: Proteção nativa contra exclusão ou alteração de contas e grupos vitais (`Administrator`, `krbtgt`, `Domain Admins`, `Enterprise Admins`, `OU=Domain Controllers`, etc.).
- **Arquitetura Híbrida**: Executa nativamente no Windows com módulos RSAT e fallback via .NET `DirectoryServices`/ADSI, além de suportar conexões remotas via LDAP/LDAPS multiplataforma.
- **Prevenção contra Injeção**: Higienização contra LDAP Injection (RFC 4515) e execução segura de comandos PowerShell com `-EncodedCommand` UTF-16LE.
- **Modo Dry-Run**: Permite simulação prévia (`dry_run=true`) em qualquer ferramenta de escrita para avaliar impacto antes de aplicar alterações.
- **Auditoria Estruturada em JSON**: Registro em tempo real com `correlation_id`, timestamps, operador e mascaramento de senhas e dados sensíveis.

---

## 2. Arquitetura do Sistema

```text
┌────────────────────────────────────────────────────────┐
│             AI Agent (Claude, Cursor, etc.)            │
└──────────────────────────┬─────────────────────────────┘
                           │ MCP Protocol (JSON-RPC)
┌──────────────────────────▼─────────────────────────────┐
│                 AD MCP SERVER (Python 3.12)            │
├────────────────────────────────────────────────────────┤
│ • 100 Tools Registry                                  │
│ • Authorization Gatekeeper (READ_ONLY / APPROVAL)     │
│ • Approval Token Manager (HMAC-SHA256 Single-Use)     │
│ • Guardrails & Injection Prevention                   │
│ • Structured Audit Logger (JSON Lines)                │
└──────────────────────────┬─────────────────────────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
┌─────────────────────────┐ ┌─────────────────────────┐
│ PowerShell RSAT & ADSI  │ │   LDAP / LDAPS (ldap3)  │
│ (Windows Server / 11)   │ │ (Cross-Platform Remote) │
└────────────┬────────────┘ └────────────┬────────────┘
             │                           │
             ▼                           ▼
┌────────────────────────────────────────────────────────┐
│   Microsoft Active Directory Domain Controllers (DCs)  │
└────────────────────────────────────────────────────────┘
```

---

## 3. Catálogo das 100 Ferramentas

O servidor MCP implementa exatamente 100 ferramentas organizadas em 10 categorias essenciais (10 ferramentas por categoria):

### Categoria 1 — Domínio e Controladores de Domínio (1 a 10)
1. `ad_get_domain_info` — Consultar informações detalhadas do domínio atual.
2. `ad_list_domains` — Listar domínios disponíveis na floresta.
3. `ad_get_forest_info` — Consultar informações da floresta Active Directory.
4. `ad_list_domain_controllers` — Listar controladores de domínio (DCs).
5. `ad_get_domain_controller_info` — Consultar detalhes de um DC específico.
6. `ad_test_domain_controller` — Verificar disponibilidade de portas e serviços de um DC.
7. `ad_get_domain_functional_level` — Consultar nível funcional do domínio.
8. `ad_get_forest_functional_level` — Consultar nível funcional da floresta.
9. `ad_get_fsmo_roles` — Consultar detentores das 5 funções FSMO.
10. `ad_get_domain_trusts` — Consultar relações de confiança (Trusts).

### Categoria 2 — Usuários (11 a 20)
11. `ad_list_users` — Listar usuários com filtros configuráveis.
12. `ad_get_user` — Consultar detalhes completos de um usuário.
13. `ad_search_users` — Pesquisar usuários por nome, login, e-mail ou atributo.
14. `ad_create_user` — Criar novo usuário no Active Directory.
15. `ad_update_user` — Atualizar atributos de usuário existente.
16. `ad_disable_user` — Desabilitar conta de usuário.
17. `ad_enable_user` — Habilitar conta de usuário.
18. `ad_delete_user` — Excluir conta de usuário com confirmação obrigatória.
19. `ad_unlock_user` — Desbloquear conta travada por tentativas de senha.
20. `ad_reset_user_password` — Redefinir senha de usuário com segurança.

### Categoria 3 — Grupos e Membros (21 a 30)
21. `ad_list_groups` — Listar grupos com filtros de escopo e categoria.
22. `ad_get_group` — Consultar detalhes e contagem de membros de grupo.
23. `ad_create_group` — Criar novo grupo no Active Directory.
24. `ad_update_group` — Atualizar atributos de um grupo.
25. `ad_delete_group` — Excluir grupo do Active Directory.
26. `ad_add_group_member` — Adicionar membro(s) a um grupo.
27. `ad_remove_group_member` — Remover membro(s) de um grupo.
28. `ad_list_group_members` — Listar membros de grupo (diretos ou recursivos).
29. `ad_get_user_groups` — Consultar grupos dos quais um usuário faz parte.
30. `ad_get_nested_group_membership` — Consultar associação recursiva a grupos (aninhados).

### Categoria 4 — Computadores e Dispositivos (31 a 40)
31. `ad_list_computers` — Listar computadores registrados no domínio.
32. `ad_get_computer` — Consultar detalhes de um computador.
33. `ad_search_computers` — Pesquisar computadores por nome, sistema operacional ou OU.
34. `ad_create_computer` — Criar objeto de computador.
35. `ad_update_computer` — Atualizar atributos de computador.
36. `ad_disable_computer` — Desabilitar conta de computador.
37. `ad_enable_computer` — Habilitar conta de computador.
38. `ad_delete_computer` — Excluir conta de computador.
39. `ad_move_computer` — Mover computador entre OUs.
40. `ad_get_stale_computers` — Identificar computadores inativos há determinado período.

### Categoria 5 — Organizational Units (OU) (41 a 50)
41. `ad_list_ous` — Listar Unidades Organizacionais (OUs).
42. `ad_get_ou` — Consultar detalhes de uma OU.
43. `ad_create_ou` — Criar nova Unidade Organizacional.
44. `ad_update_ou` — Atualizar atributos de uma OU.
45. `ad_delete_ou` — Excluir OU com validação de proteção e conteúdo.
46. `ad_move_object` — Mover qualquer objeto entre OUs.
47. `ad_list_ou_objects` — Listar objetos contidos em uma OU.
48. `ad_get_ou_hierarchy` — Consultar árvore da hierarquia de OUs.
49. `ad_get_ou_protection_status` — Consultar estado da proteção contra exclusão acidental.
50. `ad_set_ou_protection` — Habilitar ou desabilitar proteção contra exclusão acidental.

### Categoria 6 — Group Policy Objects (GPO) (51 a 60)
51. `ad_list_gpos` — Listar todas as Group Policy Objects (GPOs).
52. `ad_get_gpo` — Consultar detalhes de uma GPO.
53. `ad_create_gpo` — Criar nova GPO.
54. `ad_update_gpo` — Atualizar configurações suportadas de GPO.
55. `ad_delete_gpo` — Excluir GPO com confirmação.
56. `ad_link_gpo` — Vincular GPO a site, domínio ou OU.
57. `ad_unlink_gpo` — Remover vínculo de GPO.
58. `ad_get_gpo_links` — Consultar vínculos de GPO em um site, domínio ou OU.
59. `ad_get_gpo_report` — Gerar relatório detalhado XML ou HTML de GPO.
60. `ad_compare_gpos` — Comparar configurações de duas GPOs.

### Categoria 7 — DNS e Infraestrutura (61 a 70)
61. `ad_list_dns_zones` — Listar zonas DNS integradas ao Active Directory.
62. `ad_get_dns_zone` — Consultar detalhes e configurações de zona DNS.
63. `ad_list_dns_records` — Listar registros DNS de uma zona.
64. `ad_get_dns_record` — Consultar registro DNS específico.
65. `ad_create_dns_record` — Criar registro DNS (A, CNAME, etc.).
66. `ad_update_dns_record` — Atualizar registro DNS existente.
67. `ad_delete_dns_record` — Excluir registro DNS de uma zona.
68. `ad_test_dns_resolution` — Testar resolução de nomes DNS.
69. `ad_test_ldap_connectivity` — Testar conectividade na porta LDAP/LDAPS.
70. `ad_test_kerberos_connectivity` — Verificar conectividade Kerberos e estado do cache.

### Categoria 8 — Segurança e Auditoria (71 a 80)
71. `ad_get_locked_accounts` — Listar contas bloqueadas por tentativas de senha.
72. `ad_get_disabled_accounts` — Listar todas as contas desabilitadas do domínio.
73. `ad_get_password_expiring_users` — Identificar senhas próximas do vencimento.
74. `ad_get_password_never_expires_users` — Identificar contas com 'Senha Nunca Expira'.
75. `ad_get_privileged_users` — Identificar usuários em grupos privilegiados.
76. `ad_get_domain_admins` — Consultar membros do grupo 'Domain Admins'.
77. `ad_get_admin_count_users` — Identificar contas com atributo adminCount=1.
78. `ad_get_inactive_users` — Identificar usuários sem atividade recente.
79. `ad_get_delegated_permissions` — Auditar permissões delegadas em objeto ou OU.
80. `ad_get_security_group_changes` — Consultar alterações em grupos nos logs de eventos.

### Categoria 9 — Replicação, Saúde e Diagnóstico (81 a 90)
81. `ad_get_replication_status` — Consultar estado geral da replicação.
82. `ad_get_replication_partners` — Listar parceiros de replicação.
83. `ad_get_replication_failures` — Identificar falhas de replicação do AD.
84. `ad_sync_replication` — Solicitar sincronização imediata de replicação.
85. `ad_get_dc_services_status` — Consultar estado dos serviços essenciais (NTDS, DNS, KDC, etc.).
86. `ad_get_dc_event_logs` — Consultar eventos recentes nos logs do controlador.
87. `ad_get_directory_health` — Executar verificações de integridade e saúde do AD.
88. `ad_test_secure_channel` — Testar canal seguro entre computador e domínio.
89. `ad_get_time_sync_status` — Verificar sincronização de horário com o PDC Emulator.
90. `ad_get_sysvol_status` — Verificar disponibilidade das pastas SYSVOL e Netlogon.

### Categoria 10 — Relatórios, Inventário e Automação (91 a 100)
91. `ad_generate_domain_inventory` — Gerar inventário completo consolidado do domínio.
92. `ad_generate_user_report` — Gerar relatório detalhado de usuários.
93. `ad_generate_group_report` — Gerar relatório de grupos e membros.
94. `ad_generate_computer_report` — Gerar relatório de computadores e sistemas operacionais.
95. `ad_generate_gpo_report` — Gerar relatório consolidado de todas as GPOs.
96. `ad_generate_security_audit_report` — Gerar relatório de auditoria de segurança.
97. `ad_generate_inactive_accounts_report` — Relatório de contas inativas (usuários e computadores).
98. `ad_generate_domain_health_report` — Relatório executivo de saúde do domínio.
99. `ad_compare_directory_snapshots` — Comparar inventários de períodos diferentes.
100. `ad_run_compliance_assessment` — Executar avaliação de conformidade (regras de segurança).

---

## 4. Instalação e Configuração Passo a Passo

### Pré-requisitos
- Python 3.11 ou 3.12+ ([Download Python](https://www.python.org/downloads/))
- Sistema Operacional:
  - **Windows 10/11 ou Windows Server** (Recomendado para integração completa via RSAT/ADSI e Credential Vault).
  - **Linux / macOS** (Suportado para consultas remotas via LDAP/LDAPS).
- Ferramentas RSAT do Active Directory (opcional no cliente, mas altamente recomendado):
  ```powershell
  # Instalação automática do RSAT no Windows 10/11:
  powershell -ExecutionPolicy Bypass -File scripts/install_rsat.ps1
  ```

---

### Passo 1: Clonar e Instalar Dependências

```powershell
# 1. Clone o repositório
git clone https://github.com/nks1097/microsoft-active-directory-mcp.git
cd microsoft-active-directory-mcp

# 2. Executar o instalador automático (Windows):
.\scripts\setup_env.bat

# OU fazer a instalação manual com virtualenv:
python -m venv .venv
.\.venv\Scripts\activate
pip install -e ".[dev]"
```

---

### Passo 2: Configurar o Arquivo `.env`

Copie o modelo `.env.example` para `.env`:
```powershell
copy .env.example .env
```

Edite o arquivo `.env` com os dados do seu controlador de domínio:
```ini
# Modo de Operação (READ_ONLY por padrão para segurança)
AD_MCP_MODE=READ_ONLY

# Endereço e Domínio do Active Directory
AD_SERVER=dc01.corp.contoso.com
AD_DOMAIN=corp.contoso.com
AD_PORT=636
AD_USE_SSL=true
AD_TLS_VALIDATE_CERT=true

# Método de Autenticação Escolhido
AD_AUTH_METHOD=credential_manager
AD_CREDENTIAL_TARGET=AD_MCP_CREDENTIAL
```

---

### Passo 3: Onde e Como Colocar a Senha?

O servidor suporta **3 métodos de autenticação**. Escolha o mais adequado para o seu cenário:

#### Método A: Windows Credential Vault (Recomendado para Produção — Sem Senhas em Texto Puro)
Para evitar que senhas administrativas fiquem expostas em arquivos de texto (`.env` ou `mcp_config.json`), o servidor utiliza o **Cofre de Credenciais do Windows com criptografia DPAPI**.

1. Mantenha no seu `.env`:
   ```ini
   AD_AUTH_METHOD=credential_manager
   AD_CREDENTIAL_TARGET=AD_MCP_CREDENTIAL
   ```
2. No terminal PowerShell, execute o assistente de gravação segura:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/set_production_credentials.ps1
   ```
3. O terminal solicitará as credenciais (a digitação da senha fica oculta):
   ```text
   === Active Directory MCP - Credential Setup ===
   Digite as credenciais da conta de servico do Active Directory.
   Usuario (ex: CONTOSO\svc_ad_mcp ou svc_ad@corp.contoso.com): CONTOSO\svc_ad_mcp
   Senha da conta (a digitacao ficara oculta): **************
   Credencial para 'CONTOSO\svc_ad_mcp' armazenada com sucesso no Windows Credential Manager.
   ```
Pronto! A senha foi gravada com criptografia de sistema operacional vinculada ao seu usuário Windows. O servidor MCP lê a senha da memória criptografada automaticamente em tempo de execução. **Você não precisa colocar senha no `.env` nem no arquivo de configuração do Claude/Cursor.**

---

#### Método B: Autenticação Integrada Windows / Kerberos / SSPI (Sem Senha!)
Se você está executando em uma máquina ingressada no domínio (`domain-joined`) com um usuário que já possui permissão de leitura no Active Directory:

1. Configure no `.env`:
   ```ini
   AD_AUTH_METHOD=windows_integrated
   ```
2. **Deixe usuário e senha em branco!** O servidor utilizará o próprio token de segurança Kerberos da sua sessão Windows ativa via SSPI.

---

#### Método C: Variáveis de Ambiente Diretas (Para Linux, Docker, Containers ou CI/CD)
Se você estiver executando em Linux, Docker ou ambientes onde o Windows Credential Vault não está disponível:

1. Configure no `.env` (ou injete nas variáveis do container/orquestrador):
   ```ini
   AD_AUTH_METHOD=env
   AD_USERNAME=CONTOSO\svc_ad_mcp
   AD_PASSWORD=SuaSenhaForteAqui
   ```

---

### Passo 4: Validar a Conectividade

Antes de conectar ao Claude Desktop ou Antigravity, valide se a comunicação com o Active Directory está perfeita executando o diagnóstico integrado:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/test_connectivity.ps1
```

O diagnóstico validará automaticamente:
* Resolução de nomes DNS do domínio e do DC.
* Portas de rede (53 DNS, 88 Kerberos, 389 LDAP, 445 SMB, 636 LDAPS, 3268 Global Catalog).
* Handshake TLS e certificados digitais.
* Consulta real ao RootDSE do Active Directory.

---

## 5. Como Conectar aos Clientes de IA

### A. Antigravity IDE / VS Code MCP
Abra seu arquivo de configuração MCP (`~/.gemini/config/mcp_config.json`) e insira:

```json
{
  "mcpServers": {
    "active-directory": {
      "command": "C:\\caminho\\para\\microsoft-active-directory-mcp\\.venv\\Scripts\\python.exe",
      "args": ["-m", "ad_mcp"],
      "env": {
        "AD_MCP_MODE": "READ_ONLY",
        "AD_SERVER": "dc01.corp.contoso.com",
        "AD_DOMAIN": "corp.contoso.com",
        "AD_AUTH_METHOD": "credential_manager",
        "AD_CREDENTIAL_TARGET": "AD_MCP_CREDENTIAL"
      }
    }
  }
}
```

### B. Claude Desktop
No Claude Desktop, edite `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "active-directory": {
      "command": "C:\\caminho\\para\\microsoft-active-directory-mcp\\.venv\\Scripts\\python.exe",
      "args": ["-m", "ad_mcp"],
      "env": {
        "AD_MCP_MODE": "READ_ONLY",
        "AD_SERVER": "dc01.corp.contoso.com",
        "AD_DOMAIN": "corp.contoso.com",
        "AD_AUTH_METHOD": "credential_manager",
        "AD_CREDENTIAL_TARGET": "AD_MCP_CREDENTIAL"
      }
    }
  }
}
```

### C. Cursor AI
No Cursor, configure em *Features > MCP Servers* apontando para o binário Python do `.venv` com argumento `-m ad_mcp`.

---

## 6. Exemplos de Consultas em Linguagem Natural

Uma vez conectado, o agente de IA pode responder a perguntas como:

- *"Liste os usuários desabilitados do domínio corp.contoso.com"*
- *"Quais usuários possuem privilégios administrativos no domínio?"*
- *"Encontre computadores que não fazem logon há mais de 90 dias."*
- *"Verifique a saúde dos controladores de domínio e o status da replicação."*
- *"Gere um relatório executivo de segurança em HTML."*
- *"Quais usuários estão com o atributo 'Senha Nunca Expira' ativado?"*

---

## 7. Testes e Qualidade de Código

Para executar a suíte completa de testes unitários automatizados:

```powershell
pytest -v
```

Para verificar conformidade e formatação de código com Ruff:

```powershell
ruff check .
ruff format .
```

---

## 8. Documentação Detalhada

- [Guia de Instalação](docs/installation.md)
- [Referência de Configuração](docs/configuration.md)
- [Arquitetura de Segurança](docs/security.md)
- [Modelos de Autenticação](docs/authentication.md)
- [Delegação de Permissões Mínimas](docs/permissions.md)
- [Catálogo Detalhado das 100 Ferramentas](docs/tools-reference.md)
- [Guia de Resolução de Problemas (Troubleshooting)](docs/troubleshooting.md)
- [Boas Práticas de Implantação em Produção](docs/production-deployment.md)

---

## 9. Licença

Este projeto é open source sob a licença [MIT](LICENSE).
Contribuições da comunidade são bem-vindas! Consulte o [CONTRIBUTING.md](CONTRIBUTING.md).

