# Complete 100 Tools Reference — Microsoft Active Directory MCP

This document lists all **100 functional tools** available in the server, organized across the 10 core administrative categories.

---

## Category 1 — Domain & Domain Controllers (Tools 1–10)

| # | Tool Name | Type | Description | Key Parameters |
|---|:---|:---:|:---|:---|
| 1 | `ad_get_domain_info` | READ | Consultar informações detalhadas do domínio atual | `server` |
| 2 | `ad_list_domains` | READ | Listar domínios disponíveis na floresta | — |
| 3 | `ad_get_forest_info` | READ | Consultar informações da floresta Active Directory | — |
| 4 | `ad_list_domain_controllers` | READ | Listar controladores de domínio (DCs) | — |
| 5 | `ad_get_domain_controller_info` | READ | Consultar detalhes de um DC específico | `identity` |
| 6 | `ad_test_domain_controller` | READ | Verificar portas e disponibilidade de um DC | `target_host` |
| 7 | `ad_get_domain_functional_level` | READ | Consultar nível funcional do domínio | — |
| 8 | `ad_get_forest_functional_level` | READ | Consultar nível funcional da floresta | — |
| 9 | `ad_get_fsmo_roles` | READ | Consultar detentores das 5 funções FSMO | — |
| 10 | `ad_get_domain_trusts` | READ | Consultar relações de confiança (Trusts) | — |

---

## Category 2 — Users (Tools 11–20)

| # | Tool Name | Type | Description | Key Parameters |
|---|:---|:---:|:---|:---|
| 11 | `ad_list_users` | READ | Listar usuários com filtros | `limit`, `search_base`, `enabled_only` |
| 12 | `ad_get_user` | READ | Consultar detalhes completos de um usuário | `identity`, `properties` |
| 13 | `ad_search_users` | READ | Pesquisar usuários por nome, login ou e-mail | `query`, `limit` |
| 14 | `ad_create_user` | WRITE | Criar novo usuário no Active Directory | `sam_account_name`, `path`, `password` |
| 15 | `ad_update_user` | WRITE | Atualizar atributos de um usuário existente | `identity`, `mail`, `title`, `department` |
| 16 | `ad_disable_user` | WRITE | Desabilitar conta de usuário | `identity`, `confirmation_token` |
| 17 | `ad_enable_user` | WRITE | Habilitar conta de usuário | `identity`, `confirmation_token` |
| 18 | `ad_delete_user` | DESTRUCTIVE | Excluir conta de usuário com confirmação | `identity`, `confirmation_token` |
| 19 | `ad_unlock_user` | WRITE | Desbloquear conta travada por senha | `identity`, `confirmation_token` |
| 20 | `ad_reset_user_password` | DESTRUCTIVE | Redefinir senha de usuário com segurança | `identity`, `new_password` |

---

## Category 3 — Groups & Members (Tools 21–30)

| # | Tool Name | Type | Description | Key Parameters |
|---|:---|:---:|:---|:---|
| 21 | `ad_list_groups` | READ | Listar grupos com filtros de escopo/categoria | `limit`, `group_scope`, `group_category` |
| 22 | `ad_get_group` | READ | Consultar detalhes e contagem de membros | `identity` |
| 23 | `ad_create_group` | WRITE | Criar novo grupo no Active Directory | `name`, `path`, `group_scope` |
| 24 | `ad_update_group` | WRITE | Atualizar atributos de um grupo | `identity`, `description`, `managed_by` |
| 25 | `ad_delete_group` | DESTRUCTIVE | Excluir grupo do Active Directory | `identity`, `confirmation_token` |
| 26 | `ad_add_group_member` | WRITE | Adicionar membro(s) a um grupo | `group`, `members` |
| 27 | `ad_remove_group_member` | WRITE | Remover membro(s) de um grupo | `group`, `members` |
| 28 | `ad_list_group_members` | READ | Listar membros de grupo (diretos ou recursivos) | `identity`, `recursive` |
| 29 | `ad_get_user_groups` | READ | Consultar grupos diretos de um usuário | `identity` |
| 30 | `ad_get_nested_group_membership` | READ | Consultar associação recursiva a grupos | `identity` |

---

## Category 4 — Computers & Devices (Tools 31–40)

| # | Tool Name | Type | Description | Key Parameters |
|---|:---|:---:|:---|:---|
| 31 | `ad_list_computers` | READ | Listar computadores do domínio | `limit`, `search_base`, `enabled_only` |
| 32 | `ad_get_computer` | READ | Consultar detalhes de um computador | `identity` |
| 33 | `ad_search_computers` | READ | Pesquisar computadores por nome ou SO | `query`, `limit` |
| 34 | `ad_create_computer` | WRITE | Criar objeto de computador | `name`, `path` |
| 35 | `ad_update_computer` | WRITE | Atualizar atributos de computador | `identity`, `description`, `location` |
| 36 | `ad_disable_computer` | WRITE | Desabilitar conta de computador | `identity`, `confirmation_token` |
| 37 | `ad_enable_computer` | WRITE | Habilitar conta de computador | `identity`, `confirmation_token` |
| 38 | `ad_delete_computer` | DESTRUCTIVE | Excluir conta de computador | `identity`, `confirmation_token` |
| 39 | `ad_move_computer` | WRITE | Mover computador entre OUs | `identity`, `target_path` |
| 40 | `ad_get_stale_computers` | READ | Identificar computadores inativos | `days`, `limit` |

---

## Category 5 — Organizational Units (OUs) (Tools 41–50)

| # | Tool Name | Type | Description | Key Parameters |
|---|:---|:---:|:---|:---|
| 41 | `ad_list_ous` | READ | Listar Unidades Organizacionais | `search_base`, `limit` |
| 42 | `ad_get_ou` | READ | Consultar detalhes de uma OU | `identity` |
| 43 | `ad_create_ou` | WRITE | Criar nova Unidade Organizacional | `name`, `path`, `protected` |
| 44 | `ad_update_ou` | WRITE | Atualizar atributos de uma OU | `identity`, `description` |
| 45 | `ad_delete_ou` | DESTRUCTIVE | Excluir OU com validação de proteção | `identity`, `recursive` |
| 46 | `ad_move_object` | WRITE | Mover objeto entre OUs | `identity`, `target_ou` |
| 47 | `ad_list_ou_objects` | READ | Listar objetos diretos de uma OU | `ou_distinguished_name`, `object_class` |
| 48 | `ad_get_ou_hierarchy` | READ | Consultar hierarquia completa de OUs | — |
| 49 | `ad_get_ou_protection_status` | READ | Consultar proteção contra exclusão acidental | `identity` |
| 50 | `ad_set_ou_protection` | WRITE | Habilitar/desabilitar proteção contra exclusão | `identity`, `protected` |

---

## Category 6 — Group Policy Objects (GPOs) (Tools 51–60)

| # | Tool Name | Type | Description | Key Parameters |
|---|:---|:---:|:---|:---|
| 51 | `ad_list_gpos` | READ | Listar todas as GPOs do domínio | `limit` |
| 52 | `ad_get_gpo` | READ | Consultar detalhes de uma GPO | `identity` |
| 53 | `ad_create_gpo` | WRITE | Criar nova Group Policy Object | `name`, `comment` |
| 54 | `ad_update_gpo` | WRITE | Atualizar configurações de GPO | `identity`, `comment`, `gpo_status` |
| 55 | `ad_delete_gpo` | DESTRUCTIVE | Excluir GPO com confirmação | `identity`, `confirmation_token` |
| 56 | `ad_link_gpo` | WRITE | Vincular GPO a site, domínio ou OU | `gpo_identity`, `target_dn`, `enabled` |
| 57 | `ad_unlink_gpo` | WRITE | Remover vínculo de GPO | `gpo_identity`, `target_dn` |
| 58 | `ad_get_gpo_links` | READ | Consultar vínculos de GPO em OU/domínio | `target_dn` |
| 59 | `ad_get_gpo_report` | READ | Gerar relatório XML/HTML de GPO | `identity`, `report_type` |
| 60 | `ad_compare_gpos` | READ | Comparar duas GPOs | `gpo_a`, `gpo_b` |

---

## Category 7 — DNS & Infrastructure (Tools 61–70)

| # | Tool Name | Type | Description | Key Parameters |
|---|:---|:---:|:---|:---|
| 61 | `ad_list_dns_zones` | READ | Listar zonas DNS integradas ao AD | — |
| 62 | `ad_get_dns_zone` | READ | Consultar detalhes e configurações de zona | `zone_name` |
| 63 | `ad_list_dns_records` | READ | Listar registros DNS de uma zona | `zone_name`, `record_type`, `limit` |
| 64 | `ad_get_dns_record` | READ | Consultar registro DNS específico | `zone_name`, `name`, `record_type` |
| 65 | `ad_create_dns_record` | WRITE | Criar registro DNS (A, CNAME, etc.) | `zone_name`, `name`, `ipv4_address` |
| 66 | `ad_update_dns_record` | WRITE | Atualizar registro DNS existente | `zone_name`, `name`, `new_ipv4_address` |
| 67 | `ad_delete_dns_record` | DESTRUCTIVE | Excluir registro DNS de uma zona | `zone_name`, `name`, `record_type` |
| 68 | `ad_test_dns_resolution` | READ | Testar resolução de nomes DNS | `name`, `dns_server` |
| 69 | `ad_test_ldap_connectivity` | READ | Testar conectividade na porta LDAP/LDAPS | `server`, `port` |
| 70 | `ad_test_kerberos_connectivity` | READ | Verificar conectividade Kerberos porta 88 | `server` |

---

## Category 8 — Security & Audit (Tools 71–80)

| # | Tool Name | Type | Description | Key Parameters |
|---|:---|:---:|:---|:---|
| 71 | `ad_get_locked_accounts` | READ | Listar contas de usuário bloqueadas | `limit` |
| 72 | `ad_get_disabled_accounts` | READ | Listar todas as contas desabilitadas | `limit` |
| 73 | `ad_get_password_expiring_users` | READ | Identificar senhas próximas do vencimento | `days`, `limit` |
| 74 | `ad_get_password_never_expires_users` | READ | Identificar contas com 'Senha Nunca Expira' | `limit` |
| 75 | `ad_get_privileged_users` | READ | Identificar usuários em grupos administrativos | — |
| 76 | `ad_get_domain_admins` | READ | Consultar membros do grupo 'Domain Admins' | — |
| 77 | `ad_get_admin_count_users` | READ | Identificar contas com adminCount=1 | — |
| 78 | `ad_get_inactive_users` | READ | Identificar usuários sem atividade recente | `days`, `limit` |
| 79 | `ad_get_delegated_permissions` | READ | Auditar permissões delegadas em objeto/OU | `identity` |
| 80 | `ad_get_security_group_changes` | READ | Consultar alterações em grupos nos logs | `hours`, `limit` |

---

## Category 9 — Replication & Health (Tools 81–90)

| # | Tool Name | Type | Description | Key Parameters |
|---|:---|:---:|:---|:---|
| 81 | `ad_get_replication_status` | READ | Consultar estado geral da replicação | `server` |
| 82 | `ad_get_replication_partners` | READ | Listar parceiros de replicação | `server` |
| 83 | `ad_get_replication_failures` | READ | Identificar falhas de replicação | `server` |
| 84 | `ad_sync_replication` | WRITE | Solicitar sincronização imediata | `target_dc`, `all_dcs` |
| 85 | `ad_get_dc_services_status` | READ | Consultar estado dos serviços essenciais (NTDS, KDC, DNS) | `server` |
| 86 | `ad_get_dc_event_logs` | READ | Consultar eventos recentes nos logs do DC | `log_name`, `hours`, `limit` |
| 87 | `ad_get_directory_health` | READ | Executar verificações de integridade | `server` |
| 88 | `ad_test_secure_channel` | READ | Testar canal seguro de computadores | `computer_name` |
| 89 | `ad_get_time_sync_status` | READ | Verificar status de sincronização de horário | `server` |
| 90 | `ad_get_sysvol_status` | READ | Verificar compartilhamentos SYSVOL e Netlogon | `server` |

---

## Category 10 — Reports & Automation (Tools 91–100)

| # | Tool Name | Type | Description | Key Parameters |
|---|:---|:---:|:---|:---|
| 91 | `ad_generate_domain_inventory` | READ | Gerar inventário consolidado do domínio | `output_format` (json/html) |
| 92 | `ad_generate_user_report` | READ | Gerar relatório detalhado de usuários | `output_format`, `limit` |
| 93 | `ad_generate_group_report` | READ | Gerar relatório de grupos e membros | `output_format`, `limit` |
| 94 | `ad_generate_computer_report` | READ | Gerar relatório de computadores e SO | `output_format`, `limit` |
| 95 | `ad_generate_gpo_report` | READ | Gerar relatório consolidado de GPOs | `output_format` |
| 96 | `ad_generate_security_audit_report` | READ | Relatório executivo de auditoria de segurança | `output_format` |
| 97 | `ad_generate_inactive_accounts_report` | READ | Relatório de contas inativas (usuários/computadores) | `days`, `output_format` |
| 98 | `ad_generate_domain_health_report` | READ | Relatório executivo de saúde do domínio | `output_format` |
| 99 | `ad_compare_directory_snapshots` | READ | Comparar inventários de períodos diferentes | `snapshot_a`, `snapshot_b` |
| 100 | `ad_run_compliance_assessment` | READ | Executar avaliação de conformidade (regras de segurança) | — |

