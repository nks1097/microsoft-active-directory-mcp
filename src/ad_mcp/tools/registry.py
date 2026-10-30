"""
Tool Registry for Active Directory MCP Server.
Registers, indexes, and validates exactly 100 essential tools.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from ad_mcp.authorization.modes import ActionType, ToolCategory, get_tool_action_type

# Category 4: Computers
from ad_mcp.tools.computers import (
    ad_create_computer,
    ad_delete_computer,
    ad_disable_computer,
    ad_enable_computer,
    ad_get_computer,
    ad_get_stale_computers,
    ad_list_computers,
    ad_move_computer,
    ad_search_computers,
    ad_update_computer,
)

# Category 7: DNS & Infra
from ad_mcp.tools.dns import (
    ad_create_dns_record,
    ad_delete_dns_record,
    ad_get_dns_record,
    ad_get_dns_zone,
    ad_list_dns_records,
    ad_list_dns_zones,
    ad_test_dns_resolution,
    ad_test_kerberos_connectivity,
    ad_test_ldap_connectivity,
    ad_update_dns_record,
)

# Category 1: Domain & DCs
from ad_mcp.tools.domain import (
    ad_get_domain_controller_info,
    ad_get_domain_functional_level,
    ad_get_domain_info,
    ad_get_domain_trusts,
    ad_get_forest_functional_level,
    ad_get_forest_info,
    ad_get_fsmo_roles,
    ad_list_domain_controllers,
    ad_list_domains,
    ad_test_domain_controller,
)

# Category 6: GPOs
from ad_mcp.tools.gpo import (
    ad_compare_gpos,
    ad_create_gpo,
    ad_delete_gpo,
    ad_get_gpo,
    ad_get_gpo_links,
    ad_get_gpo_report,
    ad_link_gpo,
    ad_list_gpos,
    ad_unlink_gpo,
    ad_update_gpo,
)

# Category 3: Groups
from ad_mcp.tools.groups import (
    ad_add_group_member,
    ad_create_group,
    ad_delete_group,
    ad_get_group,
    ad_get_nested_group_membership,
    ad_get_user_groups,
    ad_list_group_members,
    ad_list_groups,
    ad_remove_group_member,
    ad_update_group,
)

# Category 5: OUs
from ad_mcp.tools.ous import (
    ad_create_ou,
    ad_delete_ou,
    ad_get_ou,
    ad_get_ou_hierarchy,
    ad_get_ou_protection_status,
    ad_list_ou_objects,
    ad_list_ous,
    ad_move_object,
    ad_set_ou_protection,
    ad_update_ou,
)

# Category 9: Replication & Health
from ad_mcp.tools.replication import (
    ad_get_dc_event_logs,
    ad_get_dc_services_status,
    ad_get_directory_health,
    ad_get_replication_failures,
    ad_get_replication_partners,
    ad_get_replication_status,
    ad_get_sysvol_status,
    ad_get_time_sync_status,
    ad_sync_replication,
    ad_test_secure_channel,
)

# Category 10: Reports & Inventory
from ad_mcp.tools.reports import (
    ad_compare_directory_snapshots,
    ad_generate_computer_report,
    ad_generate_domain_health_report,
    ad_generate_domain_inventory,
    ad_generate_gpo_report,
    ad_generate_group_report,
    ad_generate_inactive_accounts_report,
    ad_generate_security_audit_report,
    ad_generate_user_report,
    ad_run_compliance_assessment,
)

# Category 8: Security & Audit
from ad_mcp.tools.security import (
    ad_get_admin_count_users,
    ad_get_delegated_permissions,
    ad_get_disabled_accounts,
    ad_get_domain_admins,
    ad_get_inactive_users,
    ad_get_locked_accounts,
    ad_get_password_expiring_users,
    ad_get_password_never_expires_users,
    ad_get_privileged_users,
    ad_get_security_group_changes,
)

# Category 2: Users
from ad_mcp.tools.users import (
    ad_create_user,
    ad_delete_user,
    ad_disable_user,
    ad_enable_user,
    ad_get_user,
    ad_list_users,
    ad_reset_user_password,
    ad_search_users,
    ad_unlock_user,
    ad_update_user,
)


@dataclass
class ToolDefinition:
    name: str
    category: ToolCategory
    action_type: ActionType
    handler: Callable[..., Any]
    description: str


class ToolRegistry:
    """Manages the catalogue of 100 Active Directory tools."""

    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._register_all_tools()

    def register(
        self,
        name: str,
        category: ToolCategory,
        handler: Callable[..., Any],
        description: str,
    ) -> None:
        action_type = get_tool_action_type(name)
        self._tools[name] = ToolDefinition(
            name=name,
            category=category,
            action_type=action_type,
            handler=handler,
            description=description,
        )

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def list_tools(self) -> List[ToolDefinition]:
        return list(self._tools.values())

    def count(self) -> int:
        return len(self._tools)

    def _register_all_tools(self) -> None:
        # Category 1: Domain (10 tools)
        self.register(
            "ad_get_domain_info",
            ToolCategory.DOMAIN,
            ad_get_domain_info,
            "Consultar informacoes detalhadas do dominio atual.",
        )
        self.register(
            "ad_list_domains", ToolCategory.DOMAIN, ad_list_domains, "Listar dominios disponiveis na floresta."
        )
        self.register(
            "ad_get_forest_info",
            ToolCategory.DOMAIN,
            ad_get_forest_info,
            "Consultar informacoes da floresta Active Directory.",
        )
        self.register(
            "ad_list_domain_controllers",
            ToolCategory.DOMAIN,
            ad_list_domain_controllers,
            "Listar controladores de dominio.",
        )
        self.register(
            "ad_get_domain_controller_info",
            ToolCategory.DOMAIN,
            ad_get_domain_controller_info,
            "Consultar detalhes de um DC.",
        )
        self.register(
            "ad_test_domain_controller",
            ToolCategory.DOMAIN,
            ad_test_domain_controller,
            "Verificar disponibilidade de um DC.",
        )
        self.register(
            "ad_get_domain_functional_level",
            ToolCategory.DOMAIN,
            ad_get_domain_functional_level,
            "Consultar nivel funcional do dominio.",
        )
        self.register(
            "ad_get_forest_functional_level",
            ToolCategory.DOMAIN,
            ad_get_forest_functional_level,
            "Consultar nivel funcional da floresta.",
        )
        self.register(
            "ad_get_fsmo_roles", ToolCategory.DOMAIN, ad_get_fsmo_roles, "Consultar detentores das funcoes FSMO."
        )
        self.register(
            "ad_get_domain_trusts", ToolCategory.DOMAIN, ad_get_domain_trusts, "Consultar relacoes de confianca."
        )

        # Category 2: Users (10 tools)
        self.register("ad_list_users", ToolCategory.USERS, ad_list_users, "Listar usuarios com filtros configuraveis.")
        self.register("ad_get_user", ToolCategory.USERS, ad_get_user, "Consultar detalhes de um usuario.")
        self.register(
            "ad_search_users",
            ToolCategory.USERS,
            ad_search_users,
            "Pesquisar usuarios por nome, login, e-mail ou atributo.",
        )
        self.register("ad_create_user", ToolCategory.USERS, ad_create_user, "Criar novo usuario no Active Directory.")
        self.register("ad_update_user", ToolCategory.USERS, ad_update_user, "Atualizar atributos de usuario existente.")
        self.register("ad_disable_user", ToolCategory.USERS, ad_disable_user, "Desabilitar conta de usuario.")
        self.register("ad_enable_user", ToolCategory.USERS, ad_enable_user, "Habilitar conta de usuario.")
        self.register("ad_delete_user", ToolCategory.USERS, ad_delete_user, "Excluir conta de usuario com confirmacao.")
        self.register("ad_unlock_user", ToolCategory.USERS, ad_unlock_user, "Desbloquear conta travada.")
        self.register(
            "ad_reset_user_password",
            ToolCategory.USERS,
            ad_reset_user_password,
            "Redefinir senha de usuario com seguranca.",
        )

        # Category 3: Groups (10 tools)
        self.register(
            "ad_list_groups", ToolCategory.GROUPS, ad_list_groups, "Listar grupos com filtros de escopo e categoria."
        )
        self.register(
            "ad_get_group", ToolCategory.GROUPS, ad_get_group, "Consultar detalhes e contagem de membros de grupo."
        )
        self.register("ad_create_group", ToolCategory.GROUPS, ad_create_group, "Criar novo grupo no Active Directory.")
        self.register("ad_update_group", ToolCategory.GROUPS, ad_update_group, "Atualizar atributos de um grupo.")
        self.register("ad_delete_group", ToolCategory.GROUPS, ad_delete_group, "Excluir grupo do Active Directory.")
        self.register(
            "ad_add_group_member", ToolCategory.GROUPS, ad_add_group_member, "Adicionar membro(s) a um grupo."
        )
        self.register(
            "ad_remove_group_member", ToolCategory.GROUPS, ad_remove_group_member, "Remover membro(s) de um grupo."
        )
        self.register(
            "ad_list_group_members",
            ToolCategory.GROUPS,
            ad_list_group_members,
            "Listar membros de grupo (diretos ou recursivos).",
        )
        self.register("ad_get_user_groups", ToolCategory.GROUPS, ad_get_user_groups, "Consultar grupos de um usuario.")
        self.register(
            "ad_get_nested_group_membership",
            ToolCategory.GROUPS,
            ad_get_nested_group_membership,
            "Consultar associacao recursiva a grupos.",
        )

        # Category 4: Computers (10 tools)
        self.register("ad_list_computers", ToolCategory.COMPUTERS, ad_list_computers, "Listar computadores do dominio.")
        self.register(
            "ad_get_computer", ToolCategory.COMPUTERS, ad_get_computer, "Consultar detalhes de um computador."
        )
        self.register(
            "ad_search_computers",
            ToolCategory.COMPUTERS,
            ad_search_computers,
            "Pesquisar computadores por nome, sistema operacional ou OU.",
        )
        self.register("ad_create_computer", ToolCategory.COMPUTERS, ad_create_computer, "Criar objeto de computador.")
        self.register(
            "ad_update_computer", ToolCategory.COMPUTERS, ad_update_computer, "Atualizar atributos de computador."
        )
        self.register(
            "ad_disable_computer", ToolCategory.COMPUTERS, ad_disable_computer, "Desabilitar conta de computador."
        )
        self.register(
            "ad_enable_computer", ToolCategory.COMPUTERS, ad_enable_computer, "Habilitar conta de computador."
        )
        self.register("ad_delete_computer", ToolCategory.COMPUTERS, ad_delete_computer, "Excluir conta de computador.")
        self.register("ad_move_computer", ToolCategory.COMPUTERS, ad_move_computer, "Mover computador entre OUs.")
        self.register(
            "ad_get_stale_computers",
            ToolCategory.COMPUTERS,
            ad_get_stale_computers,
            "Identificar computadores inativos ha determinado periodo.",
        )

        # Category 5: OUs (10 tools)
        self.register("ad_list_ous", ToolCategory.OUS, ad_list_ous, "Listar unidades organizacionais (OUs).")
        self.register("ad_get_ou", ToolCategory.OUS, ad_get_ou, "Consultar detalhes de uma OU.")
        self.register("ad_create_ou", ToolCategory.OUS, ad_create_ou, "Criar nova Unidade Organizacional.")
        self.register("ad_update_ou", ToolCategory.OUS, ad_update_ou, "Atualizar atributos de uma OU.")
        self.register(
            "ad_delete_ou", ToolCategory.OUS, ad_delete_ou, "Excluir OU com validacao de protecao e conteudo."
        )
        self.register("ad_move_object", ToolCategory.OUS, ad_move_object, "Mover qualquer objeto entre OUs.")
        self.register("ad_list_ou_objects", ToolCategory.OUS, ad_list_ou_objects, "Listar objetos de uma OU.")
        self.register(
            "ad_get_ou_hierarchy", ToolCategory.OUS, ad_get_ou_hierarchy, "Consultar hierarquia completa de OUs."
        )
        self.register(
            "ad_get_ou_protection_status",
            ToolCategory.OUS,
            ad_get_ou_protection_status,
            "Consultar estado da protecao contra exclusao acidental.",
        )
        self.register(
            "ad_set_ou_protection",
            ToolCategory.OUS,
            ad_set_ou_protection,
            "Habilitar ou desabilitar protecao contra exclusao acidental.",
        )

        # Category 6: GPOs (10 tools)
        self.register("ad_list_gpos", ToolCategory.GPOS, ad_list_gpos, "Listar todas as Group Policy Objects (GPOs).")
        self.register("ad_get_gpo", ToolCategory.GPOS, ad_get_gpo, "Consultar detalhes de uma GPO.")
        self.register("ad_create_gpo", ToolCategory.GPOS, ad_create_gpo, "Criar nova GPO.")
        self.register("ad_update_gpo", ToolCategory.GPOS, ad_update_gpo, "Atualizar configuracoes suportadas de GPO.")
        self.register("ad_delete_gpo", ToolCategory.GPOS, ad_delete_gpo, "Excluir GPO com confirmacao.")
        self.register("ad_link_gpo", ToolCategory.GPOS, ad_link_gpo, "Vincular GPO a site, dominio ou OU.")
        self.register("ad_unlink_gpo", ToolCategory.GPOS, ad_unlink_gpo, "Remover vinculo de GPO.")
        self.register(
            "ad_get_gpo_links",
            ToolCategory.GPOS,
            ad_get_gpo_links,
            "Consultar vinculos de GPO em um site, dominio ou OU.",
        )
        self.register("ad_get_gpo_report", ToolCategory.GPOS, ad_get_gpo_report, "Gerar relatorio XML ou HTML de GPO.")
        self.register(
            "ad_compare_gpos", ToolCategory.GPOS, ad_compare_gpos, "Comparar configuracoes e status de duas GPOs."
        )

        # Category 7: DNS & Infra (10 tools)
        self.register(
            "ad_list_dns_zones", ToolCategory.DNS, ad_list_dns_zones, "Listar zonas DNS integradas ao Active Directory."
        )
        self.register(
            "ad_get_dns_zone", ToolCategory.DNS, ad_get_dns_zone, "Consultar detalhes e configuracoes de zona DNS."
        )
        self.register("ad_list_dns_records", ToolCategory.DNS, ad_list_dns_records, "Listar registros DNS de uma zona.")
        self.register("ad_get_dns_record", ToolCategory.DNS, ad_get_dns_record, "Consultar registro DNS especifico.")
        self.register("ad_create_dns_record", ToolCategory.DNS, ad_create_dns_record, "Criar registro DNS no AD.")
        self.register(
            "ad_update_dns_record", ToolCategory.DNS, ad_update_dns_record, "Atualizar registro DNS existente."
        )
        self.register(
            "ad_delete_dns_record", ToolCategory.DNS, ad_delete_dns_record, "Excluir registro DNS de uma zona."
        )
        self.register(
            "ad_test_dns_resolution", ToolCategory.DNS, ad_test_dns_resolution, "Testar resolucao de nomes DNS."
        )
        self.register(
            "ad_test_ldap_connectivity", ToolCategory.DNS, ad_test_ldap_connectivity, "Testar conectividade LDAP/LDAPS."
        )
        self.register(
            "ad_test_kerberos_connectivity",
            ToolCategory.DNS,
            ad_test_kerberos_connectivity,
            "Verificar conectividade e funcionamento do Kerberos.",
        )

        # Category 8: Security & Audit (10 tools)
        self.register(
            "ad_get_locked_accounts", ToolCategory.SECURITY, ad_get_locked_accounts, "Listar contas bloqueadas."
        )
        self.register(
            "ad_get_disabled_accounts", ToolCategory.SECURITY, ad_get_disabled_accounts, "Listar contas desabilitadas."
        )
        self.register(
            "ad_get_password_expiring_users",
            ToolCategory.SECURITY,
            ad_get_password_expiring_users,
            "Identificar senhas proximas do vencimento.",
        )
        self.register(
            "ad_get_password_never_expires_users",
            ToolCategory.SECURITY,
            ad_get_password_never_expires_users,
            "Identificar contas com senha que nunca expira.",
        )
        self.register(
            "ad_get_privileged_users",
            ToolCategory.SECURITY,
            ad_get_privileged_users,
            "Identificar usuarios em grupos privilegiados.",
        )
        self.register(
            "ad_get_domain_admins",
            ToolCategory.SECURITY,
            ad_get_domain_admins,
            "Consultar membros do grupo Domain Admins.",
        )
        self.register(
            "ad_get_admin_count_users",
            ToolCategory.SECURITY,
            ad_get_admin_count_users,
            "Identificar contas com atributo adminCount relevante.",
        )
        self.register(
            "ad_get_inactive_users",
            ToolCategory.SECURITY,
            ad_get_inactive_users,
            "Identificar usuarios sem atividade recente.",
        )
        self.register(
            "ad_get_delegated_permissions",
            ToolCategory.SECURITY,
            ad_get_delegated_permissions,
            "Auditar delegacoes de permissoes em objetos.",
        )
        self.register(
            "ad_get_security_group_changes",
            ToolCategory.SECURITY,
            ad_get_security_group_changes,
            "Consultar alteracoes em grupos de seguranca nos logs.",
        )

        # Category 9: Replication & Health (10 tools)
        self.register(
            "ad_get_replication_status",
            ToolCategory.REPLICATION,
            ad_get_replication_status,
            "Consultar estado da replicacao.",
        )
        self.register(
            "ad_get_replication_partners",
            ToolCategory.REPLICATION,
            ad_get_replication_partners,
            "Listar parceiros de replicacao.",
        )
        self.register(
            "ad_get_replication_failures",
            ToolCategory.REPLICATION,
            ad_get_replication_failures,
            "Identificar falhas de replicacao.",
        )
        self.register(
            "ad_sync_replication",
            ToolCategory.REPLICATION,
            ad_sync_replication,
            "Solicitar sincronizacao de replicacao.",
        )
        self.register(
            "ad_get_dc_services_status",
            ToolCategory.REPLICATION,
            ad_get_dc_services_status,
            "Consultar estado dos servicos essenciais do DC.",
        )
        self.register(
            "ad_get_dc_event_logs",
            ToolCategory.REPLICATION,
            ad_get_dc_event_logs,
            "Consultar eventos relevantes dos controladores.",
        )
        self.register(
            "ad_get_directory_health",
            ToolCategory.REPLICATION,
            ad_get_directory_health,
            "Executar verificacoes de saude do Active Directory.",
        )
        self.register(
            "ad_test_secure_channel",
            ToolCategory.REPLICATION,
            ad_test_secure_channel,
            "Testar canal seguro de computadores.",
        )
        self.register(
            "ad_get_time_sync_status",
            ToolCategory.REPLICATION,
            ad_get_time_sync_status,
            "Verificar sincronizacao de horario.",
        )
        self.register(
            "ad_get_sysvol_status",
            ToolCategory.REPLICATION,
            ad_get_sysvol_status,
            "Verificar disponibilidade e estado do SYSVOL.",
        )

        # Category 10: Reports & Inventory (10 tools)
        self.register(
            "ad_generate_domain_inventory",
            ToolCategory.REPORTS,
            ad_generate_domain_inventory,
            "Gerar inventario completo do dominio.",
        )
        self.register(
            "ad_generate_user_report", ToolCategory.REPORTS, ad_generate_user_report, "Gerar relatorio de usuarios."
        )
        self.register(
            "ad_generate_group_report", ToolCategory.REPORTS, ad_generate_group_report, "Gerar relatorio de grupos."
        )
        self.register(
            "ad_generate_computer_report",
            ToolCategory.REPORTS,
            ad_generate_computer_report,
            "Gerar relatorio de computadores.",
        )
        self.register(
            "ad_generate_gpo_report",
            ToolCategory.REPORTS,
            ad_generate_gpo_report,
            "Gerar relatorio consolidado de GPOs.",
        )
        self.register(
            "ad_generate_security_audit_report",
            ToolCategory.REPORTS,
            ad_generate_security_audit_report,
            "Gerar relatorio de auditoria de seguranca.",
        )
        self.register(
            "ad_generate_inactive_accounts_report",
            ToolCategory.REPORTS,
            ad_generate_inactive_accounts_report,
            "Relatorio de contas inativas.",
        )
        self.register(
            "ad_generate_domain_health_report",
            ToolCategory.REPORTS,
            ad_generate_domain_health_report,
            "Relatorio de saude do dominio.",
        )
        self.register(
            "ad_compare_directory_snapshots",
            ToolCategory.REPORTS,
            ad_compare_directory_snapshots,
            "Comparar inventarios de periodos diferentes.",
        )
        self.register(
            "ad_run_compliance_assessment",
            ToolCategory.REPORTS,
            ad_run_compliance_assessment,
            "Executar avaliacao de conformidade baseada em regras.",
        )

        # Assert exactly 100 tools are registered
        assert len(self._tools) == 100, f"Expected 100 tools, but found {len(self._tools)}"


registry = ToolRegistry()
