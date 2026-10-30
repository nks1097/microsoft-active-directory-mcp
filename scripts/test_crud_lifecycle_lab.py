"""
Laboratory CRUD Lifecycle Verification Script for Active Directory MCP Server.

Validates end-to-end administrative write operations in a controlled lab environment:
1. Group creation (_MCP_LAB_GROUP_99)
2. User creation (_MCP_LAB_USER_99)
3. Group membership assignment
4. User attribute updates
5. Account disable / enable toggling
6. Group membership removal
7. User and Group deletion (clean teardown)

Supports:
- --dry-run: Simulates write operations without touching Active Directory.
- --live: Executes real operations (requires AD_MCP_MODE=WRITE_APPROVAL or FULL_ADMIN).
"""

import argparse
import sys

from ad_mcp.config import OperationMode, settings
from ad_mcp.tools.domain import ad_get_domain_info
from ad_mcp.tools.groups import (
    ad_add_group_member,
    ad_create_group,
    ad_delete_group,
    ad_remove_group_member,
)
from ad_mcp.tools.users import (
    ad_create_user,
    ad_delete_user,
    ad_disable_user,
    ad_enable_user,
    ad_update_user,
)


def run_with_approval_if_needed(tool_func, **kwargs):
    """Executes a tool function, handling the approval token exchange if required."""
    res = tool_func(**kwargs)

    # If the server requested confirmation (WRITE_APPROVAL mode)
    if res.get("requires_approval") and res.get("confirmation_token"):
        token = res["confirmation_token"]
        print(f"       [APPROVAL REQUIRED] Token generated: {token[:16]}... Auto-confirming in lab test.")
        kwargs["confirmation_token"] = token
        res = tool_func(**kwargs)

    return res


def main():
    parser = argparse.ArgumentParser(description="Active Directory MCP CRUD Lifecycle Verification")
    parser.add_argument("--dry-run", action="store_true", help="Simulate write operations (dry-run)")
    parser.add_argument("--live", action="store_true", help="Execute real operations against lab AD")
    args = parser.parse_args()

    if not args.dry_run and not args.live:
        print("Usage: python test_crud_lifecycle_lab.py --dry-run OR --live")
        sys.exit(1)

    dry_run = args.dry_run

    print("==========================================================")
    print("   ACTIVE DIRECTORY MCP - CRUD LIFECYCLE LAB VALIDATION   ")
    print("==========================================================")
    print(f"Target Server: {settings.server}")
    print(f"Target Domain: {settings.domain}")
    print(f"Active Mode:   {settings.mcp_mode.value}")
    print(f"Execution:     {'SIMULATION (Dry-Run)' if dry_run else 'LIVE EXECUTION'}")
    print("==========================================================\n")

    if dry_run:
        # In dry-run simulation mode, temporarily set mode to WRITE_APPROVAL so simulation runs
        settings.mcp_mode = OperationMode.WRITE_APPROVAL

    if not dry_run and settings.mcp_mode == OperationMode.READ_ONLY:
        print("ERRO: O servidor está configurado em READ_ONLY mode.")
        print("Para executar testes de escrita ao vivo, configure AD_MCP_MODE=WRITE_APPROVAL ou FULL_ADMIN no .env.")
        sys.exit(1)

    test_user = "_MCP_LAB_USER_99"
    test_group = "_MCP_LAB_GROUP_99"
    domain = settings.domain or "corp.contoso.com"
    base_dn = settings.effective_base_dn or "DC=corp,DC=contoso,DC=com"
    user_upn = f"{test_user}@{domain}"
    user_path = f"CN=Users,{base_dn}"

    # Step 0: Connectivity & Base DN check
    print("[0/7] Verificando conectividade e informações do domínio...")
    d_info = ad_get_domain_info()
    if not d_info.get("success"):
        print(f"  [FALHA] Não foi possível consultar o domínio: {d_info.get('error')}")
        sys.exit(1)
    print(f"  [OK] Conectado a: {d_info.get('data', {}).get('DnsRoot', domain)}")

    try:
        # Step 1: Create Group
        print(f"\n[1/7] Criando grupo de teste '{test_group}'...")
        res_g = run_with_approval_if_needed(
            ad_create_group,
            name=test_group,
            path=user_path,
            group_scope="Global",
            group_category="Security",
            description="Grupo temporário de validação MCP",
            dry_run=dry_run,
        )
        print(f"  Resultado: {'OK' if res_g.get('success') else 'FALHA: ' + str(res_g.get('error'))}")

        # Step 2: Create User
        print(f"\n[2/7] Criando usuário de teste '{test_user}'...")
        res_u = run_with_approval_if_needed(
            ad_create_user,
            sam_account_name=test_user,
            path=user_path,
            user_principal_name=user_upn,
            display_name="MCP Lab Test User",
            password="LabPassword!9876#",
            dry_run=dry_run,
        )
        print(f"  Resultado: {'OK' if res_u.get('success') else 'FALHA: ' + str(res_u.get('error'))}")

        # Step 3: Add User to Group
        print(f"\n[3/7] Adicionando '{test_user}' ao grupo '{test_group}'...")
        res_mem = run_with_approval_if_needed(
            ad_add_group_member,
            group=test_group,
            members=[test_user],
            dry_run=dry_run,
        )
        print(f"  Resultado: {'OK' if res_mem.get('success') else 'FALHA: ' + str(res_mem.get('error'))}")

        # Step 4: Update User Attributes
        print(f"\n[4/7] Atualizando atributos de '{test_user}' (Departamento, Cargo)...")
        res_upd = run_with_approval_if_needed(
            ad_update_user,
            identity=test_user,
            department="QA Automation",
            title="Senior Test Engineer",
            dry_run=dry_run,
        )
        print(f"  Resultado: {'OK' if res_upd.get('success') else 'FALHA: ' + str(res_upd.get('error'))}")

        # Step 5: Disable / Enable User Account
        print("\n[5/7] Testando suspensão e reativação de conta...")
        res_dis = run_with_approval_if_needed(ad_disable_user, identity=test_user, dry_run=dry_run)
        print(f"  Desabilitar conta: {'OK' if res_dis.get('success') else 'FALHA: ' + str(res_dis.get('error'))}")
        res_enb = run_with_approval_if_needed(ad_enable_user, identity=test_user, dry_run=dry_run)
        print(f"  Reabilitar conta:  {'OK' if res_enb.get('success') else 'FALHA: ' + str(res_enb.get('error'))}")

        # Step 6: Remove User from Group
        print(f"\n[6/7] Removendo '{test_user}' do grupo '{test_group}'...")
        res_rm = run_with_approval_if_needed(
            ad_remove_group_member,
            group=test_group,
            members=[test_user],
            dry_run=dry_run,
        )
        print(f"  Resultado: {'OK' if res_rm.get('success') else 'FALHA: ' + str(res_rm.get('error'))}")

    finally:
        # Step 7: Teardown and Cleanup
        print("\n[7/7] Executando limpeza (Teardown dos objetos de teste)...")
        if not dry_run:
            del_u = run_with_approval_if_needed(ad_delete_user, identity=test_user)
            print(f"  Excluir usuário de teste: {'OK' if del_u.get('success') else 'AVISO: ' + str(del_u.get('error'))}")

            del_g = run_with_approval_if_needed(ad_delete_group, identity=test_group)
            print(f"  Excluir grupo de teste:   {'OK' if del_g.get('success') else 'AVISO: ' + str(del_g.get('error'))}")
        else:
            print("  [SIMULAÇÃO] Nenhum objeto foi alterado no diretório (Dry-run completo).")

    print("\n==========================================================")
    print("   VALIDAÇÃO DO CICLO DE VIDA ADMINISTRATIVO CONCLUÍDA    ")
    print("==========================================================")


if __name__ == "__main__":
    main()
