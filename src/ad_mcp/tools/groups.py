"""
Tools Category 3: Groups and Members (Tools 21 to 30).
"""

import time
from typing import Any, Dict, List, Optional

from ad_mcp.audit.logger import audit_logger
from ad_mcp.authorization.guardrails import sanitize_powershell_string
from ad_mcp.authorization.rbac import auth_engine
from ad_mcp.integrations.bridge import ad_bridge
from ad_mcp.models.response import ToolResponse


def ad_list_groups(
    limit: int = 100,
    group_scope: Optional[str] = None,
    group_category: Optional[str] = None,
    search_base: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """21. Listar grupos do domínio com filtros de escopo e categoria."""
    start = time.time()
    tool_name = "ad_list_groups"
    params = {"limit": limit, "group_scope": group_scope, "group_category": group_category}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    filter_clauses = ["*"]
    if group_scope:
        filter_clauses.append(f"GroupScope -eq '{sanitize_powershell_string(group_scope)}'")
    if group_category:
        filter_clauses.append(f"GroupCategory -eq '{sanitize_powershell_string(group_category)}'")

    base_clause = f"-SearchBase '{sanitize_powershell_string(search_base)}'" if search_base else ""
    filter_str = " -and ".join(filter_clauses) if len(filter_clauses) > 1 else "*"

    rsat = f"""
    $groups = if ($cred) {{ Get-ADGroup -Filter '{filter_str}' {base_clause} -ResultSetSize {limit} -Properties Description, GroupScope, GroupCategory -Server $adServer -Credential $cred }} else {{ Get-ADGroup -Filter '{filter_str}' {base_clause} -ResultSetSize {limit} -Properties Description, GroupScope, GroupCategory -Server $adServer }}
    $groups | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = $_.SamAccountName
            Name = $_.Name
            DistinguishedName = $_.DistinguishedName
            GroupScope = [string]$_.GroupScope
            GroupCategory = [string]$_.GroupCategory
            Description = $_.Description
        }}
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = if ('{sanitize_powershell_string(search_base)}') {{ '{sanitize_powershell_string(search_base)}' }} else {{ $root.defaultNamingContext }}
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(objectClass=group)"
    $searcher.SizeLimit = {limit}
    $searcher.PropertiesToLoad.AddRange(@("samaccountname", "name", "description", "distinguishedname"))
    $searcher.FindAll() | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = [string]$_.Properties["samaccountname"][0]
            Name = [string]$_.Properties["name"][0]
            DistinguishedName = [string]$_.Properties["distinguishedname"][0]
            Description = [string]$_.Properties["description"][0]
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_group(
    identity: str,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """22. Consultar detalhes de um grupo e contagem de membros."""
    start = time.time()
    tool_name = "ad_get_group"
    params = {"identity": identity}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rsat = f"""
    $g = if ($cred) {{ Get-ADGroup -Identity '{safe_id}' -Properties * -Server $adServer -Credential $cred }} else {{ Get-ADGroup -Identity '{safe_id}' -Properties * -Server $adServer }}
    [PSCustomObject]@{{
        SamAccountName = $g.SamAccountName
        Name = $g.Name
        DistinguishedName = $g.DistinguishedName
        GroupScope = [string]$g.GroupScope
        GroupCategory = [string]$g.GroupCategory
        Description = $g.Description
        MemberCount = if ($g.Members) {{ @($g.Members).Count }} else {{ 0 }}
        SID = [string]$g.SID.Value
        ManagedBy = $g.ManagedBy
        WhenCreated = if ($g.WhenCreated) {{ $g.WhenCreated.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ $null }}
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectClass=group)(|(sAMAccountName={safe_id})(name={safe_id})))"
    $res = $searcher.FindOne()
    if ($res) {{
        $memCount = if ($res.Properties["member"]) {{ $res.Properties["member"].Count }} else {{ 0 }}
        [PSCustomObject]@{{
            SamAccountName = [string]$res.Properties["samaccountname"][0]
            Name = [string]$res.Properties["name"][0]
            DistinguishedName = [string]$res.Properties["distinguishedname"][0]
            Description = [string]$res.Properties["description"][0]
            MemberCount = $memCount
        }}
    }} else {{ throw "Group '{safe_id}' not found." }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_create_group(
    name: str,
    path: str,
    sam_account_name: Optional[str] = None,
    group_scope: str = "Global",
    group_category: str = "Security",
    description: Optional[str] = None,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """23. Criar novo grupo no Active Directory."""
    start = time.time()
    tool_name = "ad_create_group"
    params = {
        "name": name,
        "path": path,
        "sam_account_name": sam_account_name or name,
        "group_scope": group_scope,
        "group_category": group_category,
        "confirmation_token": confirmation_token,
        "dry_run": dry_run,
    }
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=name)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_name = sanitize_powershell_string(name)
    safe_sam = sanitize_powershell_string(sam_account_name or name)
    safe_path = sanitize_powershell_string(path)
    safe_scope = sanitize_powershell_string(group_scope)
    safe_cat = sanitize_powershell_string(group_category)
    safe_desc = sanitize_powershell_string(description) if description else ""

    rsat = f"""
    $params = @{{
        Name = '{safe_name}'
        SamAccountName = '{safe_sam}'
        Path = '{safe_path}'
        GroupScope = '{safe_scope}'
        GroupCategory = '{safe_cat}'
    }}
    if ('{safe_desc}') {{ $params['Description'] = '{safe_desc}' }}
    if ($cred) {{ $params['Server'] = $adServer; $params['Credential'] = $cred }} else {{ $params['Server'] = $adServer }}

    New-ADGroup @params
    [PSCustomObject]@{{
        Status = "CREATED"
        Name = '{safe_name}'
        SamAccountName = '{safe_sam}'
        DistinguishedName = "CN={safe_name},{safe_path}"
        GroupScope = '{safe_scope}'
        GroupCategory = '{safe_cat}'
    }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_update_group(
    identity: str,
    description: Optional[str] = None,
    display_name: Optional[str] = None,
    managed_by: Optional[str] = None,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """24. Atualizar atributos de um grupo."""
    start = time.time()
    tool_name = "ad_update_group"
    params = {
        "identity": identity,
        "description": description,
        "managed_by": managed_by,
        "confirmation_token": confirmation_token,
        "dry_run": dry_run,
    }
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    updates = []
    if description is not None:
        updates.append(f"-Description '{sanitize_powershell_string(description)}'")
    if display_name is not None:
        updates.append(f"-DisplayName '{sanitize_powershell_string(display_name)}'")
    if managed_by is not None:
        updates.append(f"-ManagedBy '{sanitize_powershell_string(managed_by)}'")

    args_str = " ".join(updates)
    rsat = f"""
    if ($cred) {{ Set-ADGroup -Identity '{safe_id}' {args_str} -Server $adServer -Credential $cred }} else {{ Set-ADGroup -Identity '{safe_id}' {args_str} -Server $adServer }}
    [PSCustomObject]@{{ Status = "UPDATED"; Identity = '{safe_id}' }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_delete_group(
    identity: str,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """25. Excluir grupo do Active Directory (requer confirmação)."""
    start = time.time()
    tool_name = "ad_delete_group"
    params = {"identity": identity, "confirmation_token": confirmation_token, "dry_run": dry_run}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rsat = f"""
    if ($cred) {{ Remove-ADGroup -Identity '{safe_id}' -Confirm:$false -Server $adServer -Credential $cred }} else {{ Remove-ADGroup -Identity '{safe_id}' -Confirm:$false -Server $adServer }}
    [PSCustomObject]@{{ Status = "DELETED"; Identity = '{safe_id}' }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_add_group_member(
    group: str,
    members: List[str],
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """26. Adicionar um ou mais membros a um grupo."""
    start = time.time()
    tool_name = "ad_add_group_member"
    params = {"group": group, "members": members, "confirmation_token": confirmation_token, "dry_run": dry_run}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=group)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_grp = sanitize_powershell_string(group)
    members_arr = ", ".join(f"'{sanitize_powershell_string(m)}'" for m in members)

    rsat = f"""
    $m = @({members_arr})
    if ($cred) {{ Add-ADGroupMember -Identity '{safe_grp}' -Members $m -Server $adServer -Credential $cred }} else {{ Add-ADGroupMember -Identity '{safe_grp}' -Members $m -Server $adServer }}
    [PSCustomObject]@{{ Status = "MEMBERS_ADDED"; Group = '{safe_grp}'; AddedCount = $m.Count }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_remove_group_member(
    group: str,
    members: List[str],
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """27. Remover um ou mais membros de um grupo."""
    start = time.time()
    tool_name = "ad_remove_group_member"
    params = {"group": group, "members": members, "confirmation_token": confirmation_token, "dry_run": dry_run}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=group)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_grp = sanitize_powershell_string(group)
    members_arr = ", ".join(f"'{sanitize_powershell_string(m)}'" for m in members)

    rsat = f"""
    $m = @({members_arr})
    if ($cred) {{ Remove-ADGroupMember -Identity '{safe_grp}' -Members $m -Confirm:$false -Server $adServer -Credential $cred }} else {{ Remove-ADGroupMember -Identity '{safe_grp}' -Members $m -Confirm:$false -Server $adServer }}
    [PSCustomObject]@{{ Status = "MEMBERS_REMOVED"; Group = '{safe_grp}'; RemovedCount = $m.Count }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_list_group_members(
    identity: str,
    recursive: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """28. Listar todos os membros diretos ou aninhados de um grupo."""
    start = time.time()
    tool_name = "ad_list_group_members"
    params = {"identity": identity, "recursive": recursive}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rec_flag = "-Recursive" if recursive else ""

    rsat = f"""
    $m = if ($cred) {{ Get-ADGroupMember -Identity '{safe_id}' {rec_flag} -Server $adServer -Credential $cred }} else {{ Get-ADGroupMember -Identity '{safe_id}' {rec_flag} -Server $adServer }}
    $m | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = $_.SamAccountName
            Name = $_.Name
            ObjectClass = $_.objectClass
            DistinguishedName = $_.distinguishedName
        }}
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectClass=group)(|(sAMAccountName={safe_id})(name={safe_id})))"
    $res = $searcher.FindOne()
    if ($res) {{
        $members = $res.Properties["member"]
        $members | ForEach-Object {{
            [PSCustomObject]@{{ DistinguishedName = [string]$_ }}
        }}
    }} else {{ throw "Group '{safe_id}' not found." }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_user_groups(
    identity: str,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """29. Consultar grupos dos quais um usuário faz parte diretamente."""
    start = time.time()
    tool_name = "ad_get_user_groups"
    params = {"identity": identity}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rsat = f"""
    $u = if ($cred) {{ Get-ADPrincipalGroupMembership -Identity '{safe_id}' -Server $adServer -Credential $cred }} else {{ Get-ADPrincipalGroupMembership -Identity '{safe_id}' -Server $adServer }}
    $u | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = $_.SamAccountName
            Name = $_.Name
            GroupScope = [string]$_.GroupScope
            GroupCategory = [string]$_.GroupCategory
            DistinguishedName = $_.distinguishedName
        }}
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName={safe_id}))"
    $res = $searcher.FindOne()
    if ($res) {{
        $res.Properties["memberof"] | ForEach-Object {{
            [PSCustomObject]@{{ DistinguishedName = [string]$_ }}
        }}
    }} else {{ throw "User '{safe_id}' not found." }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_nested_group_membership(
    identity: str,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """30. Consultar associação recursiva a grupos (incluindo grupos aninhados)."""
    start = time.time()
    tool_name = "ad_get_nested_group_membership"
    params = {"identity": identity}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)

    # Uses LDAP matching rule in chain (1.2.840.113556.1.4.1941)
    rsat = f"""
    $user = if ($cred) {{ Get-ADUser -Identity '{safe_id}' -Server $adServer -Credential $cred }} else {{ Get-ADUser -Identity '{safe_id}' -Server $adServer }}
    $dn = $user.DistinguishedName
    $filter = "(member:1.2.840.113556.1.4.1941:=$dn)"
    $groups = if ($cred) {{ Get-ADGroup -LDAPFilter $filter -Server $adServer -Credential $cred }} else {{ Get-ADGroup -LDAPFilter $filter -Server $adServer }}
    $groups | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = $_.SamAccountName
            Name = $_.Name
            GroupScope = [string]$_.GroupScope
            GroupCategory = [string]$_.GroupCategory
            DistinguishedName = $_.distinguishedName
        }}
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName={safe_id}))"
    $uRes = $searcher.FindOne()
    if ($uRes) {{
        $dn = [string]$uRes.Properties["distinguishedname"][0]
        $grpSearcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
        $grpSearcher.Filter = "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=$dn))"
        $grpSearcher.FindAll() | ForEach-Object {{
            [PSCustomObject]@{{
                SamAccountName = [string]$_.Properties["samaccountname"][0]
                Name = [string]$_.Properties["name"][0]
                DistinguishedName = [string]$_.Properties["distinguishedname"][0]
            }}
        }}
    }} else {{ throw "User '{safe_id}' not found." }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()
