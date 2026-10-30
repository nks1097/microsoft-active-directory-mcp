"""
Tools Category 5: Organizational Units (OUs) (Tools 41 to 50).
"""

import time
from typing import Any, Dict, Optional

from ad_mcp.audit.logger import audit_logger
from ad_mcp.authorization.guardrails import sanitize_powershell_string
from ad_mcp.authorization.rbac import auth_engine
from ad_mcp.integrations.bridge import ad_bridge
from ad_mcp.models.response import ToolResponse


def ad_list_ous(
    search_base: Optional[str] = None,
    limit: int = 100,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """41. Listar Unidades Organizacionais (OUs) do domínio."""
    start = time.time()
    tool_name = "ad_list_ous"
    params = {"search_base": search_base, "limit": limit}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    base_clause = f"-SearchBase '{sanitize_powershell_string(search_base)}'" if search_base else ""

    rsat = f"""
    $ous = if ($cred) {{ Get-ADOrganizationalUnit -Filter * {base_clause} -ResultSetSize {limit} -Properties Description, ProtectedFromAccidentalDeletion -Server $adServer -Credential $cred }} else {{ Get-ADOrganizationalUnit -Filter * {base_clause} -ResultSetSize {limit} -Properties Description, ProtectedFromAccidentalDeletion -Server $adServer }}
    $ous | ForEach-Object {{
        [PSCustomObject]@{{
            Name = $_.Name
            DistinguishedName = $_.DistinguishedName
            Description = $_.Description
            ProtectedFromAccidentalDeletion = $_.ProtectedFromAccidentalDeletion
        }}
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = if ('{sanitize_powershell_string(search_base)}') {{ '{sanitize_powershell_string(search_base)}' }} else {{ $root.defaultNamingContext }}
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(objectCategory=organizationalUnit)"
    $searcher.SizeLimit = {limit}
    $searcher.PropertiesToLoad.AddRange(@("name", "description", "distinguishedname"))
    $searcher.FindAll() | ForEach-Object {{
        [PSCustomObject]@{{
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


def ad_get_ou(
    identity: str,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """42. Consultar detalhes de uma OU específica."""
    start = time.time()
    tool_name = "ad_get_ou"
    params = {"identity": identity}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rsat = f"""
    $ou = if ($cred) {{ Get-ADOrganizationalUnit -Identity '{safe_id}' -Properties * -Server $adServer -Credential $cred }} else {{ Get-ADOrganizationalUnit -Identity '{safe_id}' -Properties * -Server $adServer }}
    [PSCustomObject]@{{
        Name = $ou.Name
        DistinguishedName = $ou.DistinguishedName
        Description = $ou.Description
        ProtectedFromAccidentalDeletion = $ou.ProtectedFromAccidentalDeletion
        City = $ou.City
        Country = $ou.Country
        PostalCode = $ou.PostalCode
        State = $ou.State
        StreetAddress = $ou.StreetAddress
        WhenCreated = if ($ou.WhenCreated) {{ $ou.WhenCreated.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ $null }}
        ManagedBy = $ou.ManagedBy
    }}
    """

    adsi = f"""
    $entry = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/{safe_id}", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/{safe_id}" }}
    [PSCustomObject]@{{
        Name = [string]$entry.Properties["name"][0]
        DistinguishedName = [string]$entry.Properties["distinguishedname"][0]
        Description = [string]$entry.Properties["description"][0]
    }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_create_ou(
    name: str,
    path: str,
    description: Optional[str] = None,
    protected_from_accidental_deletion: bool = True,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """43. Criar nova Unidade Organizacional (OU)."""
    start = time.time()
    tool_name = "ad_create_ou"
    params = {
        "name": name,
        "path": path,
        "protected": protected_from_accidental_deletion,
        "confirmation_token": confirmation_token,
        "dry_run": dry_run,
    }
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=name)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_name = sanitize_powershell_string(name)
    safe_path = sanitize_powershell_string(path)
    safe_desc = sanitize_powershell_string(description) if description else ""

    rsat = f"""
    $params = @{{
        Name = '{safe_name}'
        Path = '{safe_path}'
        ProtectedFromAccidentalDeletion = ${str(protected_from_accidental_deletion).lower()}
    }}
    if ('{safe_desc}') {{ $params['Description'] = '{safe_desc}' }}
    if ($cred) {{ $params['Server'] = $adServer; $params['Credential'] = $cred }} else {{ $params['Server'] = $adServer }}

    New-ADOrganizationalUnit @params
    [PSCustomObject]@{{
        Status = "CREATED"
        Name = '{safe_name}'
        DistinguishedName = "OU={safe_name},{safe_path}"
        ProtectedFromAccidentalDeletion = ${str(protected_from_accidental_deletion).lower()}
    }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_update_ou(
    identity: str,
    description: Optional[str] = None,
    managed_by: Optional[str] = None,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """44. Atualizar atributos de uma OU."""
    start = time.time()
    tool_name = "ad_update_ou"
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
    if managed_by is not None:
        updates.append(f"-ManagedBy '{sanitize_powershell_string(managed_by)}'")

    args_str = " ".join(updates)
    rsat = f"""
    if ($cred) {{ Set-ADOrganizationalUnit -Identity '{safe_id}' {args_str} -Server $adServer -Credential $cred }} else {{ Set-ADOrganizationalUnit -Identity '{safe_id}' {args_str} -Server $adServer }}
    [PSCustomObject]@{{ Status = "UPDATED"; Identity = '{safe_id}' }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_delete_ou(
    identity: str,
    recursive: bool = False,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """45. Excluir OU com validação de proteção e conteúdo."""
    start = time.time()
    tool_name = "ad_delete_ou"
    params = {
        "identity": identity,
        "recursive": recursive,
        "confirmation_token": confirmation_token,
        "dry_run": dry_run,
    }
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rec_flag = "-Recursive" if recursive else ""

    rsat = f"""
    # Check protection status first
    $ou = if ($cred) {{ Get-ADOrganizationalUnit -Identity '{safe_id}' -Server $adServer -Credential $cred }} else {{ Get-ADOrganizationalUnit -Identity '{safe_id}' -Server $adServer }}
    if ($ou.ProtectedFromAccidentalDeletion) {{
        throw "Cannot delete OU '{safe_id}': OU is protected from accidental deletion. Unprotect it first using ad_set_ou_protection."
    }}
    if ($cred) {{ Remove-ADOrganizationalUnit -Identity '{safe_id}' {rec_flag} -Confirm:$false -Server $adServer -Credential $cred }} else {{ Remove-ADOrganizationalUnit -Identity '{safe_id}' {rec_flag} -Confirm:$false -Server $adServer }}
    [PSCustomObject]@{{ Status = "DELETED"; Identity = '{safe_id}'; Recursive = ${str(recursive).lower()} }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_move_object(
    identity: str,
    target_ou: str,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """46. Mover qualquer objeto (usuário, grupo, etc.) entre OUs."""
    start = time.time()
    tool_name = "ad_move_object"
    params = {
        "identity": identity,
        "target_ou": target_ou,
        "confirmation_token": confirmation_token,
        "dry_run": dry_run,
    }
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    safe_target = sanitize_powershell_string(target_ou)

    rsat = f"""
    if ($cred) {{ Move-ADObject -Identity '{safe_id}' -TargetPath '{safe_target}' -Server $adServer -Credential $cred }} else {{ Move-ADObject -Identity '{safe_id}' -TargetPath '{safe_target}' -Server $adServer }}
    [PSCustomObject]@{{ Status = "MOVED"; Object = '{safe_id}'; TargetOU = '{safe_target}' }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_list_ou_objects(
    ou_distinguished_name: str,
    object_class: Optional[str] = None,
    limit: int = 100,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """47. Listar todos os objetos contidos diretamente em uma OU."""
    start = time.time()
    tool_name = "ad_list_ou_objects"
    params = {"ou": ou_distinguished_name, "object_class": object_class, "limit": limit}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_ou = sanitize_powershell_string(ou_distinguished_name)
    class_filter = f"ObjectClass -eq '{sanitize_powershell_string(object_class)}'" if object_class else "*"

    rsat = f"""
    $objs = if ($cred) {{
        Get-ADObject -SearchBase '{safe_ou}' -SearchScope OneLevel -Filter '{class_filter}' -ResultSetSize {limit} -Properties ObjectClass -Server $adServer -Credential $cred
    }} else {{
        Get-ADObject -SearchBase '{safe_ou}' -SearchScope OneLevel -Filter '{class_filter}' -ResultSetSize {limit} -Properties ObjectClass -Server $adServer
    }}
    $objs | ForEach-Object {{
        [PSCustomObject]@{{
            Name = $_.Name
            ObjectClass = $_.ObjectClass
            DistinguishedName = $_.DistinguishedName
        }}
    }}
    """

    adsi = f"""
    $entry = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/{safe_ou}", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/{safe_ou}" }}
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
    $searcher.Filter = if ('{object_class}') {{ "(objectClass={object_class})" }} else {{ "(objectClass=*)" }}
    $searcher.SizeLimit = {limit}
    $searcher.FindAll() | ForEach-Object {{
        [PSCustomObject]@{{
            Name = [string]$_.Properties["name"][0]
            DistinguishedName = [string]$_.Properties["distinguishedname"][0]
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_ou_hierarchy(correlation_id: Optional[str] = None) -> Dict[str, Any]:
    """48. Consultar árvore completa da hierarquia de OUs do domínio."""
    start = time.time()
    tool_name = "ad_get_ou_hierarchy"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = """
    $ous = if ($cred) { Get-ADOrganizationalUnit -Filter * -Server $adServer -Credential $cred } else { Get-ADOrganizationalUnit -Filter * -Server $adServer }
    $tree = @()
    foreach ($ou in $ous) {
        $parent = ($ou.DistinguishedName -split ",", 2)[1]
        $tree += [PSCustomObject]@{
            Name = $ou.Name
            DistinguishedName = $ou.DistinguishedName
            Parent = $parent
        }
    }
    $tree
    """

    adsi = """
    $root = if ($adUser -and $adPass) { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) } else { [adsi]"LDAP://$adServer/RootDSE" }
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(objectCategory=organizationalUnit)"
    $searcher.FindAll() | ForEach-Object {
        $dn = [string]$_.Properties["distinguishedname"][0]
        $parent = ($dn -split ",", 2)[1]
        [PSCustomObject]@{
            Name = [string]$_.Properties["name"][0]
            DistinguishedName = $dn
            Parent = $parent
        }
    }
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_ou_protection_status(
    identity: str,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """49. Consultar estado da proteção contra exclusão acidental de uma OU."""
    start = time.time()
    tool_name = "ad_get_ou_protection_status"
    params = {"identity": identity}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rsat = f"""
    $ou = if ($cred) {{ Get-ADOrganizationalUnit -Identity '{safe_id}' -Properties ProtectedFromAccidentalDeletion -Server $adServer -Credential $cred }} else {{ Get-ADOrganizationalUnit -Identity '{safe_id}' -Properties ProtectedFromAccidentalDeletion -Server $adServer }}
    [PSCustomObject]@{{
        Name = $ou.Name
        DistinguishedName = $ou.DistinguishedName
        ProtectedFromAccidentalDeletion = $ou.ProtectedFromAccidentalDeletion
    }}
    """

    success, data, err = ad_bridge.run_query(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_set_ou_protection(
    identity: str,
    protected: bool,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """50. Habilitar ou desabilitar proteção contra exclusão acidental de uma OU."""
    start = time.time()
    tool_name = "ad_set_ou_protection"
    params = {
        "identity": identity,
        "protected": protected,
        "confirmation_token": confirmation_token,
        "dry_run": dry_run,
    }
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rsat = f"""
    if ($cred) {{ Set-ADOrganizationalUnit -Identity '{safe_id}' -ProtectedFromAccidentalDeletion ${str(protected).lower()} -Server $adServer -Credential $cred }} else {{ Set-ADOrganizationalUnit -Identity '{safe_id}' -ProtectedFromAccidentalDeletion ${str(protected).lower()} -Server $adServer }}
    [PSCustomObject]@{{ Status = "UPDATED"; Identity = '{safe_id}'; ProtectedFromAccidentalDeletion = ${str(protected).lower()} }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()
