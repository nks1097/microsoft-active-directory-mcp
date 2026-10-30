"""
Tools Category 6: Group Policy Objects (GPOs) (Tools 51 to 60).
"""

import time
from typing import Any, Dict, Optional

from ad_mcp.audit.logger import audit_logger
from ad_mcp.authorization.guardrails import sanitize_powershell_string
from ad_mcp.authorization.rbac import auth_engine
from ad_mcp.integrations.bridge import ad_bridge
from ad_mcp.models.response import ToolResponse


def ad_list_gpos(
    limit: int = 100,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """51. Listar todas as Group Policy Objects (GPOs) do domínio."""
    start = time.time()
    tool_name = "ad_list_gpos"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = f"""
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    $gpos = Get-GPO -All -Domain $adDomain -Server $adServer
    $gpos | Select-Object -First {limit} | ForEach-Object {{
        [PSCustomObject]@{{
            Id = $_.Id.ToString()
            DisplayName = $_.DisplayName
            GpoStatus = [string]$_.GpoStatus
            CreationTime = $_.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
            ModificationTime = $_.ModificationTime.ToString("yyyy-MM-dd HH:mm:ss")
            Description = $_.Description
        }}
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/CN=Policies,CN=System,$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(objectCategory=groupPolicyContainer)"
    $searcher.SizeLimit = {limit}
    $searcher.PropertiesToLoad.AddRange(@("displayname", "name", "flags", "whenchanged"))
    $searcher.FindAll() | ForEach-Object {{
        [PSCustomObject]@{{
            Id = [string]$_.Properties["name"][0]
            DisplayName = [string]$_.Properties["displayname"][0]
            ModificationTime = [string]$_.Properties["whenchanged"][0]
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_gpo(
    identity: str,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """52. Consultar detalhes de uma GPO por nome ou GUID."""
    start = time.time()
    tool_name = "ad_get_gpo"
    params = {"identity": identity}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rsat = f"""
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    $g = if ('{safe_id}' -match '^[0-9a-fA-F-]{{36}}$') {{
        Get-GPO -Guid '{safe_id}' -Domain $adDomain -Server $adServer
    }} else {{
        Get-GPO -Name '{safe_id}' -Domain $adDomain -Server $adServer
    }}
    [PSCustomObject]@{{
        Id = $g.Id.ToString()
        DisplayName = $g.DisplayName
        GpoStatus = [string]$g.GpoStatus
        CreationTime = $g.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
        ModificationTime = $g.ModificationTime.ToString("yyyy-MM-dd HH:mm:ss")
        UserVersion = $g.User.DSVersion
        ComputerVersion = $g.Computer.DSVersion
        Description = $g.Description
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/CN=Policies,CN=System,$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectCategory=groupPolicyContainer)(|(name={safe_id})(displayName={safe_id})))"
    $res = $searcher.FindOne()
    if ($res) {{
        [PSCustomObject]@{{
            Id = [string]$res.Properties["name"][0]
            DisplayName = [string]$res.Properties["displayname"][0]
            ModificationTime = [string]$res.Properties["whenchanged"][0]
            DistinguishedName = [string]$res.Properties["distinguishedname"][0]
        }}
    }} else {{ throw "GPO '{safe_id}' not found." }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_create_gpo(
    name: str,
    comment: Optional[str] = None,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """53. Criar uma nova Group Policy Object (GPO)."""
    start = time.time()
    tool_name = "ad_create_gpo"
    params = {"name": name, "comment": comment, "confirmation_token": confirmation_token, "dry_run": dry_run}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=name)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_name = sanitize_powershell_string(name)
    safe_comment = sanitize_powershell_string(comment) if comment else ""

    rsat = f"""
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    $params = @{{
        Name = '{safe_name}'
        Domain = $adDomain
        Server = $adServer
    }}
    if ('{safe_comment}') {{ $params['Comment'] = '{safe_comment}' }}
    $g = New-GPO @params
    [PSCustomObject]@{{
        Status = "CREATED"
        Id = $g.Id.ToString()
        DisplayName = $g.DisplayName
    }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_update_gpo(
    identity: str,
    comment: Optional[str] = None,
    gpo_status: Optional[
        str
    ] = None,  # AllSettingsEnabled, UserSettingsDisabled, ComputerSettingsDisabled, AllSettingsDisabled
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """54. Atualizar propriedades suportadas de uma GPO (comentários, status)."""
    start = time.time()
    tool_name = "ad_update_gpo"
    params = {
        "identity": identity,
        "comment": comment,
        "gpo_status": gpo_status,
        "confirmation_token": confirmation_token,
        "dry_run": dry_run,
    }
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    updates = []
    if comment is not None:
        updates.append(f"$g.Comment = '{sanitize_powershell_string(comment)}'")
    if gpo_status is not None:
        updates.append(f"$g.GpoStatus = '{sanitize_powershell_string(gpo_status)}'")

    updates_code = "\n".join(updates)
    rsat = f"""
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    $g = if ('{safe_id}' -match '^[0-9a-fA-F-]{{36}}$') {{
        Get-GPO -Guid '{safe_id}' -Domain $adDomain -Server $adServer
    }} else {{
        Get-GPO -Name '{safe_id}' -Domain $adDomain -Server $adServer
    }}
    {updates_code}
    [PSCustomObject]@{{ Status = "UPDATED"; Id = $g.Id.ToString(); DisplayName = $g.DisplayName }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_delete_gpo(
    identity: str,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """55. Excluir uma GPO (operação de alto impacto com confirmação)."""
    start = time.time()
    tool_name = "ad_delete_gpo"
    params = {"identity": identity, "confirmation_token": confirmation_token, "dry_run": dry_run}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rsat = f"""
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    if ('{safe_id}' -match '^[0-9a-fA-F-]{{36}}$') {{
        Remove-GPO -Guid '{safe_id}' -Domain $adDomain -Server $adServer
    }} else {{
        Remove-GPO -Name '{safe_id}' -Domain $adDomain -Server $adServer
    }}
    [PSCustomObject]@{{ Status = "DELETED"; Identity = '{safe_id}' }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_link_gpo(
    gpo_identity: str,
    target_dn: str,
    order: Optional[int] = None,
    enabled: bool = True,
    enforced: bool = False,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """56. Vincular uma GPO a um domínio, site ou Unidade Organizacional (OU)."""
    start = time.time()
    tool_name = "ad_link_gpo"
    params = {"gpo": gpo_identity, "target_dn": target_dn, "confirmation_token": confirmation_token, "dry_run": dry_run}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=gpo_identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_gpo = sanitize_powershell_string(gpo_identity)
    safe_target = sanitize_powershell_string(target_dn)
    order_clause = f"-Order {order}" if order is not None else ""

    rsat = f"""
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    New-GPLink -Name '{safe_gpo}' -Target '{safe_target}' {order_clause} -LinkEnabled ${str(enabled).lower()} -Enforced ${str(enforced).lower()} -Domain $adDomain -Server $adServer
    [PSCustomObject]@{{
        Status = "LINKED"
        GPO = '{safe_gpo}'
        Target = '{safe_target}'
        Enabled = ${str(enabled).lower()}
        Enforced = ${str(enforced).lower()}
    }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_unlink_gpo(
    gpo_identity: str,
    target_dn: str,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """57. Remover vínculo de uma GPO com domínio, site ou OU."""
    start = time.time()
    tool_name = "ad_unlink_gpo"
    params = {"gpo": gpo_identity, "target_dn": target_dn, "confirmation_token": confirmation_token, "dry_run": dry_run}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=gpo_identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_gpo = sanitize_powershell_string(gpo_identity)
    safe_target = sanitize_powershell_string(target_dn)

    rsat = f"""
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    Remove-GPLink -Name '{safe_gpo}' -Target '{safe_target}' -Domain $adDomain -Server $adServer
    [PSCustomObject]@{{
        Status = "UNLINKED"
        GPO = '{safe_gpo}'
        Target = '{safe_target}'
    }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_gpo_links(
    target_dn: str,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """58. Consultar vínculos de GPO em um site, domínio ou OU específica."""
    start = time.time()
    tool_name = "ad_get_gpo_links"
    params = {"target_dn": target_dn}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_target = sanitize_powershell_string(target_dn)
    rsat = f"""
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    $inheritance = Get-GPInheritance -Target '{safe_target}' -Domain $adDomain -Server $adServer
    $links = $inheritance.GpoLinks | ForEach-Object {{
        [PSCustomObject]@{{
            DisplayName = $_.DisplayName
            GpoId = $_.GpoId.ToString()
            Enabled = $_.Enabled
            Enforced = $_.Enforced
            Order = $_.Order
        }}
    }}
    [PSCustomObject]@{{
        Target = '{safe_target}'
        GpoLinks = $links
        BlockInheritance = $inheritance.GpoBlockInheritance
    }}
    """

    success, data, err = ad_bridge.run_query(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_gpo_report(
    identity: str,
    report_type: str = "xml",  # xml or html
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """59. Gerar relatório detalhado de configurações de uma GPO (XML ou resumo)."""
    start = time.time()
    tool_name = "ad_get_gpo_report"
    params = {"identity": identity, "report_type": report_type}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rep_type = "Xml" if report_type.lower() == "xml" else "Html"

    rsat = f"""
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    $report = Get-GPOReport -Name '{safe_id}' -ReportType {rep_type} -Domain $adDomain -Server $adServer
    [PSCustomObject]@{{
        GPO = '{safe_id}'
        ReportType = '{rep_type}'
        ContentPreview = $report.Substring(0, [Math]::Min(1500, $report.Length))
        Length = $report.Length
    }}
    """

    success, data, err = ad_bridge.run_query(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_compare_gpos(
    gpo_a: str,
    gpo_b: str,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """60. Comparar metadados e versões de duas GPOs."""
    start = time.time()
    tool_name = "ad_compare_gpos"
    params = {"gpo_a": gpo_a, "gpo_b": gpo_b}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_a = sanitize_powershell_string(gpo_a)
    safe_b = sanitize_powershell_string(gpo_b)

    rsat = f"""
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    $ga = Get-GPO -Name '{safe_a}' -Domain $adDomain -Server $adServer
    $gb = Get-GPO -Name '{safe_b}' -Domain $adDomain -Server $adServer
    [PSCustomObject]@{{
        GPO_A = [PSCustomObject]@{{ Name = $ga.DisplayName; Id = $ga.Id.ToString(); Status = [string]$ga.GpoStatus; ModDate = $ga.ModificationTime.ToString("s") }}
        GPO_B = [PSCustomObject]@{{ Name = $gb.DisplayName; Id = $gb.Id.ToString(); Status = [string]$gb.GpoStatus; ModDate = $gb.ModificationTime.ToString("s") }}
        StatusMatch = ($ga.GpoStatus -eq $gb.GpoStatus)
        Different = ($ga.Id -ne $gb.Id)
    }}
    """

    success, data, err = ad_bridge.run_query(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()
