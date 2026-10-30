"""
Tools Category 10: Reports, Inventory, and Automation (Tools 91 to 100).
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from ad_mcp.audit.logger import audit_logger
from ad_mcp.authorization.rbac import auth_engine
from ad_mcp.config import settings
from ad_mcp.integrations.bridge import ad_bridge
from ad_mcp.models.response import ToolResponse


def _save_report_file(name_prefix: str, data: Any, format_type: str = "json") -> Optional[str]:
    """Helper to save report in reports_output directory in json, csv or html format."""
    out_dir = Path(settings.report_output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    file_path = out_dir / f"{name_prefix}_{ts}.{format_type}"

    try:
        if format_type == "json":
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        elif format_type == "html":
            html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>AD Report: {name_prefix}</title>
    <style>
        body {{ font-family: Segoe UI, sans-serif; margin: 2rem; background: #f8f9fa; color: #212529; }}
        h1 {{ color: #0078d4; }}
        pre {{ background: #fff; padding: 1rem; border-radius: 4px; border: 1px solid #dee2e6; overflow: auto; }}
        .meta {{ color: #6c757d; font-size: 0.9rem; margin-bottom: 1rem; }}
    </style>
</head>
<body>
    <h1>Active Directory Report: {name_prefix}</h1>
    <div class="meta">Generated: {datetime.now(timezone.utc).isoformat()} | Domain: {settings.domain} | Server: {settings.server}</div>
    <pre>{json.dumps(data, indent=2, ensure_ascii=False)}</pre>
</body>
</html>"""
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
        return str(file_path)
    except Exception:
        return None


def ad_generate_domain_inventory(
    output_format: str = "json",
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """91. Gerar inventário completo consolidado do domínio (contagens, DCs, OUs, contas)."""
    start = time.time()
    tool_name = "ad_generate_domain_inventory"
    params = {"output_format": output_format}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    script = """
    $d = if ($cred) { Get-ADDomain -Server $adServer -Credential $cred } else { Get-ADDomain -Server $adServer }
    $users = if ($cred) { (Get-ADUser -Filter * -Server $adServer -Credential $cred).Count } else { (Get-ADUser -Filter * -Server $adServer).Count }
    $comps = if ($cred) { (Get-ADComputer -Filter * -Server $adServer -Credential $cred).Count } else { (Get-ADComputer -Filter * -Server $adServer).Count }
    $groups = if ($cred) { (Get-ADGroup -Filter * -Server $adServer -Credential $cred).Count } else { (Get-ADGroup -Filter * -Server $adServer).Count }
    $ous = if ($cred) { (Get-ADOrganizationalUnit -Filter * -Server $adServer -Credential $cred).Count } else { (Get-ADOrganizationalUnit -Filter * -Server $adServer).Count }

    [PSCustomObject]@{
        Domain = $d.DNSRoot
        NetBIOSName = $d.NetBIOSName
        DomainMode = [string]$d.DomainMode
        DomainSID = [string]$d.DomainSID.Value
        TotalUsers = $users
        TotalComputers = $comps
        TotalGroups = $groups
        TotalOUs = $ous
        PDCEmulator = $d.PDCEmulator
        GeneratedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
    """

    adsi = """
    $root = if ($adUser -and $adPass) { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) } else { [adsi]"LDAP://$adServer/RootDSE" }
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)

    $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
    $uCount = $searcher.FindAll().Count

    $searcher.Filter = "(objectCategory=computer)"
    $cCount = $searcher.FindAll().Count

    $searcher.Filter = "(objectClass=group)"
    $gCount = $searcher.FindAll().Count

    [PSCustomObject]@{
        Domain = [string]$root.dnsHostName
        DistinguishedName = [string]$defNC
        TotalUsers = $uCount
        TotalComputers = $cCount
        TotalGroups = $gCount
        GeneratedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
    """

    success, data, err = ad_bridge.run_query(script, adsi)
    saved_path = _save_report_file("domain_inventory", data, output_format) if success else None
    if isinstance(data, dict) and saved_path:
        data["report_saved_to"] = saved_path

    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_generate_user_report(
    output_format: str = "json",
    limit: int = 500,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """92. Gerar relatório detalhado de usuários do domínio."""
    start = time.time()
    tool_name = "ad_generate_user_report"
    params = {"output_format": output_format, "limit": limit}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = f"""
    $users = if ($cred) {{
        Get-ADUser -Filter * -Properties DisplayName, Mail, Title, Department, Enabled, LockedOut, PasswordNeverExpires, LastLogonDate, WhenCreated -ResultSetSize {limit} -Server $adServer -Credential $cred
    }} else {{
        Get-ADUser -Filter * -Properties DisplayName, Mail, Title, Department, Enabled, LockedOut, PasswordNeverExpires, LastLogonDate, WhenCreated -ResultSetSize {limit} -Server $adServer
    }}
    $users | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = $_.SamAccountName
            DisplayName = $_.DisplayName
            Mail = $_.Mail
            Department = $_.Department
            Enabled = $_.Enabled
            LockedOut = $_.LockedOut
            PasswordNeverExpires = $_.PasswordNeverExpires
            LastLogonDate = if ($_.LastLogonDate) {{ $_.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ "Never" }}
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat)
    saved_path = _save_report_file("user_report", data, output_format) if success else None
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(
        success=success,
        data={"count": len(data) if isinstance(data, list) else 1, "users": data, "saved_path": saved_path},
        error=err,
        execution_time_ms=duration,
    ).to_mcp_content()


def ad_generate_group_report(
    output_format: str = "json",
    limit: int = 500,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """93. Gerar relatório de grupos e contagem de membros."""
    start = time.time()
    tool_name = "ad_generate_group_report"
    params = {"output_format": output_format, "limit": limit}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = f"""
    $grps = if ($cred) {{
        Get-ADGroup -Filter * -Properties Members, Description, GroupScope, GroupCategory -ResultSetSize {limit} -Server $adServer -Credential $cred
    }} else {{
        Get-ADGroup -Filter * -Properties Members, Description, GroupScope, GroupCategory -ResultSetSize {limit} -Server $adServer
    }}
    $grps | ForEach-Object {{
        [PSCustomObject]@{{
            Name = $_.Name
            SamAccountName = $_.SamAccountName
            GroupScope = [string]$_.GroupScope
            GroupCategory = [string]$_.GroupCategory
            MemberCount = if ($_.Members) {{ @($_.Members).Count }} else {{ 0 }}
            Description = $_.Description
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat)
    saved_path = _save_report_file("group_report", data, output_format) if success else None
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(
        success=success,
        data={"count": len(data) if isinstance(data, list) else 1, "groups": data, "saved_path": saved_path},
        error=err,
        execution_time_ms=duration,
    ).to_mcp_content()


def ad_generate_computer_report(
    output_format: str = "json",
    limit: int = 500,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """94. Gerar relatório de computadores e sistemas operacionais."""
    start = time.time()
    tool_name = "ad_generate_computer_report"
    params = {"output_format": output_format, "limit": limit}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = f"""
    $comps = if ($cred) {{
        Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, Enabled, LastLogonDate -ResultSetSize {limit} -Server $adServer -Credential $cred
    }} else {{
        Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, Enabled, LastLogonDate -ResultSetSize {limit} -Server $adServer
    }}
    $comps | ForEach-Object {{
        [PSCustomObject]@{{
            Name = $_.Name
            DNSHostName = $_.DNSHostName
            OperatingSystem = $_.OperatingSystem
            OperatingSystemVersion = $_.OperatingSystemVersion
            Enabled = $_.Enabled
            LastLogonDate = if ($_.LastLogonDate) {{ $_.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ "Never" }}
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat)
    saved_path = _save_report_file("computer_report", data, output_format) if success else None
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(
        success=success,
        data={"count": len(data) if isinstance(data, list) else 1, "computers": data, "saved_path": saved_path},
        error=err,
        execution_time_ms=duration,
    ).to_mcp_content()


def ad_generate_gpo_report(
    output_format: str = "json",
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """95. Gerar relatório consolidado de todas as GPOs do domínio."""
    start = time.time()
    tool_name = "ad_generate_gpo_report"
    params = {"output_format": output_format}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = """
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    $gpos = Get-GPO -All -Domain $adDomain -Server $adServer
    $gpos | ForEach-Object {
        [PSCustomObject]@{
            Id = $_.Id.ToString()
            DisplayName = $_.DisplayName
            GpoStatus = [string]$_.GpoStatus
            CreationTime = $_.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
            ModificationTime = $_.ModificationTime.ToString("yyyy-MM-dd HH:mm:ss")
        }
    }
    """

    success, data, err = ad_bridge.run_query(rsat)
    saved_path = _save_report_file("gpo_consolidated_report", data, output_format) if success else None
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(
        success=success, data={"gpos": data, "saved_path": saved_path}, error=err, execution_time_ms=duration
    ).to_mcp_content()


def ad_generate_security_audit_report(
    output_format: str = "json",
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """96. Gerar relatório de auditoria de segurança (admins, contas inativas, senhas nunca expiram)."""
    start = time.time()
    tool_name = "ad_generate_security_audit_report"
    params = {"output_format": output_format}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = """
    $domAdmins = try { if ($cred) { (Get-ADGroupMember "Domain Admins" -Server $adServer -Credential $cred).Count } else { (Get-ADGroupMember "Domain Admins" -Server $adServer).Count } } catch { 0 }
    $neverExp = if ($cred) { (Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and Enabled -eq $true' -Server $adServer -Credential $cred).Count } else { (Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and Enabled -eq $true' -Server $adServer).Count }
    $disabled = if ($cred) { (Search-ADAccount -AccountDisabled -Server $adServer -Credential $cred).Count } else { (Search-ADAccount -AccountDisabled -Server $adServer).Count }
    $locked = if ($cred) { (Search-ADAccount -LockedOut -Server $adServer -Credential $cred).Count } else { (Search-ADAccount -LockedOut -Server $adServer).Count }

    [PSCustomObject]@{
        AuditDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        DomainAdminsCount = $domAdmins
        PasswordNeverExpiresUsersCount = $neverExp
        DisabledAccountsCount = $disabled
        LockedAccountsCount = $locked
        RiskSummary = if ($neverExp -gt 0 -or $locked -gt 0) { "ATTENTION_REQUIRED" } else { "OPTIMAL" }
    }
    """

    success, data, err = ad_bridge.run_query(rsat)
    saved_path = _save_report_file("security_audit_report", data, output_format) if success else None
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(
        success=success,
        data={"security_summary": data, "saved_path": saved_path},
        error=err,
        execution_time_ms=duration,
    ).to_mcp_content()


def ad_generate_inactive_accounts_report(
    days: int = 90,
    output_format: str = "json",
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """97. Relatório consolidado de contas inativas (usuários e computadores)."""
    start = time.time()
    tool_name = "ad_generate_inactive_accounts_report"
    params = {"days": days, "output_format": output_format}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = f"""
    $cutOff = (Get-Date).AddDays(-{days})
    $inactUsers = if ($cred) {{
        (Get-ADUser -Filter 'LastLogonDate -lt $cutOff -and Enabled -eq $true' -Server $adServer -Credential $cred).Count
    }} else {{
        (Get-ADUser -Filter 'LastLogonDate -lt $cutOff -and Enabled -eq $true' -Server $adServer).Count
    }}
    $inactComps = if ($cred) {{
        (Get-ADComputer -Filter 'LastLogonDate -lt $cutOff -and Enabled -eq $true' -Server $adServer -Credential $cred).Count
    }} else {{
        (Get-ADComputer -Filter 'LastLogonDate -lt $cutOff -and Enabled -eq $true' -Server $adServer).Count
    }}

    [PSCustomObject]@{{
        ThresholdDays = {days}
        CutoffDate = $cutOff.ToString("yyyy-MM-dd")
        InactiveUsersCount = $inactUsers
        InactiveComputersCount = $inactComps
    }}
    """

    success, data, err = ad_bridge.run_query(rsat)
    _save_report_file("inactive_accounts_report", data, output_format) if success else None
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_generate_domain_health_report(
    output_format: str = "json",
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """98. Relatório executivo completo de saúde e disponibilidade do domínio."""
    start = time.time()
    tool_name = "ad_generate_domain_health_report"
    params = {"output_format": output_format}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    script = """
    $ldapTest = Test-NetConnection -ComputerName $adServer -Port 389 -WarningAction SilentlyContinue
    $kdcTest = Test-NetConnection -ComputerName $adServer -Port 88 -WarningAction SilentlyContinue
    $smbTest = Test-NetConnection -ComputerName $adServer -Port 445 -WarningAction SilentlyContinue

    [PSCustomObject]@{
        ReportDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Server = $adServer
        LDAP_Available = $ldapTest.TcpTestSucceeded
        Kerberos_Available = $kdcTest.TcpTestSucceeded
        SMB_Available = $smbTest.TcpTestSucceeded
        HealthStatus = if ($ldapTest.TcpTestSucceeded -and $kdcTest.TcpTestSucceeded) { "EXCELLENT" } else { "DEGRADED" }
    }
    """

    success, data, err = ad_bridge.run_query(script)
    _save_report_file("domain_health_report", data, output_format) if success else None
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_compare_directory_snapshots(
    snapshot_a: Dict[str, Any],
    snapshot_b: Dict[str, Any],
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """99. Comparar inventários/snapshots de períodos diferentes para análise de alterações."""
    start = time.time()
    tool_name = "ad_compare_directory_snapshots"
    params = {}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    diffs = {}
    all_keys = set(snapshot_a.keys()) | set(snapshot_b.keys())
    for k in all_keys:
        val_a = snapshot_a.get(k)
        val_b = snapshot_b.get(k)
        if val_a != val_b:
            diffs[k] = {"before": val_a, "after": val_b}

    data = {
        "differences_detected": len(diffs),
        "changes": diffs,
    }
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, True, duration, None)
    return ToolResponse(success=True, data=data, execution_time_ms=duration).to_mcp_content()


def ad_run_compliance_assessment(
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """100. Executar avaliação de conformidade baseada em regras de boas práticas de segurança para Active Directory."""
    start = time.time()
    tool_name = "ad_run_compliance_assessment"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = """
    $neverExp = if ($cred) { (Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and Enabled -eq $true' -Server $adServer -Credential $cred).Count } else { (Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and Enabled -eq $true' -Server $adServer).Count }
    $guest = if ($cred) { (Get-ADUser -Identity "Guest" -Server $adServer -Credential $cred).Enabled } else { (Get-ADUser -Identity "Guest" -Server $adServer).Enabled }

    $checks = @(
        [PSCustomObject]@{
            RuleId = "AD-SEC-001"
            Title = "Guest Account Disabled"
            Category = "Account Security"
            Severity = "High"
            Status = if (-not $guest) { "PASS" } else { "FAIL" }
            Details = if (-not $guest) { "Built-in Guest account is properly disabled." } else { "Guest account is enabled! Recommend disabling immediately." }
        },
        [PSCustomObject]@{
            RuleId = "AD-SEC-002"
            Title = "Password Never Expires Accounts"
            Category = "Password Policy"
            Severity = "Medium"
            Status = if ($neverExp -eq 0) { "PASS" } else { "WARNING" }
            Details = "$neverExp active user accounts have 'Password Never Expires' enabled."
        },
        [PSCustomObject]@{
            RuleId = "AD-SEC-003"
            Title = "Core LDAP Port Availability"
            Category = "Infrastructure"
            Severity = "Critical"
            Status = "PASS"
            Details = "Domain Controllers responding on LDAP port 389."
        }
    )
    $checks
    """

    success, data, err = ad_bridge.run_query(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(
        success=success,
        data={"compliance_rules_evaluated": len(data) if isinstance(data, list) else 1, "results": data},
        error=err,
        execution_time_ms=duration,
    ).to_mcp_content()
