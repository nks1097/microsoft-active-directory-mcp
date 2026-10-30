"""
Tools Category 9: Replication, Health, and Diagnostics (Tools 81 to 90).
"""

import time
from typing import Any, Dict, Optional

from ad_mcp.audit.logger import audit_logger
from ad_mcp.authorization.guardrails import sanitize_powershell_string
from ad_mcp.authorization.rbac import auth_engine
from ad_mcp.integrations.bridge import ad_bridge
from ad_mcp.models.response import ToolResponse


def ad_get_replication_status(
    server: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """81. Consultar estado geral da replicação entre controladores de domínio."""
    start = time.time()
    tool_name = "ad_get_replication_status"
    params = {"server": server}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_srv = sanitize_powershell_string(server) if server else ""
    rsat = f"""
    $target = if ('{safe_srv}') {{ '{safe_srv}' }} else {{ $adServer }}
    $rep = if ($cred) {{
        Get-ADReplicationPartnerMetadata -Target $target -Server $adServer -Credential $cred
    }} else {{
        Get-ADReplicationPartnerMetadata -Target $target -Server $adServer
    }}
    $rep | ForEach-Object {{
        [PSCustomObject]@{{
            Server = $_.Server
            Partner = $_.Partner
            ConsecutiveFailureCount = $_.ConsecutiveFailureCount
            LastReplicationSuccess = if ($_.LastReplicationSuccess) {{ $_.LastReplicationSuccess.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ $null }}
            LastReplicationResult = $_.LastReplicationResult
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_replication_partners(
    server: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """82. Listar parceiros de replicação de entrada e saída."""
    start = time.time()
    tool_name = "ad_get_replication_partners"
    params = {"server": server}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_srv = sanitize_powershell_string(server) if server else ""
    rsat = f"""
    $target = if ('{safe_srv}') {{ '{safe_srv}' }} else {{ $adServer }}
    $p = if ($cred) {{
        Get-ADReplicationConnection -Filter * -Server $adServer -Credential $cred
    }} else {{
        Get-ADReplicationConnection -Filter * -Server $adServer
    }}
    $p | ForEach-Object {{
        [PSCustomObject]@{{
            Name = $_.Name
            ReplicateFrom = $_.ReplicateFrom
            ReplicateTo = $_.ReplicateTo
            Enabled = $_.Enabled
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_replication_failures(
    server: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """83. Identificar falhas de replicação do Active Directory."""
    start = time.time()
    tool_name = "ad_get_replication_failures"
    params = {"server": server}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_srv = sanitize_powershell_string(server) if server else ""
    rsat = f"""
    $target = if ('{safe_srv}') {{ '{safe_srv}' }} else {{ $adServer }}
    $meta = if ($cred) {{
        Get-ADReplicationFailure -Target $target -Server $adServer -Credential $cred -ErrorAction SilentlyContinue
    }} else {{
        Get-ADReplicationFailure -Target $target -Server $adServer -ErrorAction SilentlyContinue
    }}
    if ($meta) {{
        $meta | ForEach-Object {{
            [PSCustomObject]@{{
                Partner = $_.Partner
                Server = $_.Server
                FailureCount = $_.FailureCount
                FailureType = $_.FailureType
                FirstFailureTime = if ($_.FirstFailureTime) {{ $_.FirstFailureTime.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ $null }}
                LastError = $_.LastError
            }}
        }}
    }} else {{
        @()
    }}
    """

    success, data, err = ad_bridge.run_query(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_sync_replication(
    target_dc: Optional[str] = None,
    all_dcs: bool = False,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """84. Solicitar sincronização imediata de replicação (repadmin /syncall)."""
    start = time.time()
    tool_name = "ad_sync_replication"
    params = {"target_dc": target_dc, "all_dcs": all_dcs, "confirmation_token": confirmation_token, "dry_run": dry_run}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=target_dc or "Forest")
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_dc = sanitize_powershell_string(target_dc) if target_dc else ""
    rsat = f"""
    $target = if ('{safe_dc}') {{ '{safe_dc}' }} else {{ $adServer }}
    if (${str(all_dcs).lower()}) {{
        Sync-ADObject -Server $target -ErrorAction SilentlyContinue
    }}
    repadmin /syncall $target /e /A /P /q
    [PSCustomObject]@{{
        Status = "SYNC_TRIGGERED"
        Target = $target
        AllDCs = ${str(all_dcs).lower()}
    }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_dc_services_status(
    server: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """85. Consultar estado dos serviços essenciais do DC (NTDS, DNS, KDC, Netlogon, W32Time)."""
    start = time.time()
    tool_name = "ad_get_dc_services_status"
    params = {"server": server}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_srv = sanitize_powershell_string(server) if server else ""
    script = f"""
    $target = if ('{safe_srv}') {{ '{safe_srv}' }} else {{ $adServer }}
    $services = @("NTDS", "DNS", "Kdc", "Netlogon", "W32Time", "ADWS")
    $res = @()
    foreach ($s in $services) {{
        try {{
            $svc = Get-Service -Name $s -ComputerName $target -ErrorAction SilentlyContinue
            if ($svc) {{
                $res += [PSCustomObject]@{{
                    ServiceName = $svc.Name
                    DisplayName = $svc.DisplayName
                    Status = [string]$svc.Status
                    StartType = [string]$svc.StartType
                }}
            }} else {{
                $res += [PSCustomObject]@{{
                    ServiceName = $s
                    Status = "NotInstalledOrInaccessible"
                }}
            }}
        }} catch {{
            $res += [PSCustomObject]@{{ ServiceName = $s; Status = "Error"; Details = $_.Exception.Message }}
        }}
    }}
    $res
    """

    success, data, err = ad_bridge.run_query(script)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_dc_event_logs(
    log_name: str = "Directory Service",
    hours: int = 12,
    limit: int = 50,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """86. Consultar eventos recentes nos logs do controlador (Directory Service, System, DNS)."""
    start = time.time()
    tool_name = "ad_get_dc_event_logs"
    params = {"log_name": log_name, "hours": hours, "limit": limit}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_log = sanitize_powershell_string(log_name)
    script = f"""
    $startTime = (Get-Date).AddHours(-{hours})
    $events = Get-WinEvent -FilterHashtable @{{
        LogName = '{safe_log}'
        StartTime = $startTime
    }} -MaxEvents {limit} -ErrorAction SilentlyContinue

    if ($events) {{
        $events | ForEach-Object {{
            [PSCustomObject]@{{
                TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Id = $_.Id
                LevelDisplayName = $_.LevelDisplayName
                ProviderName = $_.ProviderName
                Message = $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length))
            }}
        }}
    }} else {{
        @()
    }}
    """

    success, data, err = ad_bridge.run_query(script)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_directory_health(
    server: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """87. Executar verificações de integridade e saúde do Active Directory."""
    start = time.time()
    tool_name = "ad_get_directory_health"
    params = {"server": server}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_srv = sanitize_powershell_string(server) if server else ""
    script = f"""
    $target = if ('{safe_srv}') {{ '{safe_srv}' }} else {{ $adServer }}
    # Perform core health probes
    $ldapTest = Test-NetConnection -ComputerName $target -Port 389 -WarningAction SilentlyContinue
    $kdcTest = Test-NetConnection -ComputerName $target -Port 88 -WarningAction SilentlyContinue
    $smbTest = Test-NetConnection -ComputerName $target -Port 445 -WarningAction SilentlyContinue
    $dnsTest = Test-NetConnection -ComputerName $target -Port 53 -WarningAction SilentlyContinue

    [PSCustomObject]@{{
        Target = $target
        LDAP_Available = $ldapTest.TcpTestSucceeded
        Kerberos_Available = $kdcTest.TcpTestSucceeded
        SMB_Available = $smbTest.TcpTestSucceeded
        DNS_Available = $dnsTest.TcpTestSucceeded
        OverallHealth = if ($ldapTest.TcpTestSucceeded -and $kdcTest.TcpTestSucceeded -and $dnsTest.TcpTestSucceeded) {{ "HEALTHY" }} else {{ "DEGRADED" }}
    }}
    """

    success, data, err = ad_bridge.run_query(script)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_test_secure_channel(
    computer_name: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """88. Testar canal seguro (Secure Channel) entre computador e domínio."""
    start = time.time()
    tool_name = "ad_test_secure_channel"
    params = {"computer_name": computer_name}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    script = """
    $test = Test-ComputerSecureChannel -Verbose -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        SecureChannelValid = [bool]$test
        TestedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
    """

    success, data, err = ad_bridge.run_query(script)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_time_sync_status(
    server: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """89. Verificar status de sincronização de horário (W32Time) com o PDC Emulator."""
    start = time.time()
    tool_name = "ad_get_time_sync_status"
    params = {"server": server}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    script = """
    $status = w32tm /query /status
    [PSCustomObject]@{
        RawOutput = ($status -join "`n")
        QueryTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
    """

    success, data, err = ad_bridge.run_query(script)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_sysvol_status(
    server: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """90. Verificar disponibilidade e compartilhamento das pastas SYSVOL e Netlogon."""
    start = time.time()
    tool_name = "ad_get_sysvol_status"
    params = {"server": server}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_srv = sanitize_powershell_string(server) if server else ""
    script = f"""
    $target = if ('{safe_srv}') {{ '{safe_srv}' }} else {{ $adServer }}
    $sysvol = Test-Path "\\\\$target\\SYSVOL"
    $netlogon = Test-Path "\\\\$target\\NETLOGON"
    [PSCustomObject]@{{
        Target = $target
        SYSVOL_Share_Accessible = $sysvol
        NETLOGON_Share_Accessible = $netlogon
        ReplicationReady = ($sysvol -and $netlogon)
    }}
    """

    success, data, err = ad_bridge.run_query(script)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()
