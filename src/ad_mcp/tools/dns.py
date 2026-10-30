"""
Tools Category 7: DNS and Infrastructure (Tools 61 to 70).
"""

import time
from typing import Any, Dict, Optional

from ad_mcp.audit.logger import audit_logger
from ad_mcp.authorization.guardrails import sanitize_powershell_string
from ad_mcp.authorization.rbac import auth_engine
from ad_mcp.integrations.bridge import ad_bridge
from ad_mcp.integrations.kerberos import kerberos_client
from ad_mcp.models.response import ToolResponse


def ad_list_dns_zones(
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """61. Listar zonas DNS integradas ao Active Directory."""
    start = time.time()
    tool_name = "ad_list_dns_zones"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = """
    Import-Module DnsServer -ErrorAction SilentlyContinue
    $zones = Get-DnsServerZone -ComputerName $adServer
    $zones | ForEach-Object {
        [PSCustomObject]@{
            ZoneName = $_.ZoneName
            ZoneType = [string]$_.ZoneType
            IsDsIntegrated = $_.IsDsIntegrated
            IsReverseLookupZone = $_.IsReverseLookupZone
            IsAutoCreated = $_.IsAutoCreated
        }
    }
    """

    adsi = """
    $root = if ($adUser -and $adPass) { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) } else { [adsi]"LDAP://$adServer/RootDSE" }
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/CN=MicrosoftDNS,DC=DomainDnsZones,$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(objectClass=dnsZone)"
    $searcher.FindAll() | ForEach-Object {
        [PSCustomObject]@{
            ZoneName = [string]$_.Properties["name"][0]
            IsDsIntegrated = $true
        }
    }
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_dns_zone(
    zone_name: str,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """62. Consultar detalhes e configurações de uma zona DNS."""
    start = time.time()
    tool_name = "ad_get_dns_zone"
    params = {"zone_name": zone_name}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_zone = sanitize_powershell_string(zone_name)
    rsat = f"""
    Import-Module DnsServer -ErrorAction SilentlyContinue
    $z = Get-DnsServerZone -Name '{safe_zone}' -ComputerName $adServer
    [PSCustomObject]@{{
        ZoneName = $z.ZoneName
        ZoneType = [string]$z.ZoneType
        IsDsIntegrated = $z.IsDsIntegrated
        IsReverseLookupZone = $z.IsReverseLookupZone
        DynamicUpdate = [string]$z.DynamicUpdate
        SecureSecondaries = [string]$z.SecureSecondaries
    }}
    """

    success, data, err = ad_bridge.run_query(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_list_dns_records(
    zone_name: str,
    record_type: Optional[str] = None,
    limit: int = 100,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """63. Listar registros DNS de uma zona com filtro opcional por tipo."""
    start = time.time()
    tool_name = "ad_list_dns_records"
    params = {"zone_name": zone_name, "record_type": record_type, "limit": limit}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_zone = sanitize_powershell_string(zone_name)
    type_clause = f"-RRType '{sanitize_powershell_string(record_type)}'" if record_type else ""

    rsat = f"""
    Import-Module DnsServer -ErrorAction SilentlyContinue
    $recs = Get-DnsServerResourceRecord -ZoneName '{safe_zone}' {type_clause} -ComputerName $adServer
    $recs | Select-Object -First {limit} | ForEach-Object {{
        [PSCustomObject]@{{
            HostName = $_.HostName
            RecordType = $_.RecordType
            RecordData = $_.RecordData.IPv4Address.IPAddressToString ?? $_.RecordData.HostNameAlias ?? $_.RecordData.ToString()
            TimeToLive = $_.TimeToLive.TotalSeconds
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_dns_record(
    zone_name: str,
    name: str,
    record_type: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """64. Consultar registro DNS específico."""
    start = time.time()
    tool_name = "ad_get_dns_record"
    params = {"zone_name": zone_name, "name": name, "record_type": record_type}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_zone = sanitize_powershell_string(zone_name)
    safe_name = sanitize_powershell_string(name)
    type_clause = f"-RRType '{sanitize_powershell_string(record_type)}'" if record_type else ""

    rsat = f"""
    Import-Module DnsServer -ErrorAction SilentlyContinue
    $recs = Get-DnsServerResourceRecord -ZoneName '{safe_zone}' -Name '{safe_name}' {type_clause} -ComputerName $adServer
    $recs | ForEach-Object {{
        [PSCustomObject]@{{
            HostName = $_.HostName
            RecordType = $_.RecordType
            RecordData = $_.RecordData.IPv4Address.IPAddressToString ?? $_.RecordData.HostNameAlias ?? $_.RecordData.ToString()
            TimeToLive = $_.TimeToLive.TotalSeconds
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_create_dns_record(
    zone_name: str,
    name: str,
    ipv4_address: Optional[str] = None,
    cname_alias: Optional[str] = None,
    record_type: str = "A",
    ttl_seconds: int = 3600,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """65. Criar registro DNS (A, CNAME, etc.) no servidor DNS do AD."""
    start = time.time()
    tool_name = "ad_create_dns_record"
    params = {
        "zone_name": zone_name,
        "name": name,
        "record_type": record_type,
        "confirmation_token": confirmation_token,
        "dry_run": dry_run,
    }
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=f"{name}.{zone_name}")
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_zone = sanitize_powershell_string(zone_name)
    safe_name = sanitize_powershell_string(name)
    safe_ip = sanitize_powershell_string(ipv4_address) if ipv4_address else ""
    safe_alias = sanitize_powershell_string(cname_alias) if cname_alias else ""

    rsat = f"""
    Import-Module DnsServer -ErrorAction SilentlyContinue
    if ('{record_type.upper()}' -eq 'A') {{
        Add-DnsServerResourceRecordA -Name '{safe_name}' -ZoneName '{safe_zone}' -IPv4Address '{safe_ip}' -TimeToLive (New-TimeSpan -Seconds {ttl_seconds}) -ComputerName $adServer
    }} elseif ('{record_type.upper()}' -eq 'CNAME') {{
        Add-DnsServerResourceRecordCName -Name '{safe_name}' -ZoneName '{safe_zone}' -HostNameAlias '{safe_alias}' -TimeToLive (New-TimeSpan -Seconds {ttl_seconds}) -ComputerName $adServer
    }} else {{
        throw "Unsupported record type '{record_type}'. Supported: A, CNAME"
    }}
    [PSCustomObject]@{{
        Status = "CREATED"
        ZoneName = '{safe_zone}'
        HostName = '{safe_name}'
        RecordType = '{record_type.upper()}'
    }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_update_dns_record(
    zone_name: str,
    name: str,
    new_ipv4_address: Optional[str] = None,
    new_cname_alias: Optional[str] = None,
    record_type: str = "A",
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """66. Atualizar registro DNS existente."""
    start = time.time()
    tool_name = "ad_update_dns_record"
    params = {"zone_name": zone_name, "name": name, "confirmation_token": confirmation_token, "dry_run": dry_run}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=f"{name}.{zone_name}")
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_zone = sanitize_powershell_string(zone_name)
    safe_name = sanitize_powershell_string(name)
    safe_new_ip = sanitize_powershell_string(new_ipv4_address) if new_ipv4_address else ""

    rsat = f"""
    Import-Module DnsServer -ErrorAction SilentlyContinue
    $oldRec = Get-DnsServerResourceRecord -ZoneName '{safe_zone}' -Name '{safe_name}' -RRType '{record_type}' -ComputerName $adServer
    $newRec = $oldRec.Clone()
    if ('{safe_new_ip}') {{
        $newRec.RecordData.IPv4Address = [System.Net.IPAddress]::Parse('{safe_new_ip}')
    }}
    Set-DnsServerResourceRecord -NewInputObject $newRec -OldInputObject $oldRec -ZoneName '{safe_zone}' -ComputerName $adServer
    [PSCustomObject]@{{ Status = "UPDATED"; ZoneName = '{safe_zone}'; HostName = '{safe_name}' }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_delete_dns_record(
    zone_name: str,
    name: str,
    record_type: str = "A",
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """67. Excluir registro DNS de uma zona."""
    start = time.time()
    tool_name = "ad_delete_dns_record"
    params = {
        "zone_name": zone_name,
        "name": name,
        "record_type": record_type,
        "confirmation_token": confirmation_token,
        "dry_run": dry_run,
    }
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=f"{name}.{zone_name}")
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_zone = sanitize_powershell_string(zone_name)
    safe_name = sanitize_powershell_string(name)

    rsat = f"""
    Import-Module DnsServer -ErrorAction SilentlyContinue
    Remove-DnsServerResourceRecord -ZoneName '{safe_zone}' -Name '{safe_name}' -RRType '{record_type}' -Force -ComputerName $adServer
    [PSCustomObject]@{{ Status = "DELETED"; ZoneName = '{safe_zone}'; HostName = '{safe_name}'; RecordType = '{record_type}' }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_test_dns_resolution(
    name: str,
    dns_server: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """68. Testar resolução de nomes DNS usando servidor especificado ou padrão."""
    start = time.time()
    tool_name = "ad_test_dns_resolution"
    params = {"name": name, "dns_server": dns_server}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_name = sanitize_powershell_string(name)
    server_clause = f"-Server '{sanitize_powershell_string(dns_server)}'" if dns_server else ""

    script = f"""
    $res = Resolve-DnsName -Name '{safe_name}' {server_clause} -ErrorAction SilentlyContinue
    if ($res) {{
        $res | ForEach-Object {{
            [PSCustomObject]@{{
                Name = $_.Name
                Type = [string]$_.Type
                IPAddress = $_.IPAddress
                TTL = $_.TTL
                Section = [string]$_.Section
            }}
        }}
    }} else {{
        [PSCustomObject]@{{
            Name = '{safe_name}'
            Resolved = $false
            Message = "Could not resolve name."
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(script)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_test_ldap_connectivity(
    server: Optional[str] = None,
    port: int = 389,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """69. Testar conectividade e handshake TCP na porta LDAP/LDAPS."""
    start = time.time()
    tool_name = "ad_test_ldap_connectivity"
    params = {"server": server, "port": port}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_server = sanitize_powershell_string(server) if server else ""
    script = f"""
    $target = if ('{safe_server}') {{ '{safe_server}' }} else {{ $adServer }}
    $test = Test-NetConnection -ComputerName $target -Port {port} -WarningAction SilentlyContinue
    [PSCustomObject]@{{
        Target = $target
        Port = {port}
        Reachable = $test.TcpTestSucceeded
        PingSucceeded = $test.PingSucceeded
        RoundTripTimeMs = $test.PingReplyDetails.RoundtripTime
    }}
    """

    success, data, err = ad_bridge.run_query(script)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_test_kerberos_connectivity(
    server: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """70. Verificar conectividade Kerberos na porta 88 e estado do cache de tickets."""
    start = time.time()
    tool_name = "ad_test_kerberos_connectivity"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_srv = sanitize_powershell_string(server) if server else ""
    script = f"""
    $target = if ('{safe_srv}') {{ '{safe_srv}' }} else {{ $adServer }}
    $portTest = Test-NetConnection -ComputerName $target -Port 88 -WarningAction SilentlyContinue
    [PSCustomObject]@{{
        Target = $target
        Port_88_Reachable = $portTest.TcpTestSucceeded
    }}
    """

    success, data, err = ad_bridge.run_query(script)
    # Add ticket inspection from kerberos_client
    k_info = kerberos_client.test_kerberos_connectivity()
    if isinstance(data, dict):
        data.update(k_info)

    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data or k_info, error=err, execution_time_ms=duration).to_mcp_content()
