"""
Tools Category 1: Domain and Domain Controllers (Tools 1 to 10).
"""

import time
from typing import Any, Dict, Optional

from ad_mcp.audit.logger import audit_logger
from ad_mcp.authorization.rbac import auth_engine
from ad_mcp.integrations.bridge import ad_bridge
from ad_mcp.models.response import ToolResponse


def ad_get_domain_info(
    server: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """1. Consultar informações detalhadas do domínio atual."""
    start = time.time()
    tool_name = "ad_get_domain_info"
    params = {"server": server}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = """
    $d = if ($cred) { Get-ADDomain -Server $adServer -Credential $cred } else { Get-ADDomain -Server $adServer }
    [PSCustomObject]@{
        Name = $d.Name
        DnsRoot = $d.DNSRoot
        NetBIOSName = $d.NetBIOSName
        DomainMode = [string]$d.DomainMode
        DomainSID = [string]$d.DomainSID.Value
        DistinguishedName = $d.DistinguishedName
        PDCEmulator = $d.PDCEmulator
        RIDMaster = $d.RIDMaster
        InfrastructureMaster = $d.InfrastructureMaster
        Forest = $d.Forest
    }
    """

    adsi = """
    $root = if ($adUser -and $adPass) { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) } else { [adsi]"LDAP://$adServer/RootDSE" }
    $defNC = $root.defaultNamingContext
    $entry = if ($adUser -and $adPass) { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass) } else { [adsi]"LDAP://$adServer/$defNC" }
    [PSCustomObject]@{
        DnsRoot = [string]$root.dnsHostName
        DistinguishedName = [string]$defNC
        DomainMode = [string]$root.domainFunctionality
        Forest = [string]$root.rootDomainNamingContext
    }
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)

    resp = ToolResponse(success=success, data=data, error=err, execution_time_ms=duration)
    return resp.to_mcp_content()


def ad_list_domains(correlation_id: Optional[str] = None) -> Dict[str, Any]:
    """2. Listar todos os domínios disponíveis na floresta."""
    start = time.time()
    tool_name = "ad_list_domains"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = """
    $f = if ($cred) { Get-ADForest -Server $adServer -Credential $cred } else { Get-ADForest -Server $adServer }
    $f.Domains | ForEach-Object { [PSCustomObject]@{ Domain = $_ } }
    """

    adsi = """
    $root = if ($adUser -and $adPass) { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) } else { [adsi]"LDAP://$adServer/RootDSE" }
    $configNC = $root.configurationNamingContext
    $searcher = New-Object System.DirectoryServices.DirectorySearcher((New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$configNC", $adUser, $adPass)))
    $searcher.Filter = "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=1))"
    $searcher.FindAll() | ForEach-Object { [PSCustomObject]@{ Domain = [string]$_.Properties["dnsroot"][0] } }
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_forest_info(correlation_id: Optional[str] = None) -> Dict[str, Any]:
    """3. Consultar informações da floresta Active Directory."""
    start = time.time()
    tool_name = "ad_get_forest_info"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = """
    $f = if ($cred) { Get-ADForest -Server $adServer -Credential $cred } else { Get-ADForest -Server $adServer }
    [PSCustomObject]@{
        Name = $f.Name
        RootDomain = $f.RootDomain
        ForestMode = [string]$f.ForestMode
        SchemaMaster = $f.SchemaMaster
        DomainNamingMaster = $f.DomainNamingMaster
        Domains = $f.Domains
        GlobalCatalogs = $f.GlobalCatalogs
        Sites = $f.Sites
    }
    """

    adsi = """
    $root = if ($adUser -and $adPass) { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) } else { [adsi]"LDAP://$adServer/RootDSE" }
    [PSCustomObject]@{
        RootDomain = [string]$root.rootDomainNamingContext
        ForestMode = [string]$root.forestFunctionality
        ConfigurationNC = [string]$root.configurationNamingContext
        SchemaNC = [string]$root.schemaNamingContext
    }
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_list_domain_controllers(correlation_id: Optional[str] = None) -> Dict[str, Any]:
    """4. Listar controladores de domínio (DCs) registrados."""
    start = time.time()
    tool_name = "ad_list_domain_controllers"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = """
    $dcs = if ($cred) { Get-ADDomainController -Filter * -Server $adServer -Credential $cred } else { Get-ADDomainController -Filter * -Server $adServer }
    $dcs | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            HostName = $_.HostName
            IPAddress = $_.IPv4Address
            OperatingSystem = $_.OperatingSystem
            Site = $_.Site
            IsGlobalCatalog = $_.IsGlobalCatalog
            IsReadOnly = $_.IsReadOnly
            Enabled = $_.Enabled
        }
    }
    """

    adsi = """
    $root = if ($adUser -and $adPass) { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) } else { [adsi]"LDAP://$adServer/RootDSE" }
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
    $searcher.FindAll() | ForEach-Object {
        [PSCustomObject]@{
            Name = [string]$_.Properties["name"][0]
            HostName = [string]$_.Properties["dnshostname"][0]
            DistinguishedName = [string]$_.Properties["distinguishedname"][0]
        }
    }
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_domain_controller_info(
    identity: str,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """5. Consultar detalhes de um controlador de domínio específico."""
    start = time.time()
    tool_name = "ad_get_domain_controller_info"
    params = {"identity": identity}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = f"""
    $dc = if ($cred) {{ Get-ADDomainController -Identity '{identity}' -Server $adServer -Credential $cred }} else {{ Get-ADDomainController -Identity '{identity}' -Server $adServer }}
    [PSCustomObject]@{{
        Name = $dc.Name
        HostName = $dc.HostName
        IPv4Address = $dc.IPv4Address
        IPv6Address = $dc.IPv6Address
        Site = $dc.Site
        Forest = $dc.Forest
        OperatingSystem = $dc.OperatingSystem
        OperatingSystemVersion = $dc.OperatingSystemVersion
        IsGlobalCatalog = $dc.IsGlobalCatalog
        IsReadOnly = $dc.IsReadOnly
        OperationMasterRoles = $dc.OperationMasterRoles
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectCategory=computer)(name={identity}))"
    $res = $searcher.FindOne()
    if ($res) {{
        [PSCustomObject]@{{
            Name = [string]$res.Properties["name"][0]
            HostName = [string]$res.Properties["dnshostname"][0]
            DistinguishedName = [string]$res.Properties["distinguishedname"][0]
        }}
    }} else {{ throw "Domain Controller '$identity' not found." }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_test_domain_controller(
    target_host: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """6. Verificar disponibilidade de portas e serviços de um DC (LDAP, Kerberos, SMB, DNS)."""
    start = time.time()
    tool_name = "ad_test_domain_controller"
    params = {"target_host": target_host}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    script = f"""
    $target = if ('{target_host}') {{ '{target_host}' }} else {{ $adServer }}
    $ports = @{{
        "LDAP_389" = 389
        "LDAPS_636" = 636
        "Kerberos_88" = 88
        "SMB_445" = 445
        "DNS_53" = 53
        "GC_3268" = 3268
    }}
    $results = @{{}}
    foreach ($k in $ports.Keys) {{
        $p = $ports[$k]
        try {{
            $tcp = Test-NetConnection -ComputerName $target -Port $p -WarningAction SilentlyContinue
            $results[$k] = [PSCustomObject]@{{
                Port = $p
                Open = $tcp.TcpTestSucceeded
            }}
        }} catch {{
            $results[$k] = [PSCustomObject]@{{ Port = $p; Open = $false; Error = $_.Exception.Message }}
        }}
    }}
    [PSCustomObject]@{{
        Target = $target
        Ports = $results
        AllCorePortsReachable = ($results["LDAP_389"].Open -and $results["Kerberos_88"].Open)
    }}
    """

    success, data, err = ad_bridge.run_query(script)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_domain_functional_level(correlation_id: Optional[str] = None) -> Dict[str, Any]:
    """7. Consultar nível funcional do domínio."""
    start = time.time()
    tool_name = "ad_get_domain_functional_level"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = """
    $d = if ($cred) { Get-ADDomain -Server $adServer -Credential $cred } else { Get-ADDomain -Server $adServer }
    [PSCustomObject]@{ Domain = $d.DNSRoot; DomainMode = [string]$d.DomainMode }
    """

    adsi = """
    $root = if ($adUser -and $adPass) { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) } else { [adsi]"LDAP://$adServer/RootDSE" }
    [PSCustomObject]@{
        Domain = [string]$root.dnsHostName
        DomainFunctionalityLevel = [string]$root.domainFunctionality
    }
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_forest_functional_level(correlation_id: Optional[str] = None) -> Dict[str, Any]:
    """8. Consultar nível funcional da floresta."""
    start = time.time()
    tool_name = "ad_get_forest_functional_level"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = """
    $f = if ($cred) { Get-ADForest -Server $adServer -Credential $cred } else { Get-ADForest -Server $adServer }
    [PSCustomObject]@{ Forest = $f.Name; ForestMode = [string]$f.ForestMode }
    """

    adsi = """
    $root = if ($adUser -and $adPass) { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) } else { [adsi]"LDAP://$adServer/RootDSE" }
    [PSCustomObject]@{
        RootDomain = [string]$root.rootDomainNamingContext
        ForestFunctionalityLevel = [string]$root.forestFunctionality
    }
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_fsmo_roles(correlation_id: Optional[str] = None) -> Dict[str, Any]:
    """9. Consultar detentores das 5 funções FSMO da floresta e do domínio."""
    start = time.time()
    tool_name = "ad_get_fsmo_roles"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = """
    $f = if ($cred) { Get-ADForest -Server $adServer -Credential $cred } else { Get-ADForest -Server $adServer }
    $d = if ($cred) { Get-ADDomain -Server $adServer -Credential $cred } else { Get-ADDomain -Server $adServer }
    [PSCustomObject]@{
        SchemaMaster = $f.SchemaMaster
        DomainNamingMaster = $f.DomainNamingMaster
        PDCEmulator = $d.PDCEmulator
        RIDMaster = $d.RIDMaster
        InfrastructureMaster = $d.InfrastructureMaster
    }
    """

    adsi = """
    $root = if ($adUser -and $adPass) { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) } else { [adsi]"LDAP://$adServer/RootDSE" }
    $defNC = $root.defaultNamingContext
    $schemaNC = $root.schemaNamingContext
    $configNC = $root.configurationNamingContext

    $schemaEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$schemaNC", $adUser, $adPass)
    $namingEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/CN=Partitions,$configNC", $adUser, $adPass)
    $infraEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/CN=Infrastructure,$defNC", $adUser, $adPass)
    $ridEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/CN=RID Manager$,CN=System,$defNC", $adUser, $adPass)

    [PSCustomObject]@{
        SchemaMaster = [string]$schemaEntry.Properties["fSMORoleOwner"][0]
        DomainNamingMaster = [string]$namingEntry.Properties["fSMORoleOwner"][0]
        InfrastructureMaster = [string]$infraEntry.Properties["fSMORoleOwner"][0]
        RIDMaster = [string]$ridEntry.Properties["fSMORoleOwner"][0]
        PDCEmulator = [string]$root.dnsHostName
    }
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_domain_trusts(correlation_id: Optional[str] = None) -> Dict[str, Any]:
    """10. Consultar relações de confiança (Trusts) do domínio."""
    start = time.time()
    tool_name = "ad_get_domain_trusts"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = """
    $trusts = if ($cred) { Get-ADTrust -Filter * -Server $adServer -Credential $cred } else { Get-ADTrust -Filter * -Server $adServer }
    $trusts | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            Source = $_.Source
            Target = $_.Target
            Direction = [string]$_.Direction
            TrustType = [string]$_.TrustType
            IntraForest = $_.IntraForest
            SelectiveAuthentication = $_.SelectiveAuthentication
        }
    }
    """

    adsi = """
    $root = if ($adUser -and $adPass) { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) } else { [adsi]"LDAP://$adServer/RootDSE" }
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/CN=System,$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(objectClass=trustedDomain)"
    $searcher.FindAll() | ForEach-Object {
        [PSCustomObject]@{
            Name = [string]$_.Properties["trustpartner"][0]
            TrustDirection = [string]$_.Properties["trustdirection"][0]
            TrustType = [string]$_.Properties["trusttype"][0]
        }
    }
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()
