"""
Tools Category 4: Computers and Devices (Tools 31 to 40).
"""

import time
from typing import Any, Dict, Optional

from ad_mcp.audit.logger import audit_logger
from ad_mcp.authorization.guardrails import sanitize_ldap_filter, sanitize_powershell_string
from ad_mcp.authorization.rbac import auth_engine
from ad_mcp.integrations.bridge import ad_bridge
from ad_mcp.models.response import ToolResponse


def ad_list_computers(
    limit: int = 100,
    search_base: Optional[str] = None,
    enabled_only: Optional[bool] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """31. Listar computadores registrados no domínio."""
    start = time.time()
    tool_name = "ad_list_computers"
    params = {"limit": limit, "search_base": search_base, "enabled_only": enabled_only}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    filter_clause = (
        "Enabled -eq $true" if enabled_only is True else ("Enabled -eq $false" if enabled_only is False else "*")
    )
    base_clause = f"-SearchBase '{sanitize_powershell_string(search_base)}'" if search_base else ""

    rsat = f"""
    $comps = if ($cred) {{ Get-ADComputer -Filter '{filter_clause}' {base_clause} -ResultSetSize {limit} -Properties OperatingSystem, OperatingSystemVersion, IPv4Address, Enabled, LastLogonDate -Server $adServer -Credential $cred }} else {{ Get-ADComputer -Filter '{filter_clause}' {base_clause} -ResultSetSize {limit} -Properties OperatingSystem, OperatingSystemVersion, IPv4Address, Enabled, LastLogonDate -Server $adServer }}
    $comps | ForEach-Object {{
        [PSCustomObject]@{{
            Name = $_.Name
            DNSHostName = $_.DNSHostName
            DistinguishedName = $_.DistinguishedName
            OperatingSystem = $_.OperatingSystem
            OperatingSystemVersion = $_.OperatingSystemVersion
            IPv4Address = $_.IPv4Address
            Enabled = $_.Enabled
            LastLogonDate = if ($_.LastLogonDate) {{ $_.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ $null }}
        }}
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = if ('{sanitize_powershell_string(search_base)}') {{ '{sanitize_powershell_string(search_base)}' }} else {{ $root.defaultNamingContext }}
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(objectCategory=computer)"
    $searcher.SizeLimit = {limit}
    $searcher.PropertiesToLoad.AddRange(@("name", "dnshostname", "operatingsystem", "operatingsystemversion", "useraccountcontrol"))
    $searcher.FindAll() | ForEach-Object {{
        $uac = [int]$_.Properties["useraccountcontrol"][0]
        [PSCustomObject]@{{
            Name = [string]$_.Properties["name"][0]
            DNSHostName = [string]$_.Properties["dnshostname"][0]
            DistinguishedName = [string]$_.Path.Replace("LDAP://$adServer/", "")
            OperatingSystem = [string]$_.Properties["operatingsystem"][0]
            OperatingSystemVersion = [string]$_.Properties["operatingsystemversion"][0]
            Enabled = ($uac -band 2) -eq 0
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_computer(
    identity: str,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """32. Consultar detalhes de um computador."""
    start = time.time()
    tool_name = "ad_get_computer"
    params = {"identity": identity}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rsat = f"""
    $c = if ($cred) {{ Get-ADComputer -Identity '{safe_id}' -Properties * -Server $adServer -Credential $cred }} else {{ Get-ADComputer -Identity '{safe_id}' -Properties * -Server $adServer }}
    [PSCustomObject]@{{
        Name = $c.Name
        DNSHostName = $c.DNSHostName
        DistinguishedName = $c.DistinguishedName
        OperatingSystem = $c.OperatingSystem
        OperatingSystemVersion = $c.OperatingSystemVersion
        OperatingSystemServicePack = $c.OperatingSystemServicePack
        IPv4Address = $c.IPv4Address
        Enabled = $c.Enabled
        PasswordLastSet = if ($c.PasswordLastSet) {{ $c.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ $null }}
        LastLogonDate = if ($c.LastLogonDate) {{ $c.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ $null }}
        WhenCreated = if ($c.WhenCreated) {{ $c.WhenCreated.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ $null }}
        SID = [string]$c.SID.Value
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectCategory=computer)(|(name={safe_id})(sAMAccountName={safe_id}$)))"
    $res = $searcher.FindOne()
    if ($res) {{
        $uac = [int]$res.Properties["useraccountcontrol"][0]
        [PSCustomObject]@{{
            Name = [string]$res.Properties["name"][0]
            DNSHostName = [string]$res.Properties["dnshostname"][0]
            DistinguishedName = [string]$res.Properties["distinguishedname"][0]
            OperatingSystem = [string]$res.Properties["operatingsystem"][0]
            Enabled = ($uac -band 2) -eq 0
        }}
    }} else {{ throw "Computer '{safe_id}' not found." }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_search_computers(
    query: str,
    limit: int = 50,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """33. Pesquisar computadores por nome, sistema operacional ou OU."""
    start = time.time()
    tool_name = "ad_search_computers"
    params = {"query": query, "limit": limit}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_q = sanitize_powershell_string(query)
    safe_ldap = sanitize_ldap_filter(query)

    rsat = f"""
    $c = if ($cred) {{ Get-ADComputer -Filter 'Name -like "*{safe_q}*" -or OperatingSystem -like "*{safe_q}*" -or DNSHostName -like "*{safe_q}*"' -ResultSetSize {limit} -Properties OperatingSystem, Enabled -Server $adServer -Credential $cred }} else {{ Get-ADComputer -Filter 'Name -like "*{safe_q}*" -or OperatingSystem -like "*{safe_q}*" -or DNSHostName -like "*{safe_q}*"' -ResultSetSize {limit} -Properties OperatingSystem, Enabled -Server $adServer }}
    $c | ForEach-Object {{
        [PSCustomObject]@{{
            Name = $_.Name
            DNSHostName = $_.DNSHostName
            OperatingSystem = $_.OperatingSystem
            Enabled = $_.Enabled
            DistinguishedName = $_.DistinguishedName
        }}
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectCategory=computer)(|(name=*{safe_ldap}*)(operatingSystem=*{safe_ldap}*)))"
    $searcher.SizeLimit = {limit}
    $searcher.FindAll() | ForEach-Object {{
        [PSCustomObject]@{{
            Name = [string]$_.Properties["name"][0]
            DNSHostName = [string]$_.Properties["dnshostname"][0]
            OperatingSystem = [string]$_.Properties["operatingsystem"][0]
            DistinguishedName = [string]$_.Properties["distinguishedname"][0]
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_create_computer(
    name: str,
    path: str,
    sam_account_name: Optional[str] = None,
    description: Optional[str] = None,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """34. Criar objeto de computador no Active Directory."""
    start = time.time()
    tool_name = "ad_create_computer"
    params = {"name": name, "path": path, "confirmation_token": confirmation_token, "dry_run": dry_run}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=name)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_name = sanitize_powershell_string(name)
    safe_sam = sanitize_powershell_string(sam_account_name or f"{name}$")
    safe_path = sanitize_powershell_string(path)
    safe_desc = sanitize_powershell_string(description) if description else ""

    rsat = f"""
    $params = @{{
        Name = '{safe_name}'
        SamAccountName = '{safe_sam}'
        Path = '{safe_path}'
    }}
    if ('{safe_desc}') {{ $params['Description'] = '{safe_desc}' }}
    if ($cred) {{ $params['Server'] = $adServer; $params['Credential'] = $cred }} else {{ $params['Server'] = $adServer }}

    New-ADComputer @params
    [PSCustomObject]@{{
        Status = "CREATED"
        Name = '{safe_name}'
        DistinguishedName = "CN={safe_name},{safe_path}"
    }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_update_computer(
    identity: str,
    description: Optional[str] = None,
    location: Optional[str] = None,
    managed_by: Optional[str] = None,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """35. Atualizar atributos de um computador."""
    start = time.time()
    tool_name = "ad_update_computer"
    params = {
        "identity": identity,
        "description": description,
        "location": location,
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
    if location is not None:
        updates.append(f"-Location '{sanitize_powershell_string(location)}'")
    if managed_by is not None:
        updates.append(f"-ManagedBy '{sanitize_powershell_string(managed_by)}'")

    args_str = " ".join(updates)
    rsat = f"""
    if ($cred) {{ Set-ADComputer -Identity '{safe_id}' {args_str} -Server $adServer -Credential $cred }} else {{ Set-ADComputer -Identity '{safe_id}' {args_str} -Server $adServer }}
    [PSCustomObject]@{{ Status = "UPDATED"; Identity = '{safe_id}' }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_disable_computer(
    identity: str,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """36. Desabilitar conta de computador."""
    start = time.time()
    tool_name = "ad_disable_computer"
    params = {"identity": identity, "confirmation_token": confirmation_token, "dry_run": dry_run}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rsat = f"""
    if ($cred) {{ Disable-ADAccount -Identity '{safe_id}' -Server $adServer -Credential $cred }} else {{ Disable-ADAccount -Identity '{safe_id}' -Server $adServer }}
    [PSCustomObject]@{{ Status = "DISABLED"; Identity = '{safe_id}' }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_enable_computer(
    identity: str,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """37. Habilitar conta de computador."""
    start = time.time()
    tool_name = "ad_enable_computer"
    params = {"identity": identity, "confirmation_token": confirmation_token, "dry_run": dry_run}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rsat = f"""
    if ($cred) {{ Enable-ADAccount -Identity '{safe_id}' -Server $adServer -Credential $cred }} else {{ Enable-ADAccount -Identity '{safe_id}' -Server $adServer }}
    [PSCustomObject]@{{ Status = "ENABLED"; Identity = '{safe_id}' }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_delete_computer(
    identity: str,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """38. Excluir conta de computador (operação destrutiva com confirmação)."""
    start = time.time()
    tool_name = "ad_delete_computer"
    params = {"identity": identity, "confirmation_token": confirmation_token, "dry_run": dry_run}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rsat = f"""
    if ($cred) {{ Remove-ADComputer -Identity '{safe_id}' -Confirm:$false -Server $adServer -Credential $cred }} else {{ Remove-ADComputer -Identity '{safe_id}' -Confirm:$false -Server $adServer }}
    [PSCustomObject]@{{ Status = "DELETED"; Identity = '{safe_id}' }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_move_computer(
    identity: str,
    target_path: str,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """39. Mover computador entre OUs."""
    start = time.time()
    tool_name = "ad_move_computer"
    params = {
        "identity": identity,
        "target_path": target_path,
        "confirmation_token": confirmation_token,
        "dry_run": dry_run,
    }
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    safe_path = sanitize_powershell_string(target_path)

    rsat = f"""
    if ($cred) {{ Move-ADObject -Identity '{safe_id}' -TargetPath '{safe_path}' -Server $adServer -Credential $cred }} else {{ Move-ADObject -Identity '{safe_id}' -TargetPath '{safe_path}' -Server $adServer }}
    [PSCustomObject]@{{ Status = "MOVED"; Identity = '{safe_id}'; TargetPath = '{safe_path}' }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_stale_computers(
    days: int = 90,
    limit: int = 100,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """40. Identificar computadores inativos (sem logon recente) há determinado período."""
    start = time.time()
    tool_name = "ad_get_stale_computers"
    params = {"days": days, "limit": limit}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = f"""
    $cutOff = (Get-Date).AddDays(-{days})
    $comps = if ($cred) {{
        Get-ADComputer -Filter 'LastLogonDate -lt $cutOff -or (Enabled -eq $true -and LastLogonDate -notlike "*")' -Properties OperatingSystem, LastLogonDate, Enabled -ResultSetSize {limit} -Server $adServer -Credential $cred
    }} else {{
        Get-ADComputer -Filter 'LastLogonDate -lt $cutOff -or (Enabled -eq $true -and LastLogonDate -notlike "*")' -Properties OperatingSystem, LastLogonDate, Enabled -ResultSetSize {limit} -Server $adServer
    }}
    $comps | ForEach-Object {{
        [PSCustomObject]@{{
            Name = $_.Name
            DNSHostName = $_.DNSHostName
            OperatingSystem = $_.OperatingSystem
            Enabled = $_.Enabled
            LastLogonDate = if ($_.LastLogonDate) {{ $_.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ "Never" }}
            DistinguishedName = $_.DistinguishedName
        }}
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(objectCategory=computer)"
    $searcher.SizeLimit = {limit}
    $searcher.FindAll() | ForEach-Object {{
        [PSCustomObject]@{{
            Name = [string]$_.Properties["name"][0]
            DistinguishedName = [string]$_.Properties["distinguishedname"][0]
            OperatingSystem = [string]$_.Properties["operatingsystem"][0]
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()
