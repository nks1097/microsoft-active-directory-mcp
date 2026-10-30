"""
Tools Category 8: Security and Audit (Tools 71 to 80).
"""

import time
from typing import Any, Dict, Optional

from ad_mcp.audit.logger import audit_logger
from ad_mcp.authorization.guardrails import sanitize_powershell_string
from ad_mcp.authorization.rbac import auth_engine
from ad_mcp.integrations.bridge import ad_bridge
from ad_mcp.models.response import ToolResponse


def ad_get_locked_accounts(
    limit: int = 100,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """71. Listar contas de usuário atualmente bloqueadas por excesso de tentativas de senha."""
    start = time.time()
    tool_name = "ad_get_locked_accounts"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = f"""
    $locked = if ($cred) {{ Search-ADAccount -LockedOut -Server $adServer -Credential $cred }} else {{ Search-ADAccount -LockedOut -Server $adServer }}
    $locked | Select-Object -First {limit} | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = $_.SamAccountName
            Name = $_.Name
            DistinguishedName = $_.DistinguishedName
            LastLogonDate = if ($_.LastLogonDate) {{ $_.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ $null }}
        }}
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))"
    $searcher.SizeLimit = {limit}
    $searcher.FindAll() | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = [string]$_.Properties["samaccountname"][0]
            Name = [string]$_.Properties["name"][0]
            DistinguishedName = [string]$_.Properties["distinguishedname"][0]
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_disabled_accounts(
    limit: int = 100,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """72. Listar todas as contas desabilitadas do domínio."""
    start = time.time()
    tool_name = "ad_get_disabled_accounts"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = f"""
    $dis = if ($cred) {{ Search-ADAccount -AccountDisabled -Server $adServer -Credential $cred }} else {{ Search-ADAccount -AccountDisabled -Server $adServer }}
    $dis | Select-Object -First {limit} | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = $_.SamAccountName
            Name = $_.Name
            DistinguishedName = $_.DistinguishedName
            ObjectClass = $_.ObjectClass
            LastLogonDate = if ($_.LastLogonDate) {{ $_.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ $null }}
        }}
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"
    $searcher.SizeLimit = {limit}
    $searcher.FindAll() | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = [string]$_.Properties["samaccountname"][0]
            Name = [string]$_.Properties["name"][0]
            DistinguishedName = [string]$_.Properties["distinguishedname"][0]
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_password_expiring_users(
    days: int = 14,
    limit: int = 100,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """73. Identificar usuários com senhas próximas do vencimento."""
    start = time.time()
    tool_name = "ad_get_password_expiring_users"
    params = {"days": days, "limit": limit}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = f"""
    $exp = if ($cred) {{
        Search-ADAccount -PasswordExpiring -TimeSpan (New-TimeSpan -Days {days}) -Server $adServer -Credential $cred
    }} else {{
        Search-ADAccount -PasswordExpiring -TimeSpan (New-TimeSpan -Days {days}) -Server $adServer
    }}
    $exp | Select-Object -First {limit} | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = $_.SamAccountName
            Name = $_.Name
            DistinguishedName = $_.DistinguishedName
            LastLogonDate = if ($_.LastLogonDate) {{ $_.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ $null }}
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_password_never_expires_users(
    limit: int = 100,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """74. Identificar contas de usuário configuradas com 'Senha Nunca Expira'."""
    start = time.time()
    tool_name = "ad_get_password_never_expires_users"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = f"""
    $users = if ($cred) {{
        Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and Enabled -eq $true' -Properties DisplayName, Mail, PasswordLastSet -ResultSetSize {limit} -Server $adServer -Credential $cred
    }} else {{
        Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and Enabled -eq $true' -Properties DisplayName, Mail, PasswordLastSet -ResultSetSize {limit} -Server $adServer
    }}
    $users | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = $_.SamAccountName
            DisplayName = $_.DisplayName
            Mail = $_.Mail
            PasswordLastSet = if ($_.PasswordLastSet) {{ $_.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ "Never" }}
            DistinguishedName = $_.DistinguishedName
        }}
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
    $searcher.SizeLimit = {limit}
    $searcher.FindAll() | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = [string]$_.Properties["samaccountname"][0]
            Name = [string]$_.Properties["name"][0]
            DistinguishedName = [string]$_.Properties["distinguishedname"][0]
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_privileged_users(
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """75. Identificar todos os usuários pertencentes a grupos privilegiados de administração."""
    start = time.time()
    tool_name = "ad_get_privileged_users"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = """
    $privGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Backup Operators", "Server Operators")
    $results = @()
    foreach ($grp in $privGroups) {
        try {
            $m = if ($cred) { Get-ADGroupMember -Identity $grp -Recursive -Server $adServer -Credential $cred } else { Get-ADGroupMember -Identity $grp -Recursive -Server $adServer }
            foreach ($user in $m) {
                $results += [PSCustomObject]@{
                    Group = $grp
                    SamAccountName = $user.SamAccountName
                    Name = $user.Name
                    DistinguishedName = $user.DistinguishedName
                }
            }
        } catch {}
    }
    $results | Sort-Object SamAccountName -Unique
    """

    adsi = """
    $root = if ($adUser -and $adPass) { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) } else { [adsi]"LDAP://$adServer/RootDSE" }
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(adminCount=1))"
    $searcher.FindAll() | ForEach-Object {
        [PSCustomObject]@{
            SamAccountName = [string]$_.Properties["samaccountname"][0]
            Name = [string]$_.Properties["name"][0]
            DistinguishedName = [string]$_.Properties["distinguishedname"][0]
        }
    }
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_domain_admins(correlation_id: Optional[str] = None) -> Dict[str, Any]:
    """76. Consultar membros do grupo 'Domain Admins'."""
    start = time.time()
    tool_name = "ad_get_domain_admins"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = """
    $m = if ($cred) { Get-ADGroupMember -Identity "Domain Admins" -Server $adServer -Credential $cred } else { Get-ADGroupMember -Identity "Domain Admins" -Server $adServer }
    $m | ForEach-Object {
        [PSCustomObject]@{
            SamAccountName = $_.SamAccountName
            Name = $_.Name
            ObjectClass = $_.objectClass
            DistinguishedName = $_.distinguishedName
        }
    }
    """

    adsi = """
    $root = if ($adUser -and $adPass) { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) } else { [adsi]"LDAP://$adServer/RootDSE" }
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectClass=group)(sAMAccountName=Domain Admins))"
    $res = $searcher.FindOne()
    if ($res) {
        $res.Properties["member"] | ForEach-Object {
            [PSCustomObject]@{ DistinguishedName = [string]$_ }
        }
    } else { throw "Domain Admins group not found." }
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_admin_count_users(correlation_id: Optional[str] = None) -> Dict[str, Any]:
    """77. Identificar contas com atributo adminCount=1 (protegidas por AdminSDHolder)."""
    start = time.time()
    tool_name = "ad_get_admin_count_users"
    allowed, err_resp = auth_engine.authorize_execution(tool_name, {})
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = """
    $users = if ($cred) {
        Get-ADUser -LDAPFilter "(adminCount=1)" -Properties Enabled, LastLogonDate, MemberOf -Server $adServer -Credential $cred
    } else {
        Get-ADUser -LDAPFilter "(adminCount=1)" -Properties Enabled, LastLogonDate, MemberOf -Server $adServer
    }
    $users | ForEach-Object {
        [PSCustomObject]@{
            SamAccountName = $_.SamAccountName
            Name = $_.Name
            Enabled = $_.Enabled
            DistinguishedName = $_.DistinguishedName
            AdminCount = 1
        }
    }
    """

    adsi = """
    $root = if ($adUser -and $adPass) { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) } else { [adsi]"LDAP://$adServer/RootDSE" }
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(adminCount=1))"
    $searcher.FindAll() | ForEach-Object {
        [PSCustomObject]@{
            SamAccountName = [string]$_.Properties["samaccountname"][0]
            Name = [string]$_.Properties["name"][0]
            DistinguishedName = [string]$_.Properties["distinguishedname"][0]
        }
    }
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", {}, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_inactive_users(
    days: int = 90,
    limit: int = 100,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """78. Identificar usuários inativos (sem logon recente) há determinado período."""
    start = time.time()
    tool_name = "ad_get_inactive_users"
    params = {"days": days, "limit": limit}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    rsat = f"""
    $cutOff = (Get-Date).AddDays(-{days})
    $users = if ($cred) {{
        Get-ADUser -Filter 'LastLogonDate -lt $cutOff -and Enabled -eq $true' -Properties LastLogonDate, Mail, Department -ResultSetSize {limit} -Server $adServer -Credential $cred
    }} else {{
        Get-ADUser -Filter 'LastLogonDate -lt $cutOff -and Enabled -eq $true' -Properties LastLogonDate, Mail, Department -ResultSetSize {limit} -Server $adServer
    }}
    $users | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = $_.SamAccountName
            Name = $_.Name
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
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
    $searcher.SizeLimit = {limit}
    $searcher.FindAll() | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = [string]$_.Properties["samaccountname"][0]
            Name = [string]$_.Properties["name"][0]
            DistinguishedName = [string]$_.Properties["distinguishedname"][0]
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_delegated_permissions(
    identity: str,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """79. Auditar permissões delegadas (Access Control Entries) em um objeto ou OU."""
    start = time.time()
    tool_name = "ad_get_delegated_permissions"
    params = {"identity": identity}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    sanitize_powershell_string(identity)
    rsat = """
    $acl = if ($cred) {
        (Get-ACL "AD:$safe_id").Access
    } else {
        (Get-ACL "AD:$safe_id").Access
    }
    $acl | ForEach-Object {
        [PSCustomObject]@{
            IdentityReference = $_.IdentityReference.ToString()
            ActiveDirectoryRights = [string]$_.ActiveDirectoryRights
            AccessControlType = [string]$_.AccessControlType
            IsInherited = $_.IsInherited
            InheritanceType = [string]$_.InheritanceType
        }
    }
    """

    success, data, err = ad_bridge.run_query(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_security_group_changes(
    hours: int = 24,
    limit: int = 50,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """80. Consultar alterações em grupos de segurança nos logs de eventos de segurança (Event IDs 4728, 4729, etc.)."""
    start = time.time()
    tool_name = "ad_get_security_group_changes"
    params = {"hours": hours, "limit": limit}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    script = f"""
    $startTime = (Get-Date).AddHours(-{hours})
    $eventIds = @(4728, 4729, 4732, 4733, 4756, 4757) # Member added/removed from security groups
    $events = Get-WinEvent -FilterHashtable @{{
        LogName = 'Security'
        Id = $eventIds
        StartTime = $startTime
    }} -MaxEvents {limit} -ErrorAction SilentlyContinue

    if ($events) {{
        $events | ForEach-Object {{
            [PSCustomObject]@{{
                TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                EventId = $_.Id
                Message = $_.Message.Substring(0, [Math]::Min(200, $_.Message.Length))
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
