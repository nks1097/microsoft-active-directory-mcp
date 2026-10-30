"""
Tools Category 2: Users (Tools 11 to 20).
"""

import time
from typing import Any, Dict, List, Optional

from ad_mcp.audit.logger import audit_logger
from ad_mcp.authorization.guardrails import sanitize_ldap_filter, sanitize_powershell_string
from ad_mcp.authorization.rbac import auth_engine
from ad_mcp.integrations.bridge import ad_bridge
from ad_mcp.models.response import ToolResponse


def ad_list_users(
    limit: int = 100,
    search_base: Optional[str] = None,
    enabled_only: Optional[bool] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """11. Listar usuários com filtros configuráveis."""
    start = time.time()
    tool_name = "ad_list_users"
    params = {"limit": limit, "search_base": search_base, "enabled_only": enabled_only}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    filter_clause = (
        "Enabled -eq $true" if enabled_only is True else ("Enabled -eq $false" if enabled_only is False else "*")
    )
    base_clause = f"-SearchBase '{sanitize_powershell_string(search_base)}'" if search_base else ""

    rsat = f"""
    $users = if ($cred) {{ Get-ADUser -Filter '{filter_clause}' {base_clause} -ResultSetSize {limit} -Properties DisplayName, Mail, Title, Department, Enabled, LockedOut, LastLogonDate -Server $adServer -Credential $cred }} else {{ Get-ADUser -Filter '{filter_clause}' {base_clause} -ResultSetSize {limit} -Properties DisplayName, Mail, Title, Department, Enabled, LockedOut, LastLogonDate -Server $adServer }}
    $users | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = $_.SamAccountName
            UserPrincipalName = $_.UserPrincipalName
            DisplayName = $_.DisplayName
            DistinguishedName = $_.DistinguishedName
            Enabled = $_.Enabled
            Mail = $_.Mail
            Title = $_.Title
            Department = $_.Department
            LockedOut = $_.LockedOut
            LastLogonDate = if ($_.LastLogonDate) {{ $_.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ $null }}
        }}
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = if ('{sanitize_powershell_string(search_base)}') {{ '{sanitize_powershell_string(search_base)}' }} else {{ $root.defaultNamingContext }}
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
    $searcher.SizeLimit = {limit}
    $searcher.PropertiesToLoad.AddRange(@("samaccountname", "userprincipalname", "displayname", "mail", "title", "department", "useraccountcontrol"))
    $searcher.FindAll() | ForEach-Object {{
        $uac = [int]$_.Properties["useraccountcontrol"][0]
        $enabled = ($uac -band 2) -eq 0
        [PSCustomObject]@{{
            SamAccountName = [string]$_.Properties["samaccountname"][0]
            UserPrincipalName = [string]$_.Properties["userprincipalname"][0]
            DisplayName = [string]$_.Properties["displayname"][0]
            DistinguishedName = [string]$_.Path.Replace("LDAP://$adServer/", "")
            Enabled = $enabled
            Mail = [string]$_.Properties["mail"][0]
            Title = [string]$_.Properties["title"][0]
            Department = [string]$_.Properties["department"][0]
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_get_user(
    identity: str,
    properties: Optional[List[str]] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """12. Consultar detalhes completos de um usuário."""
    start = time.time()
    tool_name = "ad_get_user"
    params = {"identity": identity, "properties": properties}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rsat = f"""
    $u = if ($cred) {{ Get-ADUser -Identity '{safe_id}' -Properties * -Server $adServer -Credential $cred }} else {{ Get-ADUser -Identity '{safe_id}' -Properties * -Server $adServer }}
    [PSCustomObject]@{{
        SamAccountName = $u.SamAccountName
        UserPrincipalName = $u.UserPrincipalName
        Name = $u.Name
        DisplayName = $u.DisplayName
        DistinguishedName = $u.DistinguishedName
        Enabled = $u.Enabled
        LockedOut = $u.LockedOut
        PasswordNeverExpires = $u.PasswordNeverExpires
        PasswordExpired = $u.PasswordExpired
        PasswordLastSet = if ($u.PasswordLastSet) {{ $u.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ $null }}
        LastLogonDate = if ($u.LastLogonDate) {{ $u.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ $null }}
        WhenCreated = if ($u.WhenCreated) {{ $u.WhenCreated.ToString("yyyy-MM-dd HH:mm:ss") }} else {{ $null }}
        Mail = $u.Mail
        Title = $u.Title
        Department = $u.Department
        Company = $u.Company
        Manager = $u.Manager
        MemberOf = $u.MemberOf
        SID = [string]$u.SID.Value
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={safe_id})(userPrincipalName={safe_id})))"
    $res = $searcher.FindOne()
    if ($res) {{
        $uac = [int]$res.Properties["useraccountcontrol"][0]
        [PSCustomObject]@{{
            SamAccountName = [string]$res.Properties["samaccountname"][0]
            UserPrincipalName = [string]$res.Properties["userprincipalname"][0]
            DisplayName = [string]$res.Properties["displayname"][0]
            DistinguishedName = [string]$res.Properties["distinguishedname"][0]
            Enabled = ($uac -band 2) -eq 0
            PasswordNeverExpires = ($uac -band 65536) -ne 0
            Mail = [string]$res.Properties["mail"][0]
            Title = [string]$res.Properties["title"][0]
            Department = [string]$res.Properties["department"][0]
            MemberOf = $res.Properties["memberof"]
        }}
    }} else {{ throw "User '{safe_id}' not found." }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_search_users(
    query: str,
    limit: int = 50,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """13. Pesquisar usuários por nome, login, e-mail ou atributo."""
    start = time.time()
    tool_name = "ad_search_users"
    params = {"query": query, "limit": limit}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_q = sanitize_powershell_string(query)
    safe_ldap_q = sanitize_ldap_filter(query)

    rsat = f"""
    $users = if ($cred) {{ Get-ADUser -Filter 'Name -like "*{safe_q}*" -or SamAccountName -like "*{safe_q}*" -or UserPrincipalName -like "*{safe_q}*" -or Mail -like "*{safe_q}*"' -ResultSetSize {limit} -Properties DisplayName, Mail, Title, Department, Enabled -Server $adServer -Credential $cred }} else {{ Get-ADUser -Filter 'Name -like "*{safe_q}*" -or SamAccountName -like "*{safe_q}*" -or UserPrincipalName -like "*{safe_q}*" -or Mail -like "*{safe_q}*"' -ResultSetSize {limit} -Properties DisplayName, Mail, Title, Department, Enabled -Server $adServer }}
    $users | ForEach-Object {{
        [PSCustomObject]@{{
            SamAccountName = $_.SamAccountName
            UserPrincipalName = $_.UserPrincipalName
            DisplayName = $_.DisplayName
            DistinguishedName = $_.DistinguishedName
            Enabled = $_.Enabled
            Mail = $_.Mail
            Department = $_.Department
        }}
    }}
    """

    adsi = f"""
    $root = if ($adUser -and $adPass) {{ New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/RootDSE", $adUser, $adPass) }} else {{ [adsi]"LDAP://$adServer/RootDSE" }}
    $defNC = $root.defaultNamingContext
    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$adServer/$defNC", $adUser, $adPass)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(|(name=*{safe_ldap_q}*)(sAMAccountName=*{safe_ldap_q}*)(mail=*{safe_ldap_q}*)))"
    $searcher.SizeLimit = {limit}
    $searcher.PropertiesToLoad.AddRange(@("samaccountname", "userprincipalname", "displayname", "mail", "department", "useraccountcontrol"))
    $searcher.FindAll() | ForEach-Object {{
        $uac = [int]$_.Properties["useraccountcontrol"][0]
        [PSCustomObject]@{{
            SamAccountName = [string]$_.Properties["samaccountname"][0]
            UserPrincipalName = [string]$_.Properties["userprincipalname"][0]
            DisplayName = [string]$_.Properties["displayname"][0]
            DistinguishedName = [string]$_.Properties["distinguishedname"][0]
            Enabled = ($uac -band 2) -eq 0
            Mail = [string]$_.Properties["mail"][0]
            Department = [string]$_.Properties["department"][0]
        }}
    }}
    """

    success, data, err = ad_bridge.run_query(rsat, adsi)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_create_user(
    sam_account_name: str,
    path: str,
    name: Optional[str] = None,
    given_name: Optional[str] = None,
    surname: Optional[str] = None,
    display_name: Optional[str] = None,
    user_principal_name: Optional[str] = None,
    mail: Optional[str] = None,
    password: Optional[str] = None,
    enabled: bool = True,
    password_never_expires: bool = False,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """14. Criar novo usuário no Active Directory."""
    start = time.time()
    tool_name = "ad_create_user"
    params = {
        "sam_account_name": sam_account_name,
        "path": path,
        "name": name or sam_account_name,
        "mail": mail,
        "enabled": enabled,
        "confirmation_token": confirmation_token,
        "dry_run": dry_run,
    }
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=sam_account_name)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_sam = sanitize_powershell_string(sam_account_name)
    safe_name = sanitize_powershell_string(name or sam_account_name)
    safe_path = sanitize_powershell_string(path)
    safe_upn = sanitize_powershell_string(user_principal_name or f"{sam_account_name}@{safe_path}")
    safe_mail = sanitize_powershell_string(mail) if mail else ""
    safe_pass = sanitize_powershell_string(password) if password else "Pass@Temp1234!"

    rsat = f"""
    $sec = ConvertTo-SecureString '{safe_pass}' -AsPlainText -Force
    $params = @{{
        SamAccountName = '{safe_sam}'
        Name = '{safe_name}'
        Path = '{safe_path}'
        AccountPassword = $sec
        Enabled = ${str(enabled).lower()}
        PasswordNeverExpires = ${str(password_never_expires).lower()}
    }}
    if ('{safe_upn}') {{ $params['UserPrincipalName'] = '{safe_upn}' }}
    if ('{safe_mail}') {{ $params['EmailAddress'] = '{safe_mail}' }}
    if ($cred) {{ $params['Server'] = $adServer; $params['Credential'] = $cred }} else {{ $params['Server'] = $adServer }}

    New-ADUser @params
    [PSCustomObject]@{{
        Status = "CREATED"
        SamAccountName = '{safe_sam}'
        DistinguishedName = "CN={safe_name},{safe_path}"
        Enabled = ${str(enabled).lower()}
    }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_update_user(
    identity: str,
    display_name: Optional[str] = None,
    mail: Optional[str] = None,
    title: Optional[str] = None,
    department: Optional[str] = None,
    company: Optional[str] = None,
    manager: Optional[str] = None,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """15. Atualizar atributos de um usuário existente."""
    start = time.time()
    tool_name = "ad_update_user"
    params = {
        "identity": identity,
        "display_name": display_name,
        "mail": mail,
        "title": title,
        "department": department,
        "confirmation_token": confirmation_token,
        "dry_run": dry_run,
    }
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    updates = []
    if display_name is not None:
        updates.append(f"-DisplayName '{sanitize_powershell_string(display_name)}'")
    if mail is not None:
        updates.append(f"-EmailAddress '{sanitize_powershell_string(mail)}'")
    if title is not None:
        updates.append(f"-Title '{sanitize_powershell_string(title)}'")
    if department is not None:
        updates.append(f"-Department '{sanitize_powershell_string(department)}'")
    if company is not None:
        updates.append(f"-Company '{sanitize_powershell_string(company)}'")
    if manager is not None:
        updates.append(f"-Manager '{sanitize_powershell_string(manager)}'")

    args_str = " ".join(updates)
    rsat = f"""
    $cmd = if ($cred) {{ Set-ADUser -Identity '{safe_id}' {args_str} -Server $adServer -Credential $cred }} else {{ Set-ADUser -Identity '{safe_id}' {args_str} -Server $adServer }}
    [PSCustomObject]@{{
        Status = "UPDATED"
        Identity = '{safe_id}'
        AttributesUpdated = @({", ".join(f"'{k}'" for k, v in params.items() if v is not None and k not in ("identity", "confirmation_token", "dry_run"))})
    }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_disable_user(
    identity: str,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """16. Desabilitar conta de usuário."""
    start = time.time()
    tool_name = "ad_disable_user"
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


def ad_enable_user(
    identity: str,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """17. Habilitar conta de usuário."""
    start = time.time()
    tool_name = "ad_enable_user"
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


def ad_delete_user(
    identity: str,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """18. Excluir conta de usuário (operação destrutiva com confirmação obrigatória)."""
    start = time.time()
    tool_name = "ad_delete_user"
    params = {"identity": identity, "confirmation_token": confirmation_token, "dry_run": dry_run}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rsat = f"""
    if ($cred) {{ Remove-ADUser -Identity '{safe_id}' -Confirm:$false -Server $adServer -Credential $cred }} else {{ Remove-ADUser -Identity '{safe_id}' -Confirm:$false -Server $adServer }}
    [PSCustomObject]@{{ Status = "DELETED"; Identity = '{safe_id}' }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_unlock_user(
    identity: str,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """19. Desbloquear conta de usuário travada por tentativas de senha."""
    start = time.time()
    tool_name = "ad_unlock_user"
    params = {"identity": identity, "confirmation_token": confirmation_token, "dry_run": dry_run}
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    rsat = f"""
    if ($cred) {{ Unlock-ADAccount -Identity '{safe_id}' -Server $adServer -Credential $cred }} else {{ Unlock-ADAccount -Identity '{safe_id}' -Server $adServer }}
    [PSCustomObject]@{{ Status = "UNLOCKED"; Identity = '{safe_id}' }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()


def ad_reset_user_password(
    identity: str,
    new_password: str,
    must_change_at_next_logon: bool = True,
    confirmation_token: Optional[str] = None,
    dry_run: bool = False,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """20. Redefinir senha de usuário com confirmação e segurança."""
    start = time.time()
    tool_name = "ad_reset_user_password"
    # Never log password
    params = {
        "identity": identity,
        "must_change_at_next_logon": must_change_at_next_logon,
        "confirmation_token": confirmation_token,
        "dry_run": dry_run,
    }
    allowed, err_resp = auth_engine.authorize_execution(tool_name, params, target_object=identity)
    if not allowed and err_resp:
        return err_resp.to_mcp_content()

    safe_id = sanitize_powershell_string(identity)
    safe_pass = sanitize_powershell_string(new_password)
    change_flag = "$true" if must_change_at_next_logon else "$false"

    rsat = f"""
    $sec = ConvertTo-SecureString '{safe_pass}' -AsPlainText -Force
    if ($cred) {{
        Set-ADAccountPassword -Identity '{safe_id}' -NewPassword $sec -Reset -Server $adServer -Credential $cred
        Set-ADUser -Identity '{safe_id}' -ChangePasswordAtLogon {change_flag} -Server $adServer -Credential $cred
    }} else {{
        Set-ADAccountPassword -Identity '{safe_id}' -NewPassword $sec -Reset -Server $adServer
        Set-ADUser -Identity '{safe_id}' -ChangePasswordAtLogon {change_flag} -Server $adServer
    }}
    [PSCustomObject]@{{
        Status = "PASSWORD_RESET"
        Identity = '{safe_id}'
        MustChangeAtNextLogon = {change_flag}
    }}
    """

    success, data, err = ad_bridge.run_mutation(rsat)
    duration = (time.time() - start) * 1000
    audit_logger.log_event(tool_name, correlation_id or "", params, success, duration, err)
    return ToolResponse(success=success, data=data, error=err, execution_time_ms=duration).to_mcp_content()
