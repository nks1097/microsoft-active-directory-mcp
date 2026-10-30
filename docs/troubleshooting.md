# Troubleshooting Guide — Microsoft Active Directory MCP Server

Common issues, diagnostics, and resolution steps when connecting AI agents to Active Directory.

---

## 1. LDAP Authentication & Channel Binding Errors

### Error: `00002028: LdapErr: DSID-0C09035C, comment: The server requires binds to turn on integrity checking if SSL\TLS are not already active on the connection`

**Cause:**
Active Directory Domain Controllers have LDAP Channel Binding and LDAP Signing enforcement turned on (standard Windows Server security baseline). Simple, unencrypted LDAP binds over port 389 without integrity signing are rejected.

**Solutions:**
1. **Enable LDAPS (Recommended)**: Set `AD_PORT=636` and `AD_USE_SSL=true`. Ensure your Domain Controller has an Active Directory Certificate Services (AD CS) certificate installed.
2. **Use Hybrid / PowerShell Backend**: When running on Windows, set `AD_BACKEND=hybrid` (the default). It automatically leverages Windows SSPI / Negotiate with built-in sign-and-seal integrity over port 389.

---

## 2. RSAT Module Not Found (`ActiveDirectory module is absent`)

### Error: `The term 'Get-ADUser' is not recognized as the name of a cmdlet`

**Cause:**
The Windows host does not have the RSAT ActiveDirectory module installed.

**Solution:**
Install RSAT via PowerShell (run as Administrator):
```powershell
Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
```
*Note: Our MCP server has built-in ADSI / .NET fallback routines that allow queries even when RSAT is absent!*

---

## 3. Account Locked Out or Invalid Credentials

### Error: `The supplied credential is invalid (error 8009030C)`

**Cause:**
- Username or password in `.env` is incorrect.
- The service account is locked out or expired.

**Diagnostic Check:**
Run `scripts/test_connectivity.ps1` to test connectivity and check credentials:
```powershell
powershell -File scripts/test_connectivity.ps1 -Server dc01.corp.contoso.com -Domain corp.contoso.com
```

---

## 4. Operation Denied: `MODE_READ_ONLY`

### Message: `Tool 'ad_create_user' performs WRITE actions, but the server is running in READ_ONLY mode.`

**Cause:**
The server is running in default `READ_ONLY` mode to protect production AD.

**Solution:**
In `.env`, configure:
```ini
AD_MCP_MODE=WRITE_APPROVAL
```
Or for full unattended admin workflows:
```ini
AD_MCP_MODE=FULL_ADMIN
```
Restart the MCP server after editing `.env`.

