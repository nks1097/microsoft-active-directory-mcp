<#
.SYNOPSIS
    Stores Active Directory credentials securely into Windows Credential Manager.
.DESCRIPTION
    Prompts the administrator for credentials via a secure Windows prompt and stores them
    encrypted with Windows DPAPI into the Windows Credential Vault under 'AD_MCP_CREDENTIAL'.
    This completely eliminates plaintext passwords from .env and mcp_config.json.
#>

param(
    [string]$TargetName = "AD_MCP_CREDENTIAL"
)

Write-Host "=== Active Directory MCP - Secure Credential Vault Setup ===" -ForegroundColor Cyan
Write-Host "Prompting for credentials to store encrypted in Windows Vault..." -ForegroundColor Yellow

$cred = Get-Credential -Title "Active Directory MCP Service Account" -Message "Enter the service account username (e.g. DOMAIN\svc_mcp) and password:"

if (-not $cred) {
    Write-Error "No credentials provided. Operation cancelled."
    exit 1
}

$username = $cred.UserName
$password = $cred.GetNetworkCredential().Password

# Call Python helper to write into Windows Credential Vault
& python -c "
from ad_mcp.auth.credentials import credential_manager
credential_manager.store_in_vault('$TargetName', r'''$username''', r'''$password''')
print('SUCCESS: Credentials encrypted and saved to Windows Credential Vault under target ''$TargetName''.')
"

Write-Host ""
Write-Host "Done! You can now safely REMOVE 'AD_PASSWORD' and 'AD_USERNAME' from your .env and mcp_config.json files." -ForegroundColor Green
Write-Host "The MCP server will retrieve the password securely and encrypted directly from the OS." -ForegroundColor Green
