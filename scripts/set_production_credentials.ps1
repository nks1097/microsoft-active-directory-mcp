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

# In Windows PowerShell 5.1, Get-Credential supports -Message and -UserName (no -Title)
$cred = Get-Credential -Message "Active Directory MCP: Digite as credenciais da conta de servico (ex: DOMAIN\usuario)"

if (-not $cred) {
    Write-Error "No credentials provided. Operation cancelled."
    exit 1
}

$username = $cred.UserName
$password = $cred.GetNetworkCredential().Password

# Locate project virtual environment Python or fallback to PATH
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonBin = if (Test-Path "$scriptDir\..\.venv\Scripts\python.exe") { 
    "$scriptDir\..\.venv\Scripts\python.exe" 
} else { 
    "python" 
}

# Pass credentials safely via ephemeral environment variables (protects against special characters in passwords)
$env:_TEMP_VAULT_USER = $username
$env:_TEMP_VAULT_PASS = $password

& $pythonBin -c "
import os
from ad_mcp.auth.credentials import credential_manager
u = os.environ.pop('_TEMP_VAULT_USER', '')
p = os.environ.pop('_TEMP_VAULT_PASS', '')
credential_manager.store_in_vault('$TargetName', u, p)
print(f'SUCCESS: Credentials encrypted and saved to Windows Credential Vault under target ''$TargetName''.')
"

Write-Host ""
Write-Host "Done! You can now safely REMOVE 'AD_PASSWORD' and 'AD_USERNAME' from your .env and mcp_config.json files." -ForegroundColor Green
Write-Host "The MCP server will retrieve the password securely and encrypted directly from the OS." -ForegroundColor Green
