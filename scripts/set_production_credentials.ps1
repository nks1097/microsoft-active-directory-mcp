<#
.SYNOPSIS
    Stores Active Directory credentials securely into Windows Credential Manager.
.DESCRIPTION
    Prompts the administrator directly in the console (with password masking) and stores them
    encrypted with Windows DPAPI into the Windows Credential Vault under 'AD_MCP_CREDENTIAL'.
    This completely eliminates plaintext passwords from .env and mcp_config.json.
#>

param(
    [string]$TargetName = "AD_MCP_CREDENTIAL",
    [string]$Username,
    [string]$Password
)

Write-Host "=== Active Directory MCP - Secure Credential Vault Setup ===" -ForegroundColor Cyan

# 1. Prompt for username if not provided via parameter
if (-not $Username) {
    $Username = Read-Host "Digite o usuario da conta de servico (ex: nks1097\Administrator)"
}

# 2. Prompt for password with console masking (asterisks / hidden) if not provided
if (-not $Password) {
    $secPass = Read-Host "Digite a senha (a digitacao ficara oculta)" -AsSecureString
    $credTemp = New-Object System.Management.Automation.PSCredential($Username, $secPass)
    $Password = $credTemp.GetNetworkCredential().Password
}

if ([string]::IsNullOrWhiteSpace($Username) -or [string]::IsNullOrWhiteSpace($Password)) {
    Write-Error "Usuario ou senha em branco. Operacao cancelada."
    exit 1
}

# 3. Locate project virtual environment Python or fallback to PATH
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonBin = if (Test-Path "$scriptDir\..\.venv\Scripts\python.exe") { 
    "$scriptDir\..\.venv\Scripts\python.exe" 
} else { 
    "python" 
}

# 4. Pass credentials safely via ephemeral environment variables
$env:_TEMP_VAULT_USER = $Username
$env:_TEMP_VAULT_PASS = $Password

& $pythonBin -c "
import os
from ad_mcp.auth.credentials import credential_manager
u = os.environ.pop('_TEMP_VAULT_USER', '')
p = os.environ.pop('_TEMP_VAULT_PASS', '')
credential_manager.store_in_vault('$TargetName', u, p)
print(f'SUCCESS: Credenciais para ''{u}'' salvas com criptografia DPAPI no cofre sob ''$TargetName''.')
"

# Clean up memory
$Password = $null
$env:_TEMP_VAULT_USER = $null
$env:_TEMP_VAULT_PASS = $null

Write-Host ""
Write-Host "Concluido com sucesso!" -ForegroundColor Green
Write-Host "As credenciais foram criptografadas pelo Windows e estao protegidas no Cofre de Credenciais." -ForegroundColor Green
Write-Host "Voce NAO precisa colocar senhas no .env ou no mcp_config.json." -ForegroundColor Green
