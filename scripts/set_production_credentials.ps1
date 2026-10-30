<#
.SYNOPSIS
    Configura credenciais de servico de forma segura no Windows Credential Manager.
.DESCRIPTION
    Invoca o script Python que solicita usuario e senha interativamente (com digitação oculta)
    e armazena os dados criptografados com a DPAPI do Windows sob o alvo 'AD_MCP_CREDENTIAL'.
#>

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$pythonScript = Join-Path $scriptDir "set_production_credentials.py"

# Localiza o executavel Python: prioriza o .venv local do projeto
$pythonBin = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $pythonBin)) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) {
        $pythonBin = $cmd.Source
    }
}

if (-not $pythonBin -or -not (Test-Path $pythonBin)) {
    Write-Error "Ambiente Python nao encontrado. Execute 'setup_env.bat' ou crie a virtualenv com 'python -m venv .venv' antes de configurar as credenciais."
    exit 1
}

if (-not (Test-Path $pythonScript)) {
    Write-Error "Script 'set_production_credentials.py' nao encontrado em: $pythonScript"
    exit 1
}

# Executa o script Python diretamente, preservando tty e getpass sem interferência de quoting do PowerShell
& $pythonBin $pythonScript

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
