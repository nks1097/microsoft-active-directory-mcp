$ErrorActionPreference = "Stop"

Write-Host "=== Active Directory MCP - Credential Setup ===" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$pythonBin = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $pythonBin)) {
    throw "Python da virtualenv nao encontrado: $pythonBin. Execute primeiro o setup_env.bat ou uv venv."
}

# Codigo fixo: nenhuma entrada do usuario e interpolada nele (evita injecao e exposicao)
$pythonCode = @'
import getpass
import sys

try:
    from ad_mcp.auth.credentials import credential_manager
except ImportError as e:
    print(f"ERRO: Nao foi possivel importar ad_mcp: {e}", file=sys.stderr)
    sys.exit(1)

target = "AD_MCP_CREDENTIAL"

print("Digite as credenciais da conta de servico do Active Directory.")
username = input("Usuario (ex: nks1097\\Administrator ou svc_ad@nks1097.local): ").strip()

if not username:
    print("ERRO: O nome de usuario nao pode ser vazio.", file=sys.stderr)
    sys.exit(1)

password = getpass.getpass("Senha da conta (a digitacao ficara oculta): ")

if not password:
    print("ERRO: A senha nao pode ser vazia.", file=sys.stderr)
    sys.exit(1)

try:
    credential_manager.store_in_vault(target, username, password)
    print(f"Credencial para '{username}' armazenada com sucesso no Windows Credential Manager.")
    print("Nenhuma senha sera exibida ou gravada em texto puro em arquivos.")
except Exception as ex:
    print(f"ERRO ao gravar no Cofre do Windows: {ex}", file=sys.stderr)
    sys.exit(2)
'@

Push-Location $projectRoot

try {
    & $pythonBin -c $pythonCode

    if ($LASTEXITCODE -ne 0) {
        throw "Falha ao armazenar a credencial. Codigo de saida do Python: $LASTEXITCODE"
    }

    Write-Host ""
    Write-Host "Armazenamento concluido com sucesso." -ForegroundColor Green
    Write-Host "Voce pode remover qualquer referencia a AD_PASSWORD do seu .env e mcp_config.json." -ForegroundColor Green
}
finally {
    Pop-Location
}
