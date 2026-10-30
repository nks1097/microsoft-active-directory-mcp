<#
.SYNOPSIS
    Instala e valida os modulos RSAT (ActiveDirectory, GroupPolicy, DnsServer) no Windows 10/11 ou Windows Server.
.DESCRIPTION
    Verifica privilegios elevados, executa a instalacao via DISM / ServerManager e
    valida a importacao de cada modulo para garantir prontidao operacional.
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "     INSTALACAO E VALIDACAO DAS FERRAMENTAS RSAT AD       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Este script exige privilegios de Administrador. Abra o PowerShell como Administrador e execute novamente."
    exit 1
}

$os = Get-CimInstance Win32_OperatingSystem
Write-Host "Sistema Operacional detectado: $($os.Caption) (Build $($os.BuildNumber))" -ForegroundColor Gray

if ($os.ProductType -eq 1) {
    # Windows Client (Windows 10 / 11)
    Write-Host ""
    Write-Host "Instalando Recursos RSAT via Windows Capabilities..." -ForegroundColor Yellow

    $capabilities = @(
        "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0",
        "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0",
        "Rsat.Dns.Tools~~~~0.0.1.0"
    )

    foreach ($cap in $capabilities) {
        Write-Host "  Instalando $cap..." -NoNewline
        $result = Add-WindowsCapability -Online -Name $cap -ErrorAction SilentlyContinue
        if ($result.RestartNeeded) {
            Write-Host " [OK - Reinicializacao pendente]" -ForegroundColor Yellow
        } elseif ($result.State -eq "Installed") {
            Write-Host " [INSTALADO]" -ForegroundColor Green
        } else {
            Write-Host " [STATUS: $($result.State)]" -ForegroundColor Cyan
        }
    }
} else {
    # Windows Server
    Write-Host ""
    Write-Host "Instalando Recursos RSAT via ServerManager..." -ForegroundColor Yellow

    $features = @("RSAT-AD-PowerShell", "GPMC", "RSAT-DNS-Server")
    foreach ($feat in $features) {
        Write-Host "  Instalando $feat..." -NoNewline
        $res = Install-WindowsFeature -Name $feat -IncludeAllSubFeature -ErrorAction SilentlyContinue
        if ($res.Success) {
            Write-Host " [INSTALADO]" -ForegroundColor Green
        } else {
            Write-Host " [FALHA: $($res.ExitCode)]" -ForegroundColor Red
        }
    }
}

# Verificacao rigorosa dos modulos PowerShell
Write-Host ""
Write-Host "Validando disponibilidade dos modulos PowerShell..." -ForegroundColor Yellow

$modulesToTest = @("ActiveDirectory", "GroupPolicy", "DnsServer")
$allValid = $true

foreach ($modName in $modulesToTest) {
    $mod = Get-Module -ListAvailable -Name $modName
    if ($mod) {
        try {
            Import-Module $modName -ErrorAction Stop
            Write-Host "  [OK] Modulo '$modName' versao $($mod.Version) importado com sucesso." -ForegroundColor Green
        } catch {
            Write-Host "  [AVISO] Modulo '$modName' encontrado mas falhou ao importar: $($_.Exception.Message)" -ForegroundColor Yellow
            $allValid = $false
        }
    } else {
        Write-Host "  [FALHA] Modulo '$modName' nao foi encontrado apos a instalacao." -ForegroundColor Red
        $allValid = $false
    }
}

Write-Host ""
if ($allValid) {
    Write-Host "Todas as ferramentas administrativas RSAT estao prontas para uso pelo servidor MCP!" -ForegroundColor Green
} else {
    Write-Host "Alguns modulos podem necessitar que a maquina seja reiniciada para concluir o registro." -ForegroundColor Yellow
}
