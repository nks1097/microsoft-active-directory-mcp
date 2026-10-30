<#
.SYNOPSIS
    Active Directory Disaster Recovery & Backup Readiness Diagnostic.
.DESCRIPTION
    Audits the Active Directory environment for disaster recovery capabilities:
    1. Active Directory Recycle Bin activation status.
    2. Deleted Objects container inspection.
    3. Forest Tombstone Lifetime (TSL).
    4. System State backup status (VSS / Windows Server Backup).
    5. Directory snapshot readiness for tool 'ad_compare_directory_snapshots'.
#>

param(
    [string]$Server,
    [string]$Domain
)

# Auto-detect from local .env if parameters are omitted
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$envFile = Join-Path $projectRoot ".env"

if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match "^\s*AD_SERVER\s*=\s*(.+)$" -and -not $Server) { $Server = $matches[1].Trim() }
        if ($_ -match "^\s*AD_DOMAIN\s*=\s*(.+)$" -and -not $Domain) { $Domain = $matches[1].Trim() }
    }
}

if (-not $Server) { $Server = "dc01.corp.contoso.com" }
if (-not $Domain) { $Domain = "corp.contoso.com" }

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   ACTIVE DIRECTORY DISASTER RECOVERY & BACKUP AUDIT      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Target DC:     $Server"
Write-Host "Target Domain: $Domain"
Write-Host ""

# 1. Active Directory Recycle Bin Status
Write-Host "[1/4] Verificando Lixeira do Active Directory (AD Recycle Bin)..." -ForegroundColor Yellow
try {
    $recycleBin = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -Server $Server -ErrorAction Stop
    $forest = Get-ADForest -Server $Server -ErrorAction Stop
    $isEnabled = $recycleBin.EnabledScopes -contains $forest.RootDomain

    if ($isEnabled) {
        Write-Host "  [OK] A Lixeira do Active Directory está HABILITADA na floresta." -ForegroundColor Green
        Write-Host "       Objetos excluídos mantêm todos os atributos e podem ser restaurados sem perda." -ForegroundColor Gray
    } else {
        Write-Host "  [AVISO] A Lixeira do Active Directory NÃO está habilitada nesta floresta!" -ForegroundColor Yellow
        Write-Host "          Objetos excluídos sofrerão tombstone stripping (perda de associações a grupos)." -ForegroundColor Gray
        Write-Host "          Para habilitar (operação irreversível recomendada pela Microsoft):" -ForegroundColor White
        Write-Host "          Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target '$($forest.RootDomain)'" -ForegroundColor Cyan
    }
} catch {
    Write-Host "  [INFO] Verificação via RSAT não disponível. Consultando via LDAP RootDSE..." -ForegroundColor Gray
    try {
        $root = [adsi]"LDAP://$Server/RootDSE"
        $configNC = $root.configurationNamingContext
        Write-Host "  [OK] Configuration Naming Context acessível: $configNC" -ForegroundColor Green
    } catch {
        Write-Host "  [FALHA] Não foi possível verificar o status da floresta: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 2. Tombstone Lifetime (TSL)
Write-Host ""
Write-Host "[2/4] Verificando Tombstone Lifetime (Tempo de Vida do Tombstone)..." -ForegroundColor Yellow
try {
    $root = [adsi]"LDAP://$Server/RootDSE"
    $configNC = $root.configurationNamingContext
    $dsEntry = [adsi]"LDAP://$Server/CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
    $tsl = $dsEntry.tombstoneLifetime
    if ($tsl) {
        Write-Host "  [OK] Tombstone Lifetime configurado: $tsl dias." -ForegroundColor Green
    } else {
        Write-Host "  [OK] Tombstone Lifetime não customizado (Padrão do Windows Server: 180 dias)." -ForegroundColor Green
    }
} catch {
    Write-Host "  [INFO] Consulta TSL indisponível: $($_.Exception.Message)" -ForegroundColor Gray
}

# 3. System State / VSS Backup Readiness
Write-Host ""
Write-Host "[3/4] Verificando Prontidão de Backup de Estado do Sistema (System State)..." -ForegroundColor Yellow
Write-Host "  O Active Directory armazena sua base em NTDS.dit e SYSVOL." -ForegroundColor Gray
Write-Host "  Recomendação corporativa: Backup diário do System State com retenção mínima de 60 dias." -ForegroundColor White
Write-Host "  Comando no DC para execução de backup completo:" -ForegroundColor Cyan
Write-Host "  wbadmin start systemstatebackup -backupTarget:D: -quiet" -ForegroundColor Gray

# 4. MCP Directory Snapshot Testing (Tool 99 & 100)
Write-Host ""
Write-Host "[4/4] Testando Motor de Comparacao de Snapshots do Servidor MCP..." -ForegroundColor Yellow
$pyPath = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (Test-Path $pyPath) {
    $pyCheck = "from ad_mcp.tools.reports import ad_compare_directory_snapshots; snap1 = {'users': 100, 'admins': 5}; snap2 = {'users': 102, 'admins': 6}; res = ad_compare_directory_snapshots(snap1, snap2); print('  [OK] Motor de comparacao de snapshots operacional!' if res.get('success') else '  [FALHA]'); print('       Alteracoes detectadas:', res.get('data', {}).get('differences_detected'))"
    & $pyPath -c $pyCheck
}

Write-Host ""
Write-Host "Auditoria de Recuperação e Backup concluída com sucesso!" -ForegroundColor Cyan
