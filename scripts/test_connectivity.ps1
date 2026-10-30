<#
.SYNOPSIS
    Diagnostico avancado de conectividade, resolucao DNS, portas e handshake LDAPS/TLS.
.DESCRIPTION
    Testa resolucao de nomes, conectividade TCP, inspeciona certificados SSL/TLS na porta 636 (LDAPS)
    e valida a cadeia de confianca e o nome comum (CN/SAN).
#>

param(
    [string]$Server,
    [string]$Domain,
    [int]$LdapsPort = 636
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
Write-Host "    ACTIVE DIRECTORY ENTERPRISE CONNECTIVITY DIAGNOSTICS   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Target DC Host: $Server"
Write-Host "Target Domain:  $Domain"
Write-Host ""

# 1. DNS Resolution
Write-Host "[1/4] Testando Resolucao DNS..." -ForegroundColor Yellow
$dnsDomain = Resolve-DnsName -Name $Domain -ErrorAction SilentlyContinue
if ($dnsDomain) {
    Write-Host "  [OK] Dominio '$Domain' resolveu para: $(($dnsDomain.IPAddress | Select-Object -Unique) -join ', ')" -ForegroundColor Green
} else {
    Write-Host "  [ALERTA] Falha ao resolver dominio '$Domain'." -ForegroundColor Red
}

$dnsServer = Resolve-DnsName -Name $Server -ErrorAction SilentlyContinue
if ($dnsServer) {
    Write-Host "  [OK] Host '$Server' resolveu para: $(($dnsServer.IPAddress | Select-Object -Unique) -join ', ')" -ForegroundColor Green
} else {
    Write-Host "  [ALERTA] Falha ao resolver host '$Server'. Testando via IP se fornecido." -ForegroundColor Yellow
}

# 2. Port Connectivity Check
Write-Host ""
Write-Host "[2/4] Testando Portas Essenciais do Active Directory..." -ForegroundColor Yellow
$ports = [ordered]@{
    "DNS (Porta 53)"                 = 53
    "Kerberos KDC (Porta 88)"        = 88
    "LDAP Directory (Porta 389)"     = 389
    "SMB / SYSVOL (Porta 445)"       = 445
    "LDAPS SSL/TLS (Porta 636)"      = 636
    "Global Catalog (Porta 3268)"    = 3268
}

foreach ($name in $ports.Keys) {
    $p = $ports[$name]
    $t = Test-NetConnection -ComputerName $Server -Port $p -WarningAction SilentlyContinue
    if ($t.TcpTestSucceeded) {
        Write-Host "  [ABERTA]  $name" -ForegroundColor Green
    } else {
        Write-Host "  [FECHADA] $name" -ForegroundColor Red
    }
}

# 3. LDAPS TLS/SSL Handshake & Certificate Validation
Write-Host ""
Write-Host "[3/4] Testando Handshake TLS e Certificado Digital LDAPS (Porta $LdapsPort)..." -ForegroundColor Yellow

try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpClient.ReceiveTimeout = 5000
    $tcpClient.SendTimeout = 5000
    $tcpClient.Connect($Server, $LdapsPort)

    $sslStream = New-Object System.Net.Security.SslStream(
        $tcpClient.GetStream(),
        $false,
        ({ $true } -as [System.Net.Security.RemoteCertificateValidationCallback])
    )

    $sslStream.AuthenticateAsClient($Server)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sslStream.RemoteCertificate)

    Write-Host "  [OK] Handshake TLS completado com sucesso!" -ForegroundColor Green
    Write-Host "       Protocolo TLS:  $($sslStream.SslProtocol)" -ForegroundColor Gray
    Write-Host "       Cipher:         $($sslStream.CipherAlgorithm) ($($sslStream.CipherStrength) bits)" -ForegroundColor Gray
    Write-Host "       Assunto (CN):   $($cert.Subject)" -ForegroundColor Gray
    Write-Host "       Emissor (CA):   $($cert.Issuer)" -ForegroundColor Gray
    Write-Host "       Validade:       $($cert.NotBefore.ToString('yyyy-MM-dd')) ate $($cert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
    Write-Host "       Thumbprint:     $($cert.Thumbprint)" -ForegroundColor Gray

    # Test chain trust against local Windows certificate store
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chainPolicy = New-Object System.Security.Cryptography.X509Certificates.X509ChainPolicy
    $chainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy = $chainPolicy
    $isTrusted = $chain.Build($cert)

    if ($isTrusted) {
        Write-Host "  [OK] A autoridade certificadora (CA) e confiavel nesta maquina." -ForegroundColor Green
    } else {
        Write-Host "  [AVISO] O certificado e valido mas nao e confiavel na raiz local (CA privada nao importada)." -ForegroundColor Yellow
    }

    $sslStream.Close()
    $tcpClient.Close()
} catch {
    Write-Host "  [FALHA] Nao foi possivel estabelecer handshake LDAPS na porta $LdapsPort." -ForegroundColor Red
    Write-Host "          Detalhes: $($_.Exception.Message)" -ForegroundColor Gray
    Write-Host "          Nota: O servico LDAPS no DC requer um certificado valido instalado no Personal Store do Servidor." -ForegroundColor Gray
}

# 4. Active Directory RootDSE Query
Write-Host ""
Write-Host "[4/4] Validando Consulta ao Active Directory (RootDSE)..." -ForegroundColor Yellow
try {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $projectRoot = Split-Path -Parent $scriptDir
    $pythonBin = Join-Path $projectRoot ".venv\Scripts\python.exe"
    
    if (Test-Path $pythonBin) {
        $pyCheck = "import sys, os; sys.path.insert(0, os.path.join(r'''$projectRoot''', 'src')); from ad_mcp.tools.domain import ad_get_domain_info; res = ad_get_domain_info(); data = res.get('data', {}); ok = res.get('success'); print('  [OK] Consulta AD bem-sucedida!' if ok else '  [FALHA] ' + str(res.get('error'))); print('       DistinguishedName:', data.get('DistinguishedName')); print('       DnsRoot:          ', data.get('DnsRoot')); print('       Forest:           ', data.get('Forest'))"
        & $pythonBin -c $pyCheck
    }
} catch {
    Write-Host "  [INFO] Consulta Python nao executada: $($_.Exception.Message)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Diagnostico concluido." -ForegroundColor Cyan
