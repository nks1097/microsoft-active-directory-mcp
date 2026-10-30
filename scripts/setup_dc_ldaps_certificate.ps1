<#
.SYNOPSIS
    Configures and installs a dedicated LDAPS Server Authentication certificate on the Domain Controller.
.DESCRIPTION
    Active Directory Domain Services (AD DS) requires a valid X.509 certificate in the Local Computer's
    Personal store (Cert:\LocalMachine\My) with the Server Authentication EKU (1.3.6.1.5.5.7.3.1) in order
    to accept LDAPS connections on TCP port 636.

    This script:
    1. Checks if a valid LDAPS certificate already exists on the DC.
    2. Generates an Active Directory compatible certificate with proper Subject Alternative Names (SANs).
    3. Exports the public certificate (.cer) to C:\ad_mcp_ldaps_ca.cer for distribution to clients.
    4. Provides the command to trust the certificate on client workstations running the MCP server.
.NOTES
    Must be executed with Administrator privileges on the Active Directory Domain Controller.
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "    ACTIVE DIRECTORY LDAPS CERTIFICATE CONFIGURATION      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Detect Domain and Host Identity
$fqdn = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
$domain = (Get-CimInstance Win32_ComputerSystem).Domain
$netbios = $env:COMPUTERNAME

Write-Host "DC Hostname:  $fqdn"
Write-Host "Domain FQDN:  $domain"
Write-Host "NetBIOS Name: $netbios"
Write-Host ""

# 2. Check for existing LDAPS certificate
Write-Host "[1/3] Verificando certificados existentes em Cert:\LocalMachine\My..." -ForegroundColor Yellow
$serverAuthOid = "1.3.6.1.5.5.7.3.1"
$existingCerts = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
    $_.EnhancedKeyUsageList.ObjectId -contains $serverAuthOid -and $_.HasPrivateKey
}

if ($existingCerts) {
    Write-Host "  [INFO] Certificado(s) com suporte a Autenticacao de Servidor (LDAPS) encontrado(s):" -ForegroundColor Green
    foreach ($c in $existingCerts) {
        Write-Host "         - Assunto: $($c.Subject)" -ForegroundColor Gray
        Write-Host "           Emissor: $($c.Issuer)" -ForegroundColor Gray
        Write-Host "           Validade: ate $($c.NotAfter)" -ForegroundColor Gray
        Write-Host "           Thumbprint: $($c.Thumbprint)" -ForegroundColor Gray
    }
} else {
    Write-Host "  [AVISO] Nenhum certificado de Autenticacao de Servidor encontrado no Personal Store." -ForegroundColor Yellow
    Write-Host "          Gerando novo certificado compativel com AD DS..." -ForegroundColor Cyan

    $dnsNames = @($fqdn, $netbios, $domain) | Select-Object -Unique

    $cert = New-SelfSignedCertificate `
        -DnsName $dnsNames `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -KeyLength 2048 `
        -KeyAlgorithm RSA `
        -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature, KeyEncipherment `
        -Type Custom `
        -TextExtension @("2.5.29.37={text}$serverAuthOid") `
        -NotAfter (Get-Date).AddYears(3) `
        -FriendlyName "AD DS LDAPS Service Certificate"

    # Also trust locally on the DC
    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $rootStore.Open("ReadWrite")
    $rootStore.Add($cert)
    $rootStore.Close()

    Write-Host "  [OK] Certificado gerado e instalado com sucesso em Cert:\LocalMachine\My e Root!" -ForegroundColor Green
    Write-Host "       Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
    $existingCerts = @($cert)
}

# 3. Export Public Certificate for Clients
Write-Host ""
Write-Host "[2/3] Exportando certificado publico para clientes MCP..." -ForegroundColor Yellow
$exportPath = "C:\ad_mcp_ldaps_ca.cer"
$targetCert = $existingCerts[0]
Export-Certificate -Cert $targetCert -FilePath $exportPath -Force | Out-Null

Write-Host "  [OK] Certificado publico exportado para: $exportPath" -ForegroundColor Green

# 4. Instructions for MCP Client Workstation
Write-Host ""
Write-Host "[3/3] Instrucoes para a Estacao do Servidor MCP:" -ForegroundColor Yellow
Write-Host "  Para que o cliente Python e o MCP validem a conexao TLS estrita sem erros:" -ForegroundColor White
Write-Host ""
Write-Host "  1. Copie o arquivo '$exportPath' do DC para a estacao de trabalho." -ForegroundColor Cyan
Write-Host "  2. Na estacao de trabalho, execute como Administrador:" -ForegroundColor Cyan
Write-Host "     Import-Certificate -FilePath '$exportPath' -CertStoreLocation Cert:\LocalMachine\Root" -ForegroundColor Green
Write-Host ""
Write-Host "  3. Execute o teste de conectividade para validar o handshake:" -ForegroundColor Cyan
Write-Host "     powershell -ExecutionPolicy Bypass -File scripts/test_connectivity.ps1" -ForegroundColor Green
Write-Host ""
Write-Host "Configuracao de LDAPS no Controlador de Dominio concluida com sucesso!" -ForegroundColor Cyan
