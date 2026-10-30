<#
.SYNOPSIS
    Diagnoses network, DNS, and LDAP connectivity to target Active Directory Domain Controllers.
#>

param(
    [string]$Server = "192.168.0.201",
    [string]$Domain = "nks1097.local"
)

Write-Host "=== Active Directory Diagnostic Probes ===" -ForegroundColor Cyan
Write-Host "Target DC Server: $Server"
Write-Host "Target Domain:    $Domain"
Write-Host ""

Write-Host "1. Testing DNS Resolution..." -ForegroundColor Yellow
$dns = Resolve-DnsName -Name $Domain -ErrorAction SilentlyContinue
if ($dns) {
    Write-Host "   SUCCESS: Domain resolved to $($dns.IPAddress -join ', ')" -ForegroundColor Green
} else {
    Write-Host "   WARNING: Could not resolve '$Domain' via default DNS." -ForegroundColor Red
}

Write-Host "2. Testing Essential Ports on $Server..." -ForegroundColor Yellow
$ports = @{
    "LDAP (389)" = 389
    "LDAPS (636)" = 636
    "Kerberos (88)" = 88
    "SMB (445)" = 445
    "DNS (53)" = 53
    "Global Catalog (3268)" = 3268
}

foreach ($k in $ports.Keys) {
    $p = $ports[$k]
    $t = Test-NetConnection -ComputerName $Server -Port $p -WarningAction SilentlyContinue
    if ($t.TcpTestSucceeded) {
        Write-Host "   [OPEN]   $k" -ForegroundColor Green
    } else {
        Write-Host "   [CLOSED] $k" -ForegroundColor Red
    }
}
Write-Host ""
Write-Host "Diagnostic complete." -ForegroundColor Cyan

