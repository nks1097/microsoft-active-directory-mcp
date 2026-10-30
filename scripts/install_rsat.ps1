<#
.SYNOPSIS
    Installs the ActiveDirectory and RSAT management tools on Windows 10/11 or Windows Server.
.DESCRIPTION
    Checks Windows Edition and installs RSAT ActiveDirectory tools via DISM / Windows Capabilities.
#>

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be executed as Administrator. Please run PowerShell as Administrator."
    exit 1
}

Write-Host "Installing Active Directory Domain Services Tools (RSAT)..." -ForegroundColor Cyan

if ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 1) {
    # Windows Client (10 / 11)
    Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    Add-WindowsCapability -Online -Name "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
    Add-WindowsCapability -Online -Name "Rsat.Dns.Tools~~~~0.0.1.0"
} else {
    # Windows Server
    Install-WindowsFeature -Name RSAT-AD-PowerShell, GPMC, RSAT-DNS-Server -IncludeAllSubFeature
}

Write-Host "RSAT installation completed! Verifying module availability..." -ForegroundColor Green
Get-Module -ListAvailable ActiveDirectory | Select-Object Name, Version

