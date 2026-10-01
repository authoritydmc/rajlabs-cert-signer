<#
.SYNOPSIS
    Installs the ca CA trust chain (Root CA and Intermediate CA)
    onto a Windows machine in the appropriate system trust stores.

.DESCRIPTION
    - Root CA is installed into 'LocalMachine\Root' (Trusted Root Certification Authorities)
    - Intermediate CA is installed into 'LocalMachine\CA' (Intermediate Certification Authorities)
    Once installed, any certificate issued by the Intermediate CA will be 100% trusted
    by Windows, Edge, Chrome, IIS, and PowerShell without chain errors.

.PARAMETER CaChainPath
    Local path or HTTP URL to ca-chain.crt or root-ca.crt
#>

param(
    [string]$CaServerUrl = "http://localhost:8080"
)

# Elevate if not Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Elevating privileges to install system certificates..." -ForegroundColor Yellow
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -CaServerUrl `"$CaServerUrl`"") -Verb RunAs
    exit
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  ca CA Trust Chain Installer (Windows)              " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$tempDir = [System.IO.Path]::GetTempPath()
$rootCertTemp = Join-Path $tempDir "ca-root-ca.crt"
$intCertTemp  = Join-Path $tempDir "ca-int-ca.crt"

# 1. Download certificates
Write-Host "Downloading trust chain from $CaServerUrl..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "$CaServerUrl/certs/root-ca.crt" -OutFile $rootCertTemp -UseBasicParsing
    Invoke-WebRequest -Uri "$CaServerUrl/certs/int-server.crt" -OutFile $intCertTemp -UseBasicParsing
} catch {
    Write-Host "Could not download from URL, looking for local files in repo..." -ForegroundColor DarkYellow
    $localRoot = Resolve-Path "$PSScriptRoot\crl-web\public\certs\root-ca.crt" -ErrorAction SilentlyContinue
    $localInt  = Resolve-Path "$PSScriptRoot\crl-web\public\certs\int-server.crt" -ErrorAction SilentlyContinue
    if ($localRoot -and $localInt) {
        Copy-Item $localRoot $rootCertTemp
        Copy-Item $localInt $intCertTemp
    } else {
        throw "Could not acquire root or intermediate certificates."
    }
}

# 2. Install Root CA into LocalMachine\Root
Write-Host "Installing Root CA into Trusted Root Certification Authorities (LocalMachine\Root)..." -ForegroundColor Cyan
$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::Root, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
$rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$rootCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($rootCertTemp)
$rootStore.Add($rootCert)
$rootStore.Close()
Write-Host "  [OK] Root CA successfully installed." -ForegroundColor Green

# 3. Install Intermediate CA into LocalMachine\CA
Write-Host "Installing Intermediate CA into Intermediate Certification Authorities (LocalMachine\CA)..." -ForegroundColor Cyan
$intStore = New-Object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::CertificateAuthority, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
$intStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$intCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($intCertTemp)
$intStore.Add($intCert)
$intStore.Close()
Write-Host "  [OK] Intermediate CA successfully installed." -ForegroundColor Green

Write-Host "`nAll certificates in the chain are now globally trusted on this machine!" -ForegroundColor Green
Write-Host "Any certificate issued by ca CAs will be automatically recognized." -ForegroundColor Cyan
pause
