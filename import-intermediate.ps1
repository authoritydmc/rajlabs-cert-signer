<#
.SYNOPSIS
    Prepares the rajlabs-cert-signer container environment.
    Copies intermediate CA public cert + private key and Root CA public certificate.
    STRICT SECURITY RULE: The Root CA private key (root-ca.key.pem) is NEVER copied or referenced!
#>

param (
    [ValidateSet("int-server", "int-wifi", "int-iot")]
    [string]$TargetIntermediate = "int-server"
)

$ErrorActionPreference = "Stop"

$scriptDir = $PSScriptRoot
$sourceBase = Resolve-Path "$scriptDir\.."

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Rajlabs Docker PKI Signer - Intermediate CA Importer" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Target Intermediate CA : $TargetIntermediate" -ForegroundColor Yellow

$mountedCaDir = "$scriptDir\mounted-ca"
$mountedCerts = "$mountedCaDir\certs"
$mountedKeys  = "$mountedCaDir\private"
$crlPublic    = "$scriptDir\crl-web\public"

# Ensure target directories exist
@($mountedCerts, $mountedKeys, "$crlPublic\crl", "$crlPublic\certs", "$scriptDir\data") | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

# 1. Verify source files exist in main CA directory
$srcIntCert = "$sourceBase\$TargetIntermediate\certs\$TargetIntermediate.cert.pem"
$srcIntKey  = "$sourceBase\$TargetIntermediate\private\$TargetIntermediate.key.pem"
$srcRootCert = "$sourceBase\root-ca\certs\root-ca.cert.pem"
$srcChain    = "$sourceBase\$TargetIntermediate\certs\ca-chain.cert.pem"

if (-not (Test-Path $srcIntCert) -or -not (Test-Path $srcIntKey)) {
    throw "Intermediate CA '$TargetIntermediate' certificate or private key missing! Run generate-cas.ps1 first."
}
if (-not (Test-Path $srcRootCert)) {
    throw "Root CA public certificate missing at $srcRootCert!"
}

# 2. Copy intermediate private key & public certs into mounted-ca
Copy-Item -Path $srcIntCert -Destination "$mountedCerts\$TargetIntermediate.cert.pem" -Force
Copy-Item -Path $srcIntKey  -Destination "$mountedKeys\$TargetIntermediate.key.pem" -Force
Copy-Item -Path $srcRootCert -Destination "$mountedCerts\root-ca.cert.pem" -Force

Write-Host "[OK] Intermediate CA cert & private key mounted." -ForegroundColor Green
Write-Host "[OK] Root CA PUBLIC certificate mounted (Public trust anchor)." -ForegroundColor Green
Write-Host "[VERIFIED] Root CA private key was NOT touched or imported." -ForegroundColor Magenta

# 3. Publish public certificates and chain to CRL / Public Web server
Copy-Item -Path $srcRootCert -Destination "$crlPublic\certs\root-ca.crt" -Force
Copy-Item -Path $srcIntCert  -Destination "$crlPublic\certs\$TargetIntermediate.crt" -Force
if (Test-Path $srcChain) {
    Copy-Item -Path $srcChain -Destination "$crlPublic\certs\ca-chain.crt" -Force
}

# 4. Copy Root CRL if available
$srcRootCrl = "$sourceBase\root-ca\crl\root-ca.crl.pem"
if (Test-Path $srcRootCrl) {
    Copy-Item -Path $srcRootCrl -Destination "$crlPublic\crl\root-ca.crl" -Force
    Write-Host "[OK] Root CA CRL published to web distribution folder." -ForegroundColor Green
}

Write-Host "`nEnvironment preparation completed successfully!" -ForegroundColor Green
Write-Host "Next steps:"
Write-Host "  1. Start services:  docker compose up -d"
Write-Host "  2. ACME Directory:  http://localhost:9000/acme/directory"
Write-Host "  3. CRL Endpoint:    http://localhost:8080/crl/"
