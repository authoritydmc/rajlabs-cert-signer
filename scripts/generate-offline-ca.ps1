<#
.SYNOPSIS
    Interactive Offline Root CA and Intermediate Signer Generator.
    Designed for air-gapped / offline computers or secure environments.

.DESCRIPTION
    1. Generates an offline Root CA (stored locally in an offline-vault folder).
    2. Generates an Intermediate CA (e.g. Server, WiFi, or IoT signer).
    3. Signs the Intermediate CA using the Root CA with proper pathlen:0 constraints.
    4. Clearly packages the EXACT files to upload to the Web UI vs files to KEEP OFFLINE.
#>

param(
    [string]$OrgName = "Enterprise",
    [string]$Country = "US",
    [string]$State = "California",
    [string]$City = "San Francisco",
    [string]$IntermediateName = "int-server"
)

$ErrorActionPreference = "Stop"

# Detect OpenSSL
$OpenSSL = (Get-Command openssl -ErrorAction SilentlyContinue).Source
if (-not $OpenSSL) {
    if (Test-Path "C:\Program Files\Git\usr\bin\openssl.exe") {
        $OpenSSL = "C:\Program Files\Git\usr\bin\openssl.exe"
    } else {
        throw "OpenSSL was not found. Please install OpenSSL or Git for Windows."
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Zero-Trust Offline PKI Generator (OpenSSL)              " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$baseDir = $PSScriptRoot
$offlineVault = "$baseDir\offline-root-ca-vault"
$exportDir = "$baseDir\upload-to-web-ui"

# Ensure output directories exist
@($offlineVault, $exportDir) | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

# -------------------------------------------------------------
# STEP 1: Generate or Preserve Root CA (Kept in offline vault)
# -------------------------------------------------------------
$rootKey  = "$offlineVault\root-ca.key.pem"
$rootCert = "$offlineVault\root-ca.cert.pem"

if ((Test-Path $rootKey) -and (Test-Path $rootCert)) {
    Write-Host "`n[1/3] Existing Root CA found in vault: $rootCert" -ForegroundColor Green
    Write-Host "      Preserving existing Root CA." -ForegroundColor DarkGray
} else {
    Write-Host "`n[1/3] Generating Air-Gapped Root CA (RSA 4096, 20 Years)..." -ForegroundColor Yellow
    & $OpenSSL genrsa -out $rootKey 4096
    
    $rootSubj = "/C=$Country/ST=$State/L=$City/O=$OrgName/OU=$OrgName Root Authority/CN=$OrgName Root CA"
    & $OpenSSL req -new -x509 -days 7300 -sha256 -key $rootKey -out $rootCert -subj $rootSubj
    Write-Host "      [OK] Root CA generated in: $offlineVault" -ForegroundColor Green
}

# -------------------------------------------------------------
# STEP 2: Generate Intermediate CA Signer Key & CSR
# -------------------------------------------------------------
Write-Host "`n[2/3] Generating Intermediate CA Signer: $IntermediateName..." -ForegroundColor Yellow

$intKey  = "$exportDir\$IntermediateName.key.pem"
$intCsr  = "$offlineVault\$IntermediateName.csr.pem"
$intCert = "$exportDir\$IntermediateName.cert.pem"
$extFile = "$offlineVault\int_ext.cnf"

# Generate 4096-bit RSA Intermediate Key
& $OpenSSL genrsa -out $intKey 4096

# Generate CSR
$intSubj = "/C=$Country/ST=$State/L=$City/O=$OrgName/OU=$OrgName Infrastructure/CN=$OrgName Intermediate CA"
& $OpenSSL req -new -sha256 -key $intKey -out $intCsr -subj $intSubj

# -------------------------------------------------------------
# STEP 3: Sign Intermediate with Root CA (Offline)
# -------------------------------------------------------------
Write-Host "`n[3/3] Signing Intermediate CA with Root CA..." -ForegroundColor Yellow

@"
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
"@ | Set-Content -Path $extFile

& $OpenSSL x509 -req -in $intCsr -CA $rootCert -CAkey $rootKey `
                -CAcreateserial -out $intCert -days 3650 -sha256 -extfile $extFile

# Copy public Root Certificate to export folder (needed as trust anchor)
Copy-Item -Path $rootCert -Destination "$exportDir\root-ca.cert.pem" -Force

# Create instructions summary
$readmePath = "$exportDir\WHAT_TO_DO_NEXT.txt"
@"
================================================================================
  FILES READY TO UPLOAD TO YOUR WEB UI DASHBOARD
================================================================================

Folder: upload-to-web-ui\

1. root-ca.cert.pem       --> Paste into: 'Public Root CA Certificate (PEM)'
2. $IntermediateName.cert.pem   --> Paste into: 'Intermediate Certificate (PEM)'
3. $IntermediateName.key.pem    --> Paste into: 'Intermediate Private Key (PEM)'

================================================================================
  SECURITY ADVISORY - WHAT NEVER TO UPLOAD
================================================================================

Folder: offline-root-ca-vault\
File  : root-ca.key.pem (Root CA Private Key)

DO NOT UPLOAD 'root-ca.key.pem' TO DOCKER, COOLIFY, OR ANY SERVER.
Keep the 'offline-root-ca-vault\' folder on an encrypted offline drive or cold storage.
================================================================================
"@ | Set-Content -Path $readmePath

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  SUCCESS! CA GENERATION COMPLETE                         " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "Files to upload to Web UI are located in:" -ForegroundColor Cyan
Write-Host "  --> $exportDir" -ForegroundColor Yellow
Write-Host "`nYour Root CA private key is safely preserved in:" -ForegroundColor Cyan
Write-Host "  --> $offlineVault (KEEP THIS SECURE & OFFLINE)" -ForegroundColor Magenta
Write-Host "==========================================================" -ForegroundColor Green
