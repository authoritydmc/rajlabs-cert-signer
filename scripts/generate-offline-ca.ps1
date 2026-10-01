<#
.SYNOPSIS
    Interactive Offline Root CA and Intermediate Signer Generator.
    Equipped with strict override protections for both Root CA and Intermediate CAs.

.DESCRIPTION
    1. NEVER overwrites Root CA if root-ca.key.pem or root-ca.cert.pem already exists (requires typing explicit confirmation 'OVERWRITE-ROOT').
    2. NEVER overwrites existing Intermediate CAs without prompting options:
       [S] Skip (Preserve existing)
       [A] Archive existing and create new
       [F] Force Overwrite
       [Q] Quit / Abort
    3. Clearly segregates files to upload to Web UI vs files to keep strictly offline.
#>

param(
    [string]$OrgName = "Enterprise",
    [string]$Country = "US",
    [string]$State = "California",
    [string]$City = "San Francisco",
    [string]$IntermediateName = "int-server",
    [switch]$ForceRootRegen = $false
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
Write-Host "  Zero-Trust Offline PKI Generator (Protected)            " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$baseDir = $PSScriptRoot
$offlineVault = "$baseDir\offline-root-ca-vault"
$exportDir = "$baseDir\upload-to-web-ui"
$archiveDir = "$offlineVault\archive"
$configFile = "$baseDir\pki-config.json"

# Load saved user organization config if present
if (Test-Path $configFile) {
    try {
        $savedConfig = Get-Content $configFile -Raw | ConvertFrom-Json
        if ($PSBoundParameters.ContainsKey('OrgName') -eq $false -and $savedConfig.OrgName) { $OrgName = $savedConfig.OrgName }
        if ($PSBoundParameters.ContainsKey('Country') -eq $false -and $savedConfig.Country) { $Country = $savedConfig.Country }
        if ($PSBoundParameters.ContainsKey('State') -eq $false -and $savedConfig.State)     { $State   = $savedConfig.State }
        if ($PSBoundParameters.ContainsKey('City') -eq $false -and $savedConfig.City)       { $City    = $savedConfig.City }
        Write-Host "Loaded saved organization profile from: $configFile" -ForegroundColor DarkGray
    } catch {}
} else {
    # Save for future runs
    @{
        OrgName = $OrgName
        Country = $Country
        State   = $State
        City    = $City
    } | ConvertTo-Json | Set-Content -Path $configFile
}

# Ensure output directories exist
@($offlineVault, $exportDir, $archiveDir) | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

# -------------------------------------------------------------
# STEP 1: Root CA Protection & Generation
# -------------------------------------------------------------
$rootKey  = "$offlineVault\root-ca.key.pem"
$rootCert = "$offlineVault\root-ca.cert.pem"

if ((Test-Path $rootKey) -or (Test-Path $rootCert)) {
    Write-Host "`n[1/3] Root CA already exists in vault: $offlineVault" -ForegroundColor Green
    
    if ($ForceRootRegen) {
        Write-Host "`n⚠️  DANGER: You passed -ForceRootRegen!" -ForegroundColor Red
        Write-Host "Regenerating the Root CA will INVALIDATE ALL existing intermediate CAs and end certificates!" -ForegroundColor Yellow
        $confirm = Read-Host -Prompt "To confirm complete Root CA destruction & recreation, type 'OVERWRITE-ROOT'"
        if ($confirm -ne "OVERWRITE-ROOT") {
            Write-Host "Protection triggered: Aborting Root CA regeneration. Existing Root CA preserved." -ForegroundColor Green
        } else {
            $ts = Get-Date -Format "yyyyMMdd-HHmmss"
            Move-Item -Path $rootKey -Destination "$archiveDir\root-ca-$ts.key.pem" -Force -ErrorAction SilentlyContinue
            Move-Item -Path $rootCert -Destination "$archiveDir\root-ca-$ts.cert.pem" -Force -ErrorAction SilentlyContinue
            Write-Host "Old Root CA backed up to $archiveDir" -ForegroundColor DarkGray

            Write-Host "Generating NEW Air-Gapped Root CA (RSA 4096, 20 Years)..." -ForegroundColor Yellow
            & $OpenSSL genrsa -out $rootKey 4096
            $rootSubj = "/C=$Country/ST=$State/L=$City/O=$OrgName/OU=$OrgName Root Authority/CN=$OrgName Root CA"
            & $OpenSSL req -new -x509 -days 7300 -sha256 -key $rootKey -out $rootCert -subj $rootSubj
            Write-Host "      [OK] New Root CA created." -ForegroundColor Green
        }
    } else {
        Write-Host "      [PROTECTED] Preserving existing Root CA (Never overwritten automatically)." -ForegroundColor Cyan
    }
} else {
    Write-Host "`n[1/3] Generating Air-Gapped Root CA (RSA 4096, 20 Years)..." -ForegroundColor Yellow
    & $OpenSSL genrsa -out $rootKey 4096
    $rootSubj = "/C=$Country/ST=$State/L=$City/O=$OrgName/OU=$OrgName Root Authority/CN=$OrgName Root CA"
    & $OpenSSL req -new -x509 -days 7300 -sha256 -key $rootKey -out $rootCert -subj $rootSubj
    Write-Host "      [OK] Root CA generated in: $offlineVault" -ForegroundColor Green
}

# -------------------------------------------------------------
# STEP 2: Intermediate CA Protection & Generation
# -------------------------------------------------------------
$intKey  = "$exportDir\$IntermediateName.key.pem"
$intCsr  = "$offlineVault\$IntermediateName.csr.pem"
$intCert = "$exportDir\$IntermediateName.cert.pem"
$extFile = "$offlineVault\int_ext.cnf"

Write-Host "`n[2/3] Checking Intermediate CA Signer: $IntermediateName..." -ForegroundColor Cyan

if ((Test-Path $intKey) -or (Test-Path $intCert)) {
    Write-Host "⚠️  ATTENTION: Intermediate CA '$IntermediateName' already exists in $exportDir!" -ForegroundColor Yellow
    Write-Host "   Cert : $intCert"
    Write-Host "   Key  : $intKey"
    
    $prompt = @"
   What would you like to do?
     [S] Skip (Protect and keep existing intermediate CA)
     [A] Archive existing and create a new signed intermediate
     [F] Force Overwrite without backup
     [Q] Quit / Abort
   Choice (default: S): 
"@
    $choice = (Read-Host -Prompt $prompt).Trim().ToUpper()

    switch ($choice) {
        "A" {
            $ts = Get-Date -Format "yyyyMMdd-HHmmss"
            if (Test-Path $intCert) { Move-Item -Path $intCert -Destination "$archiveDir\$IntermediateName-$ts.cert.pem" -Force }
            if (Test-Path $intKey)  { Move-Item -Path $intKey -Destination "$archiveDir\$IntermediateName-$ts.key.pem" -Force }
            Write-Host "   [OK] Existing intermediate archived to $archiveDir" -ForegroundColor DarkGray
        }
        "F" {
            Write-Host "   [OVERWRITE] Proceeding to overwrite $IntermediateName..." -ForegroundColor Yellow
        }
        "Q" {
            Write-Host "Operation cancelled by user." -ForegroundColor Red
            return
        }
        Default {
            Write-Host "   [PROTECTED] Keeping existing $IntermediateName. No files modified." -ForegroundColor Green
            return
        }
    }
}

Write-Host "Generating private key for $IntermediateName (RSA 4096)..."
& $OpenSSL genrsa -out $intKey 4096

Write-Host "Generating CSR for $IntermediateName..."
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

# Save organization config for subsequent intermediate generation
@{
    OrgName = $OrgName
    Country = $Country
    State   = $State
    City    = $City
} | ConvertTo-Json | Set-Content -Path $configFile

# Create instructions summary
$readmePath = "$exportDir\WHAT_TO_DO_NEXT.txt"
@"
================================================================================
  FILES READY TO UPLOAD TO YOUR WEB UI DASHBOARD
================================================================================

Folder: upload-to-web-ui\

1. root-ca.cert.pem          --> Paste into: 'Public Root CA Certificate (PEM)'
2. $IntermediateName.cert.pem      --> Paste into: 'Intermediate Certificate (PEM)'
3. $IntermediateName.key.pem       --> Paste into: 'Intermediate Private Key (PEM)'

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
