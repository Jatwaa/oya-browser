<#
.SYNOPSIS
    Generates a versioned distributable package for Oya Browser in .\Distrib.

.DESCRIPTION
    Builds the standalone release binary (if needed), packages executables, assets,
    documentation, and manifest into a structured .\Distrib\v<version>\OyaBrowser\ folder,
    creates a portable .zip archive, and computes SHA-256 checksums.

.PARAMETER Version
    Optional version string (e.g. "1.1.0"). If omitted, it is extracted automatically
    from Cargo.toml.

.PARAMETER SkipBuild
    Skip running `cargo build --release -p rc_browser` and package existing release binaries.

.PARAMETER Clean
    Run `cargo clean -p rc_browser` before building.

.PARAMETER OutputDir
    Custom destination directory. Defaults to .\Distrib.

.EXAMPLE
    .\generate_distrib.ps1
    .\generate_distrib.ps1 -Version "1.1.0"
    .\generate_distrib.ps1 -SkipBuild
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Version,

    [switch]$SkipBuild,
    [switch]$Clean,
    [string]$OutputDir
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ScriptDir) {
    $ScriptDir = Get-Location
}
Set-Location $ScriptDir

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "         OYA BROWSER — DISTRIBUTABLE PACKAGE GENERATOR           " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Determine Version
# ---------------------------------------------------------------------------
if (-not $Version) {
    $CargoPath = Join-Path $ScriptDir "Cargo.toml"
    if (Test-Path $CargoPath) {
        $CargoContent = Get-Content $CargoPath -Raw
        if ($CargoContent -match '\[workspace\.package\][\s\S]*?version\s*=\s*"([^"]+)"') {
            $Version = $Matches[1]
        } elseif ($CargoContent -match 'version\s*=\s*"([^"]+)"') {
            $Version = $Matches[1]
        }
    }
}

if (-not $Version) {
    $Version = "1.1.0"
    Write-Warning "Could not detect version from Cargo.toml. Falling back to default: $Version"
}

$VerTag = "v$Version"
Write-Host "[1/6] Target Version       : $Version ($VerTag)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 2. Determine Output Paths
# ---------------------------------------------------------------------------
if (-not $OutputDir) {
    $OutputDir = Join-Path $ScriptDir "Distrib"
}
$VersionDistribDir = Join-Path $OutputDir $VerTag
$AppPayloadDir = Join-Path $VersionDistribDir "OyaBrowser"
$ZipFileName = "OyaBrowser-$VerTag-windows-x64.zip"
$ZipFilePath = Join-Path $VersionDistribDir $ZipFileName

Write-Host "[2/6] Output Directory     : $VersionDistribDir" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Build Release Binary (if not skipped)
# ---------------------------------------------------------------------------
$ReleaseExe = Join-Path $ScriptDir "target\release\oya_browser.exe"
$CompatExe  = Join-Path $ScriptDir "target\release\rustchrome.exe"

if (-not $SkipBuild) {
    Write-Host "[3/6] Building release binaries via Cargo..." -ForegroundColor Yellow

    # Terminate any running browser processes to prevent OS Error 5 (Access Denied)
    Stop-Process -Name "oya_browser" -Force -ErrorAction SilentlyContinue
    Stop-Process -Name "rustchrome" -Force -ErrorAction SilentlyContinue

    if ($Clean) {
        Write-Host "      Cleaning previous build artifacts..." -ForegroundColor Gray
        cargo clean -p rc_browser
    }

    Write-Host "      Executing: cargo build --release -p rc_browser" -ForegroundColor Gray
    $BuildTimer = [System.Diagnostics.Stopwatch]::StartNew()
    cargo build --release -p rc_browser
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Cargo build failed with exit code $LASTEXITCODE. Aborting distribution generation."
        exit $LASTEXITCODE
    }
    $BuildTimer.Stop()
    Write-Host "      Build succeeded in $($BuildTimer.Elapsed.TotalSeconds.ToString('F1'))s" -ForegroundColor Green
} else {
    Write-Host "[3/6] Skipping build step (-SkipBuild specified)." -ForegroundColor Yellow
}

# Verify release executable exists
if (-not (Test-Path $ReleaseExe)) {
    Write-Error "Release executable not found at: $ReleaseExe"
    exit 1
}

# Mirror to compat executable name if needed
Copy-Item -Path $ReleaseExe -Destination $CompatExe -Force

$ExeSize = (Get-Item $ReleaseExe).Length
Write-Host "      Executable Verified : $ReleaseExe ($([math]::Round($ExeSize / 1MB, 2)) MB)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4. Assemble Distribution Directory
# ---------------------------------------------------------------------------
Write-Host "[4/6] Assembling portable distributable directory structure..." -ForegroundColor Yellow

# Clean previous distribution directory for this version
if (Test-Path $AppPayloadDir) {
    Remove-Item -Path $AppPayloadDir -Recurse -Force
}
New-Item -Path $AppPayloadDir -ItemType Directory -Force | Out-Null

# Copy primary binary and compat binary
Copy-Item -Path $ReleaseExe -Destination (Join-Path $AppPayloadDir "oya_browser.exe") -Force
Copy-Item -Path $CompatExe  -Destination (Join-Path $AppPayloadDir "rustchrome.exe") -Force

# Copy Assets
$AssetsSource = Join-Path $ScriptDir "assets"
$AssetsTarget = Join-Path $AppPayloadDir "assets"
if (Test-Path $AssetsSource) {
    Copy-Item -Path $AssetsSource -Destination $AppPayloadDir -Recurse -Force
}

# Copy Documentation
$DocsToCopy = @("OyaBrowser.md", "README.md", "CHANGELOG.md", "SECURITY.md", "LICENSE-MIT", "LICENSE-APACHE")
foreach ($doc in $DocsToCopy) {
    $DocSource = Join-Path $ScriptDir $doc
    if (Test-Path $DocSource) {
        Copy-Item -Path $DocSource -Destination (Join-Path $AppPayloadDir $doc) -Force
    }
}

# Create empty logs directory placeholder
$LogsDir = Join-Path $AppPayloadDir "logs"
New-Item -Path $LogsDir -ItemType Directory -Force | Out-Null
Set-Content -Path (Join-Path $LogsDir ".gitkeep") -Value "" -NoNewline

# Create batch launcher
$LauncherContent = @"
@echo off
start "" "%~dp0oya_browser.exe" %*
"@
Set-Content -Path (Join-Path $AppPayloadDir "Launch_OyaBrowser.bat") -Value $LauncherContent -Encoding ASCII

# Generate version manifest.json
$ExeHash = (Get-FileHash -Path $ReleaseExe -Algorithm SHA256).Hash.ToLower()
$Manifest = [ordered]@{
    product       = "Oya Browser"
    version       = $Version
    version_tag   = $VerTag
    target        = "x86_64-pc-windows-msvc"
    subsystem     = "windows (no-console)"
    build_time    = (Get-Date).ToString("o")
    files         = @(
        [ordered]@{
            file   = "oya_browser.exe"
            bytes  = $ExeSize
            sha256 = $ExeHash
        },
        [ordered]@{
            file   = "rustchrome.exe"
            bytes  = $ExeSize
            sha256 = $ExeHash
        }
    )
}
$ManifestJson = $Manifest | ConvertTo-Json -Depth 5
Set-Content -Path (Join-Path $AppPayloadDir "manifest.json") -Value $ManifestJson -Encoding UTF8

Write-Host "      Assembled payload in: $AppPayloadDir" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 5. Create Compressed Archive (.zip)
# ---------------------------------------------------------------------------
Write-Host "[5/6] Creating portable ZIP archive: $ZipFileName..." -ForegroundColor Yellow

if (Test-Path $ZipFilePath) {
    Remove-Item -Path $ZipFilePath -Force
}

Compress-Archive -Path $AppPayloadDir -DestinationPath $ZipFilePath -CompressionLevel Optimal
$ZipSize = (Get-Item $ZipFilePath).Length
Write-Host "      Created archive     : $ZipFilePath ($([math]::Round($ZipSize / 1MB, 2)) MB)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 6. Generate SHA256 Checksums
# ---------------------------------------------------------------------------
Write-Host "[6/6] Generating SHA256 checksums..." -ForegroundColor Yellow

$Checksums = @()

$FilesToHash = @(
    (Join-Path $AppPayloadDir "oya_browser.exe"),
    (Join-Path $AppPayloadDir "rustchrome.exe"),
    $ZipFilePath
)

foreach ($f in $FilesToHash) {
    if (Test-Path $f) {
        $h = (Get-FileHash -Path $f -Algorithm SHA256).Hash.ToLower()
        $relName = Split-Path -Leaf $f
        if ($f -like "*\OyaBrowser\*") {
            $relName = "OyaBrowser/$relName"
        }
        $Checksums += "$h  $relName"
    }
}

$ChecksumFile = Join-Path $VersionDistribDir "SHA256SUMS.txt"
Set-Content -Path $ChecksumFile -Value ($Checksums -join "`r`n") -Encoding ASCII

# ---------------------------------------------------------------------------
# Distribution Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "           DISTRIBUTION GENERATION COMPLETE                      " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Version Dir : $VersionDistribDir" -ForegroundColor White
Write-Host "Payload Dir : $AppPayloadDir" -ForegroundColor White
Write-Host "ZIP Archive : $ZipFilePath ($([math]::Round($ZipSize / 1MB, 2)) MB)" -ForegroundColor White
Write-Host "Checksums   : $ChecksumFile" -ForegroundColor White
Write-Host ""
Write-Host "Contents of $($ChecksumFile):" -ForegroundColor Gray
Get-Content $ChecksumFile | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
Write-Host ""
Write-Host "To test the distributed binary:" -ForegroundColor Yellow
Write-Host "  & `"$AppPayloadDir\oya_browser.exe`"" -ForegroundColor White
Write-Host "=================================================================" -ForegroundColor Cyan
