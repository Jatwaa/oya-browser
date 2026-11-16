<#
.SYNOPSIS
    Commits, tests, pushes, and optionally tags/releases Oya Browser updates to GitHub.

.DESCRIPTION
    Automates deploying Oya Browser changes to GitHub (`origin`).
    - Optionally bumps the workspace version in Cargo.toml (-Bump patch|minor|major or -Version X.Y.Z).
    - Runs `cargo test --workspace --quiet` before committing unless -SkipTests is set.
    - Stages and commits changes, pushes to the target branch on GitHub.
    - When -Tag is passed, creates and pushes `v<version>`, which triggers `.github/workflows/release.yml`
      to build the Windows x64 zip and publish a GitHub Release automatically.
    - When -Distrib is passed, also runs `.\generate_distrib.ps1` locally.

.PARAMETER Message
    Git commit message. Defaults to "Update Oya Browser".

.PARAMETER Bump
    Optional semver bump: none (default), patch, minor, or major.

.PARAMETER Version
    Explicit version string (e.g. "1.2.0") to set in Cargo.toml instead of -Bump.

.PARAMETER Branch
    Target git branch to push. Defaults to the current checked-out branch.

.PARAMETER Tag
    Create and push git tag `v<version>` to trigger GitHub Actions Release workflow.

.PARAMETER Distrib
    Also run `.\generate_distrib.ps1` locally to update `.\Distrib\v<version>`.

.PARAMETER SkipTests
    Skip running `cargo test --workspace --quiet` before pushing.

.PARAMETER DryRun
    Show what would be done without modifying Cargo.toml, committing, or pushing.

.EXAMPLE
    .\deploy_github.ps1 -Message "Add download manager and hazard scanner"
    .\deploy_github.ps1 -Bump minor -Message "Release v1.2.0" -Tag
    .\deploy_github.ps1 -Version "1.2.0" -Tag -Distrib
#>

[CmdletBinding()]
param(
    [string]$Message = "Update Oya Browser",

    [ValidateSet("none", "patch", "minor", "major")]
    [string]$Bump = "none",

    [string]$Version,
    [string]$Branch,
    [switch]$Tag,
    [switch]$Distrib,
    [switch]$SkipTests,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ScriptDir) {
    $ScriptDir = Get-Location
}
Set-Location $ScriptDir

function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$GitArgs)
    & git @GitArgs
    if ($LASTEXITCODE -ne 0) {
        throw "git $($GitArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "              OYA BROWSER - GITHUB DEPLOY SCRIPT                 " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Verify git repository & branch
if (-not $Branch) {
    $Branch = (& git rev-parse --abbrev-ref HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $Branch -or $Branch -eq "HEAD") {
        throw "Could not determine current git branch. Specify -Branch explicitly."
    }
}
$RemoteUrl = (& git remote get-url origin).Trim()
Write-Host "[1/6] Branch / Remote      : $Branch -> $RemoteUrl" -ForegroundColor Green

# 2. Read / optionally bump version in Cargo.toml
$CargoPath = Join-Path $ScriptDir "Cargo.toml"
$CargoRaw = Get-Content $CargoPath -Raw
if ($CargoRaw -notmatch '(\[workspace\.package\][\s\S]*?version\s*=\s*")([^"]+)(")') {
    throw "Could not locate [workspace.package] version in Cargo.toml"
}
$CurrentVersion = $Matches[2]
$TargetVersion = $CurrentVersion

if ($Version) {
    $TargetVersion = $Version.TrimStart("v")
} elseif ($Bump -ne "none") {
    $parts = $CurrentVersion.Split(".")
    if ($parts.Count -lt 3) {
        throw "Current version '$CurrentVersion' is not X.Y.Z semver"
    }
    $maj = [int]$parts[0]
    $min = [int]$parts[1]
    $pat = [int]$parts[2]
    switch ($Bump) {
        "major" { $maj++; $min = 0; $pat = 0 }
        "minor" { $min++; $pat = 0 }
        "patch" { $pat++ }
    }
    $TargetVersion = "$maj.$min.$pat"
}

if ($TargetVersion -ne $CurrentVersion) {
    Write-Host "[2/6] Version Bump         : $CurrentVersion -> $TargetVersion" -ForegroundColor Yellow
    if (-not $DryRun) {
        $UpdatedCargo = [regex]::Replace(
            $CargoRaw,
            '(\[workspace\.package\][\s\S]*?version\s*=\s*")([^"]+)(")',
            "`${1}$TargetVersion`${3}",
            1
        )
        Set-Content -Path $CargoPath -Value $UpdatedCargo -NoNewline -Encoding utf8
    }
} else {
    Write-Host "[2/6] Version              : $TargetVersion (unchanged)" -ForegroundColor Green
}
$VerTag = "v$TargetVersion"

# 3. Run tests
if (-not $SkipTests) {
    Write-Host "[3/6] Running tests        : cargo test --workspace --quiet" -ForegroundColor Yellow
    if (-not $DryRun) {
        & cargo test --workspace --quiet
        if ($LASTEXITCODE -ne 0) {
            throw "Tests failed (exit code $LASTEXITCODE). Aborting deploy."
        }
    }
} else {
    Write-Host "[3/6] Skipping tests       : -SkipTests set" -ForegroundColor DarkGray
}

# 4. Optional local distributable build
if ($Distrib) {
    Write-Host "[4/6] Building Distrib     : .\generate_distrib.ps1 -Version $TargetVersion" -ForegroundColor Yellow
    if (-not $DryRun) {
        & (Join-Path $ScriptDir "generate_distrib.ps1") -Version $TargetVersion
        if ($LASTEXITCODE -ne 0) {
            throw "generate_distrib.ps1 failed with exit code $LASTEXITCODE"
        }
    }
} else {
    Write-Host "[4/6] Local Distrib        : skipped (pass -Distrib to generate)" -ForegroundColor DarkGray
}

# 5. Stage, commit, and push branch
Write-Host "[5/6] Staging & Pushing    : origin/$Branch" -ForegroundColor Yellow
if ($DryRun) {
    & git status -s
    Write-Host "      [DryRun] Would commit with message: '$Message' and push to origin/$Branch" -ForegroundColor Cyan
} else {
    Invoke-Git add -A
    $Pending = (& git status --porcelain)
    if ($Pending) {
        Invoke-Git commit -m $Message
    } else {
        Write-Host "      No new local changes to commit; pushing any unpushed commits..." -ForegroundColor Gray
    }
    Invoke-Git push origin $Branch
}

# 6. Optional tag & GitHub Release trigger
if ($Tag) {
    Write-Host "[6/6] Tagging & Releasing  : $VerTag" -ForegroundColor Yellow
    if ($DryRun) {
        Write-Host "      [DryRun] Would create tag '$VerTag' and push to origin" -ForegroundColor Cyan
    } else {
        $ExistingTag = (& git tag -l $VerTag).Trim()
        if ($ExistingTag) {
            Write-Warning "Tag $VerTag already exists locally; skipping git tag creation."
        } else {
            Invoke-Git tag -a $VerTag -m "Oya Browser $VerTag"
        }
        Invoke-Git push origin $VerTag
        Write-Host "      Pushed $VerTag -> GitHub Actions Release workflow triggered." -ForegroundColor Green
    }
} else {
    Write-Host "[6/6] Release Tag          : skipped (pass -Tag to trigger GitHub Release)" -ForegroundColor DarkGray
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Deploy complete." -ForegroundColor Green
