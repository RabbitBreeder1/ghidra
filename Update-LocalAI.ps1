param(
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Get-PropertyValue([string]$Path, [string]$Name) {
    $line = Get-Content -LiteralPath $Path |
        Where-Object { $_ -match ("^" + [regex]::Escape($Name) + "=") } |
        Select-Object -First 1

    if (-not $line) {
        throw "Could not find '$Name' in $Path"
    }

    return ($line -split "=", 2)[1].Trim()
}

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $repoRoot

$gradle = Join-Path $repoRoot "gradlew.bat"
$appProperties = Join-Path $repoRoot "Ghidra\application.properties"
$buildInfoPath = Join-Path $repoRoot "Ghidra\Extensions\LocalAI\src\main\java\ghidra\localai\LocalAIBuildInfo.java"

if (-not (Test-Path -LiteralPath $gradle)) {
    throw "gradlew.bat was not found. Run this script from the Ghidra repository copy."
}

if (-not (Test-Path -LiteralPath $appProperties)) {
    throw "Ghidra application.properties was not found."
}

Write-Step "Checking whether Ghidra is running"

$ghidraProcesses = @(
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.Name -in @("java.exe", "javaw.exe")) -and
            ($_.CommandLine -match "(?i)ghidra")
        }
)

if ($ghidraProcesses.Count -gt 0) {
    Write-Host "Ghidra appears to still be running:" -ForegroundColor Yellow
    foreach ($process in $ghidraProcesses) {
        Write-Host ("  PID {0}: {1}" -f $process.ProcessId, $process.CommandLine)
    }

    throw "Close every Ghidra window and run Update-LocalAI again. The updater will not replace a loaded extension."
}

$version = Get-PropertyValue $appProperties "application.version"
$release = Get-PropertyValue $appProperties "application.release.name"

$settingsFolderName = "ghidra_${version}_${release}"
$targetRoot = Join-Path $env:APPDATA "ghidra\$settingsFolderName\Extensions"
$target = Join-Path $targetRoot "LocalAI"

$buildId = "<unknown>"
if (Test-Path -LiteralPath $buildInfoPath) {
    $buildInfoText = Get-Content -LiteralPath $buildInfoPath -Raw
    $match = [regex]::Match(
        $buildInfoText,
        'BUILD_ID\s*=\s*"([^"]+)"'
    )
    if ($match.Success) {
        $buildId = $match.Groups[1].Value
    }
}

Write-Step "Building LocalAI $buildId"

$gradleArgs = @()
if (-not $SkipTests) {
    $gradleArgs += ":LocalAI:test"
}
$gradleArgs += ":LocalAI:zipExtensions"
$gradleArgs += "--console=plain"

& $gradle @gradleArgs
if ($LASTEXITCODE -ne 0) {
    throw "Gradle failed with exit code $LASTEXITCODE. The installed extension was not changed."
}

Write-Step "Finding the newly built LocalAI extension archive"

$dist = Join-Path $repoRoot "build\dist"
$zip = Get-ChildItem -LiteralPath $dist -Filter "*_LocalAI.zip" -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $zip) {
    throw "No LocalAI extension ZIP was found under $dist"
}

Write-Host ("Using: {0}" -f $zip.FullName)

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("LocalAI-update-" + [guid]::NewGuid().ToString("N"))
$extractRoot = Join-Path $tempRoot "extract"

New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null

try {
    Expand-Archive -LiteralPath $zip.FullName -DestinationPath $extractRoot -Force

    $source = Get-ChildItem -LiteralPath $extractRoot -Directory |
        Where-Object {
            Test-Path -LiteralPath (Join-Path $_.FullName "extension.properties")
        } |
        Select-Object -First 1

    if (-not $source) {
        throw "The built ZIP does not contain a valid extension folder."
    }

    $sourceJar = Get-ChildItem -LiteralPath (Join-Path $source.FullName "lib") -Filter "*.jar" -File -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if (-not $sourceJar) {
        throw "The built extension does not contain a compiled JAR."
    }

    Write-Step "Preparing the installed LocalAI location"

    New-Item -ItemType Directory -Path $targetRoot -Force | Out-Null

    $backupRoot = Join-Path $repoRoot "build\localai-backups"
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null

    if (Test-Path -LiteralPath $target) {
        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $backup = Join-Path $backupRoot ("LocalAI-" + $stamp)

        Write-Host ("Backing up current installed extension to: {0}" -f $backup)
        Copy-Item -LiteralPath $target -Destination $backup -Recurse -Force
    }

    $staging = Join-Path $targetRoot ("LocalAI.__new__." + [guid]::NewGuid().ToString("N"))

    if (Test-Path -LiteralPath $staging) {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }

    Copy-Item -LiteralPath $source.FullName -Destination $staging -Recurse -Force

    $stagedProperties = Join-Path $staging "extension.properties"
    $stagedJar = Get-ChildItem -LiteralPath (Join-Path $staging "lib") -Filter "*.jar" -File -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if (-not (Test-Path -LiteralPath $stagedProperties) -or -not $stagedJar) {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
        throw "The staged extension failed validation. The previous installed copy was left untouched."
    }

    Write-Step "Replacing the installed LocalAI extension"

    $rollback = Join-Path $targetRoot ("LocalAI.__old__." + [guid]::NewGuid().ToString("N"))
    $hadOldInstall = Test-Path -LiteralPath $target

    try {
        if ($hadOldInstall) {
            Move-Item -LiteralPath $target -Destination $rollback
        }

        Move-Item -LiteralPath $staging -Destination $target

        $installedProperties = Join-Path $target "extension.properties"
        $installedJar = Get-ChildItem -LiteralPath (Join-Path $target "lib") -Filter "*.jar" -File -ErrorAction SilentlyContinue |
            Select-Object -First 1

        if (-not (Test-Path -LiteralPath $installedProperties) -or -not $installedJar) {
            throw "Installation verification failed after replacement."
        }

        $sourceJarHash = (Get-FileHash -LiteralPath $sourceJar.FullName -Algorithm SHA256).Hash
        $installedJarHash = (Get-FileHash -LiteralPath $installedJar.FullName -Algorithm SHA256).Hash

        if ($sourceJarHash -ne $installedJarHash) {
            throw "Installed JAR hash does not match the freshly built JAR."
        }

        if (Test-Path -LiteralPath $rollback) {
            Remove-Item -LiteralPath $rollback -Recurse -Force
        }
    }
    catch {
        Write-Host "Replacement failed. Restoring the previous LocalAI installation..." -ForegroundColor Yellow

        if (Test-Path -LiteralPath $target) {
            Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue
        }

        if ($hadOldInstall -and (Test-Path -LiteralPath $rollback)) {
            Move-Item -LiteralPath $rollback -Destination $target
        }

        throw
    }

    Write-Step "Cleaning old LocalAI backups"

    Get-ChildItem -LiteralPath $backupRoot -Directory |
        Sort-Object LastWriteTime -Descending |
        Select-Object -Skip 3 |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "LocalAI update complete." -ForegroundColor Green
    Write-Host ("Build ID:      {0}" -f $buildId)
    Write-Host ("Installed to:  {0}" -f $target)
    Write-Host ("Compiled JAR:  {0}" -f $installedJar.FullName)
    Write-Host ""
    Write-Host "Start Ghidra normally. The Local AI panel should show the same build ID." -ForegroundColor Green
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
