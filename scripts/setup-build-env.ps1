<#
.SYNOPSIS
    Idempotent setup of the Theta Agent Windows dev/build environment.

.DESCRIPTION
    Ensures everything needed to build and package the Windows agent, tray,
    session helper, and the fully-offline Inno installer is present:

      * Go toolchain        (pinned version, user-space, no admin required)
      * Inno Setup compiler (pinned version, per-user install, no admin required)
      * vendor assets       (WireGuard MSI, VC++ redist, OpenCredential CP),
        fetched into installer/windows/vendor/ and verified against the pinned
        sha256 in installer/windows/vendor-manifest.json

    Safe to run repeatedly: each component is skipped when already installed
    and valid, so `powershell -File scripts/setup-build-env.ps1` is a no-op on a
    ready machine. Pass -Build to also compile the binaries and the installer.

.PARAMETER ToolDir
    Where to install toolchains. Default: %LOCALAPPDATA%\Theta42\buildtools

.PARAMETER RepoRoot
    Repository root. Default: the parent of this script's directory.

.PARAMETER SkipGo
    Do not install/verify the Go toolchain.

.PARAMETER SkipInno
    Do not install/verify Inno Setup.

.PARAMETER SkipVendor
    Do not fetch/verify vendor assets.

.PARAMETER Build
    After setup, build the agent/tray/helper for windows (amd64+arm64), run
    `go test ./...`, and compile the installer with ISCC.

.PARAMETER CI
    Non-interactive/CI mode: exit non-zero on any failure. (Used by the
    GitHub Actions workflow so the runner fails loudly on a broken env.)

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\setup-build-env.ps1 -Build
#>
[CmdletBinding()]
param(
    [string]$ToolDir = (Join-Path $env:LOCALAPPDATA 'Theta42\buildtools'),
    [string]$RepoRoot = '',
    [switch]$SkipGo,
    [switch]$SkipInno,
    [switch]$SkipVendor,
    [switch]$Build,
    [switch]$CI
)

$ErrorActionPreference = 'Stop'
$script:anyFailed = $false

# $PSScriptRoot is not populated inside the param() defaults on PowerShell 5.1.
if (-not $RepoRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

function Write-Step($msg) { Write-Host "== $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "   [OK]   $msg" -ForegroundColor Green }
function Write-Skip($msg) { Write-Host "   [skip] $msg" -ForegroundColor DarkGray }
function Write-Fail($msg) { Write-Host "   [FAIL] $msg" -ForegroundColor Red; $script:anyFailed = $true }
function Write-Info($msg) { Write-Host "   [info] $msg" -ForegroundColor Gray }

# ---------------------------------------------------------------- manifest ----
$manifestPath = Join-Path $RepoRoot 'installer\windows\vendor-manifest.json'
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
$vendorDir = Join-Path $RepoRoot 'installer\windows\vendor'

# -------------------------------------------------------------- Go toolchain --
function Get-GoVersion {
    $v = (go version 2>$null)
    if ($v -match 'go([0-9]+\.[0-9]+)') { return $matches[1] }
    return ''
}

function Install-Go {
    $needGo = $manifest.toolchain.go.version
    $minGo  = ($needGo -split '\.')[0] + '.' + ($needGo -split '\.')[1]  # e.g. 1.22
    $have   = Get-GoVersion

    if ($have -ne '' -and ([version]$have -ge [version]$minGo)) {
        Write-OK "Go $have already available ($minGo+ required)"
        return
    }

    $url = $manifest.toolchain.go.url
    $goRoot = Join-Path $ToolDir "go$needGo"
    # The official zip contains a top-level go/ folder -> goRoot\go\bin\go.exe.
    $goBin = Join-Path $goRoot 'go\bin'
    if (Test-Path (Join-Path $goBin 'go.exe')) {
        Write-OK "Go $needGo found at $goRoot"
    } else {
        Write-Step "Installing Go $needGo (no admin required, zip extract)"
        $zip = Join-Path $env:TEMP "go$needGo.windows-amd64.zip"
        if (-not (Test-Path $zip)) {
            Write-Info "Downloading $url"
            Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
        }
        $staging = Join-Path $goRoot 'staging'
        New-Item -ItemType Directory -Force -Path $staging | Out-Null
        Expand-Archive -Path $zip -DestinationPath $staging -Force
        # staging\go -> goRoot\go
        Move-Item -Force (Join-Path $staging 'go') $goRoot
        Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue
        if (-not (Test-Path (Join-Path $goBin 'go.exe'))) {
            Write-Fail "Go extract produced no bin\go.exe at $goBin"
            return
        }
        Write-OK "Go $needGo installed at $goRoot"
    }

    Add-ToUserPath $goBin
    $env:Path = "$goBin;$env:Path"
}

# --------------------------------------------------------------- Inno Setup ---
function Find-Iscc {
    $candidates = @(
        (Join-Path $ToolDir 'InnoSetup7\ISCC.exe'),
        "$env:ProgramFiles\Inno Setup 7\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return ''
}

function Install-Inno {
    $iscc = Find-Iscc
    if ($iscc) {
        Write-OK "Inno Setup ISCC found at $iscc"
        return $iscc
    }

    $inno = $manifest.toolchain.inno
    $exe  = Join-Path $env:TEMP "innosetup-$($inno.version)-x64.exe"
    if (-not (Test-Path $exe)) {
        Write-Step "Downloading Inno Setup $($inno.version)"
        Invoke-WebRequest -Uri $inno.url -OutFile $exe -UseBasicParsing
        $h = (Get-FileHash $exe -Algorithm SHA256).Hash.ToUpper()
        if ($h -ne $inno.sha256) {
            Remove-Item $exe -Force
            Write-Fail "Inno Setup installer sha256 mismatch: $h"
            return ''
        }
        Write-OK "Downloaded and verified Inno Setup installer"
    }

    $dest = Join-Path $ToolDir 'InnoSetup7'
    Write-Step "Installing Inno Setup per-user to $dest"
    # /CURRENTUSER installs without admin; /DIR is honored in that mode.
    $p = Start-Process -FilePath $exe -ArgumentList @(
        '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/CURRENTUSER',"/DIR=$dest"
    ) -Wait -PassThru
    if ($p.ExitCode -ne 0 -or -not (Test-Path (Join-Path $dest 'ISCC.exe'))) {
        Write-Fail "Inno Setup install failed (exit $($p.ExitCode)); ISCC not found at $dest"
        return ''
    }
    Write-OK "Inno Setup installed; ISCC at $(Join-Path $dest 'ISCC.exe')"
    Add-ToUserPath $dest
    return (Join-Path $dest 'ISCC.exe')
}

# ------------------------------------------------- PATH (idempotent) ----------
function Add-ToUserPath($dir) {
    if (-not $dir -or -not (Test-Path $dir)) { return }
    $userPath = [Environment]::GetEnvironmentVariable('Path','User')
    if ($userPath -and ($userPath -split ';' -contains $dir)) {
        Write-Skip "$dir already on user PATH"
        return
    }
    $newPath = if ($userPath) { "$userPath;$dir" } else { $dir }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Write-OK "Added $dir to user PATH"
}

# ------------------------------------------------ Vendor assets (idempotent) --
function Fetch-Asset($asset) {
    $dest = Join-Path $vendorDir $asset.name
    $ok = $false
    if (Test-Path $dest) {
        $h = (Get-FileHash $dest -Algorithm SHA256).Hash.ToUpper()
        if ($h -eq $asset.sha256) {
            $ok = $true
            Write-Skip "$($asset.name) present and checksum verified"
        } else {
            Write-Info "$($asset.name): stale or corrupt (got $h), re-downloading"
        }
    }
    if (-not $ok) {
        Write-Info "Downloading $($asset.name)"
        Invoke-WebRequest -Uri $asset.url -OutFile $dest -UseBasicParsing
        $h = (Get-FileHash $dest -Algorithm SHA256).Hash.ToUpper()
        if ($h -ne $asset.sha256) {
            Remove-Item $dest -Force
            Write-Fail "$($asset.name): sha256 mismatch ($h) - expected $($asset.sha256)"
            return
        }
        Write-OK "$($asset.name) downloaded and checksum verified"
    }
    Set-Content -Path "$dest.sha256" -Value $asset.sha256 -NoNewline
}

function Ensure-Vendor {
    Write-Step "Vendor assets (pinned in vendor-manifest.json)"
    New-Item -ItemType Directory -Force -Path $vendorDir | Out-Null
    foreach ($a in $manifest.assets) {
        Fetch-Asset $a
    }
}

# ----------------------------------------------------------------- Verify -----
function Assert-BuildReady {
    Write-Step "Verification"
    $go = Get-GoVersion
    if ($go) { Write-OK "go $go" } elseif (-not $SkipGo) { Write-Fail 'go not found' }

    $iscc = Find-Iscc
    if ($iscc) { Write-OK "ISCC $iscc" } elseif (-not $SkipInno) { Write-Fail 'ISCC not found' }

    foreach ($a in $manifest.assets) {
        $dest = Join-Path $vendorDir $a.name
        if (Test-Path $dest) {
            $h = (Get-FileHash $dest -Algorithm SHA256).Hash.ToUpper()
            if ($h -eq $a.sha256) { Write-OK "$($a.name) verified" }
            else { Write-Fail "$($a.name) checksum mismatch" }
        } elseif (-not $SkipVendor) {
            Write-Fail "$($a.name) missing"
        }
    }

    if ($script:anyFailed) {
        if ($CI) { throw 'Build environment setup failed' }
        exit 1
    }
    Write-Host "Build environment ready." -ForegroundColor Green
}

# ------------------------------------------------------------------- Build ----
function Invoke-Build {
    Write-Step "Building agent, tray, helper (windows amd64+arm64)"
    $dist = Join-Path $RepoRoot 'dist'
    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    $flags = '-s -w'
    # The tray and helper are GUI-subsystem binaries: no console window pops up
    # when the installer starts the tray or the service spawns the helper.
    $guiFlags = '-s -w -H=windowsgui'
    foreach ($arch in @('amd64','arm64')) {
        $env:GOOS='windows'; $env:GOARCH=$arch; $env:CGO_ENABLED='0'
        go build "-ldflags=$flags" -o (Join-Path $dist "theta-agent-windows-$arch.exe") $RepoRoot
        if ($LASTEXITCODE -ne 0) { Write-Fail "build agent windows/$arch failed"; return }
        go build "-ldflags=$guiFlags" -o (Join-Path $dist "theta-agent-tray-windows-$arch.exe") (Join-Path $RepoRoot 'cmd\theta-agent-tray')
        if ($LASTEXITCODE -ne 0) { Write-Fail "build tray windows/$arch failed"; return }
        go build "-ldflags=$guiFlags" -o (Join-Path $dist "theta-agent-helper-windows-$arch.exe") (Join-Path $RepoRoot 'cmd\theta-agent-helper')
        if ($LASTEXITCODE -ne 0) { Write-Fail "build helper windows/$arch failed"; return }
    }
    Remove-Item Env:GOOS,Env:GOARCH,Env:CGO_ENABLED -ErrorAction SilentlyContinue

    Write-Step "Running go test ./..."
    Push-Location $RepoRoot
    go test ./...
    if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Fail 'go test failed'; return }
    Pop-Location

    $iscc = Find-Iscc
    if (-not $iscc) { Write-Fail 'ISCC not found; cannot build installer'; return }
    Write-Step "Compiling installer with ISCC"
    & $iscc (Join-Path $RepoRoot 'installer\windows\installer.iss')
    if ($LASTEXITCODE -ne 0) { Write-Fail 'ISCC compile failed' }
}

# ------------------------------------------------------------------- Main -----
New-Item -ItemType Directory -Force -Path $ToolDir | Out-Null

if (-not $SkipGo)      { Install-Go }
if (-not $SkipInno)    { $null = Install-Inno }
if (-not $SkipVendor)  { Ensure-Vendor }

Assert-BuildReady
if ($Build) { Invoke-Build }

if ($script:anyFailed) {
    if ($CI) { throw 'Setup failed' }
    exit 1
}
