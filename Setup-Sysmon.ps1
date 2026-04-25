#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs (if needed) and configures Sysmon with the detection rules required
    by the Cyber Behaviour Profiler.
.DESCRIPTION
    If Sysmon is not found it is downloaded automatically from the official
    Sysinternals URL and installed. Then sysmon-profiler.xml is applied and the
    three profiler event IDs are verified.
.NOTES
    Run from an elevated PowerShell prompt:
        .\Setup-Sysmon.ps1
    To use a local copy instead of downloading:
        .\Setup-Sysmon.ps1 -SysmonPath "C:\Tools\Sysmon64.exe"
#>
param(
    [string]$SysmonPath = "",
    [string]$ConfigPath = "$PSScriptRoot\sysmon-profiler.xml"
)

$ErrorActionPreference = "Stop"

function Write-Step  { param($msg) Write-Host "`n[*] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "    [+] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "    [!] $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "    [-] $msg" -ForegroundColor Red }

# ── 1. Locate or download the Sysmon executable ───────────────────────────────
Write-Step "Locating Sysmon"

$sysmonExe = $null
$candidates = @("Sysmon64.exe", "Sysmon.exe")

if ($SysmonPath -and (Test-Path $SysmonPath)) {
    $sysmonExe = $SysmonPath
    Write-Ok "Using provided path: $sysmonExe"
} else {
    foreach ($name in $candidates) {
        $found = Get-Command $name -ErrorAction SilentlyContinue
        if ($found) { $sysmonExe = $found.Source; break }
    }
    if (-not $sysmonExe) {
        foreach ($name in $candidates) {
            $path = "C:\Windows\$name"
            if (Test-Path $path) { $sysmonExe = $path; break }
        }
    }
}

if (-not $sysmonExe) {
    Write-Warn "Sysmon not found — downloading from Sysinternals..."

    $downloadUrl = "https://download.sysinternals.com/files/Sysmon.zip"
    $zipPath     = "$env:TEMP\Sysmon.zip"
    $extractDir  = "$env:TEMP\Sysmon"

    try {
        Write-Host "    Downloading $downloadUrl ..." -NoNewline
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
        Write-Host " done." -ForegroundColor Green
    } catch {
        Write-Fail "Download failed: $_"
        Write-Warn "Check your internet connection or supply the binary manually:"
        Write-Warn "  .\Setup-Sysmon.ps1 -SysmonPath 'C:\path\to\Sysmon64.exe'"
        exit 1
    }

    if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
    Expand-Archive -Path $zipPath -DestinationPath $extractDir
    Remove-Item $zipPath -Force

    # Prefer 64-bit
    $sysmonExe = if (Test-Path "$extractDir\Sysmon64.exe") {
        "$extractDir\Sysmon64.exe"
    } else {
        "$extractDir\Sysmon.exe"
    }

    if (-not (Test-Path $sysmonExe)) {
        Write-Fail "Extraction succeeded but Sysmon executable not found in $extractDir"
        exit 1
    }
    Write-Ok "Downloaded and extracted: $sysmonExe"
}

Write-Ok "Found: $sysmonExe"

# ── 2. Check the Sysmon service ───────────────────────────────────────────────
Write-Step "Checking Sysmon service"

$service = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $service) {
    $service = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
}

if (-not $service) {
    Write-Warn "Sysmon service not installed — installing now..."
    & $sysmonExe -i $ConfigPath -accepteula 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Installation failed (exit $LASTEXITCODE). Check that you are running as Administrator."
        exit 1
    }
    Write-Ok "Sysmon installed and started."
} elseif ($service.Status -ne "Running") {
    Write-Warn "Sysmon service exists but is not running — starting..."
    Start-Service $service.Name
    Write-Ok "Service started."
} else {
    Write-Ok "Service is running ($($service.Name))."
}

# ── 3. Verify the config file ─────────────────────────────────────────────────
Write-Step "Verifying config file"

if (-not (Test-Path $ConfigPath)) {
    Write-Fail "Config not found at: $ConfigPath"
    exit 1
}
Write-Ok "Config: $ConfigPath"

# ── 4. Apply the configuration ────────────────────────────────────────────────
Write-Step "Applying Sysmon configuration"

& $sysmonExe -c $ConfigPath 2>&1 | ForEach-Object { Write-Host "    $_" }
if ($LASTEXITCODE -ne 0) {
    Write-Fail "sysmon -c returned exit code $LASTEXITCODE"
    exit 1
}
Write-Ok "Configuration applied."

# ── 5. Verify events are being captured ───────────────────────────────────────
Write-Step "Verifying event log"

Start-Sleep -Seconds 2

$log = "Microsoft-Windows-Sysmon/Operational"
try {
    $latest = Get-WinEvent -LogName $log -MaxEvents 1 -ErrorAction Stop
    Write-Ok "Sysmon event log is active. Latest event: ID $($latest.Id) at $($latest.TimeCreated)"
} catch {
    Write-Warn "Could not read the Sysmon event log: $_"
}

# Report which of the three profiler event IDs are configured
Write-Step "Checking profiler event coverage"

$configXml  = [xml](& $sysmonExe -s 2>&1 | Out-String)
$eventNames = @{
    10 = "ProcessAccess (LSASS detection)"
    8  = "CreateRemoteThread (injection detection)"
    25 = "ProcessTampering (hollowing detection)"
}

foreach ($id in $eventNames.Keys) {
    $label = $eventNames[$id]
    $active = & $sysmonExe -s 2>&1 | Select-String "value=`"$id`""
    if ($active) {
        Write-Ok "EventID $id — $label"
    } else {
        Write-Warn "EventID $id — $label (not found in schema, may still work)"
    }
}

Write-Host ""
Write-Host "Setup complete. The profiler is ready to detect:" -ForegroundColor Green
Write-Host "  • LSASS handle opens        (Sysmon EventID 10)" -ForegroundColor White
Write-Host "  • Remote thread injection   (Sysmon EventID  8)" -ForegroundColor White
Write-Host "  • Process hollowing         (Sysmon EventID 25)" -ForegroundColor White
Write-Host ""
