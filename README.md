# Cyber Behaviour Profiler

A Windows process behaviour analysis tool that monitors running processes in real time, builds behavioural baselines, and detects anomalous or malicious activity using KNN-based anomaly detection and semantic rule matching.

---

## Requirements

### Operating System
- Windows 10 or Windows 11 (64-bit)

### .NET SDK
- **.NET 10 SDK** — required to build and run the main profiler
- **.NET 8 SDK** — required to build TestApp only

Download from: https://dotnet.microsoft.com/download

### Administrator privileges
The profiler must be run as Administrator. It uses ETW (Event Tracing for Windows) kernel sessions which require elevated access.

---

## Dependencies

### 1. Sysmon

Sysmon is a Windows system service that logs detailed process activity to the Windows Event Log. The profiler reads from it to detect:

- LSASS handle opens (credential theft)
- Remote thread injection
- Process hollowing

**Install Sysmon automatically** by running the included setup script from an elevated PowerShell prompt:

```powershell
.\Setup-Sysmon.ps1
```

This will download Sysmon from Microsoft Sysinternals, install it, and apply the profiler's detection rules from `sysmon-profiler.xml`.

If you already have Sysmon installed, point the script at your existing binary:

```powershell
.\Setup-Sysmon.ps1 -SysmonPath "C:\Tools\Sysmon64.exe"
```

> If Sysmon is not installed, LSASS and injection detections will not fire. The profiler will still work for all other detections.

---

### 2. PowerShell Script Block Logging

The profiler monitors PowerShell activity via ETW. To enable script block logging so that PowerShell commands are captured:

1. Open **Group Policy Editor** (`gpedit.msc`) as Administrator
2. Navigate to: `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`
3. Enable **Turn on PowerShell Script Block Logging**

Or enable it via registry (run as Administrator):

```powershell
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1
```

> Without this, PowerShell-based attack detections (encoded commands, download cradles) will not fire.

---

### 3. Microsoft-Windows-Crypto-DPAPI ETW Provider

DPAPI decryption monitoring is built in — no installation required. The profiler subscribes to the `Microsoft-Windows-Crypto-DPAPI` ETW provider automatically when it starts.

---

## Building

From the repository root in an elevated PowerShell or Command Prompt:

```powershell
dotnet build
```

To build TestApp separately:

```powershell
dotnet build TestApp/TestApp.csproj
```

---

## Running

Run the profiler from an **elevated** PowerShell or Command Prompt:

```powershell
dotnet run
```

The profiler will start monitoring all running processes immediately. Baselines are loaded from `baselines.json` if present.

---

## Running Tests

```powershell
dotnet test CyberProfiler.Tests/CyberProfiler.Tests.csproj
```

To run a specific test class:

```powershell
dotnet test CyberProfiler.Tests --filter "FullyQualifiedName~KnnDetectorTests"
dotnet test CyberProfiler.Tests --filter "FullyQualifiedName~StandardDeviationKnnTests"
dotnet test CyberProfiler.Tests --filter "FullyQualifiedName~BehaviorAnalyzerValidDataTests"
```

---

## Recording a Baseline

A baseline is a recording of what a specific process looks like when running normally. The profiler uses it to detect when that process starts behaving differently.

1. Run the profiler while the target process is running normally
2. Select the process and start a baseline recording session
3. The baseline is saved to `baselines.json`

Once a baseline exists for a process, the KNN anomaly detector will use it as the reference for future sessions.

---

## Sysmon Configuration

The included `sysmon-profiler.xml` configures Sysmon to log exactly the events the profiler needs:

| Sysmon Event ID | What it detects |
|---|---|
| 10 | ProcessAccess — LSASS handle opens |
| 8 | CreateRemoteThread — injection into other processes |
| 25 | ProcessTampering — process hollowing |

Known noisy system processes (WMI, VirtualBox, VMware Tools) are excluded to reduce false positives.

To re-apply the config after making changes:

```powershell
Sysmon64.exe -c sysmon-profiler.xml
```
