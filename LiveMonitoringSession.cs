using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading;

namespace Cyber_behaviour_profiling
{
    public sealed class MonitoringEventUpdate
    {
        public int ProcessId { get; init; }
        public string ProcessName { get; init; } = "";
        public string EventType { get; init; } = "";
        public string Category { get; init; } = "";
        public string RawData { get; init; } = "";
        public string ActivityType { get; init; } = "";
        public DateTime Timestamp { get; init; }
        public int AttemptCount { get; init; }
    }

    public sealed class RawActivityUpdate
    {
        public string ActivityType { get; init; } = "";
        public string Detail { get; init; } = "";
        public string ProcessName { get; init; } = "";
        public int ProcessId { get; init; }
        public DateTime Timestamp { get; init; }
    }

    public sealed class MonitoringSessionResult
    {
        public string TargetProcess { get; init; } = "";
        public string OverallGrade { get; init; } = "SAFE";
        public string OverallStory { get; init; } = "SAFE — No suspicious activity detected.";
        public List<AttackNarrative> Narratives { get; init; } = new();
        public List<ProcessProfile> MergedProfiles { get; init; } = new();
    }

    public sealed class LiveMonitoringSession : IDisposable
    {
        private readonly object _sync = new();
        private readonly HashSet<uint> _monitoredPids = new();

        private TraceEventSession? _userSession;
        private TraceEventSession? _dnsSession;
        private TraceEventSession? _kernelSession;
        private TraceEventSession? _psSession;
        private EventLogWatcher? _sysmonWatcher;
        private Thread? _userThread;
        private Thread? _dnsThread;
        private Thread? _kernelThread;
        private Thread? _psThread;
        private string _targetProcess = "";
        private bool _isRunning;
        private bool _powerShellLoggingEnabled;
        private Timer? _snapshotTimer;
        private DirectorySnapshot? _baselineSnapshot;

        public event Action<MonitoringEventUpdate>? EventObserved;
        public event Action<RawActivityUpdate>? ActivityObserved;

        public bool IsRunning
        {
            get
            {
                lock (_sync)
                    return _isRunning;
            }
        }

        public void Start(string targetProcess, string dataFilePath, bool enablePowerShellLogging = false)
        {
            if (string.IsNullOrWhiteSpace(targetProcess))
                throw new ArgumentException("A process name is required.", nameof(targetProcess));

            if (!File.Exists(dataFilePath))
                throw new FileNotFoundException("Could not find data.json for the monitoring rules.", dataFilePath);

            lock (_sync)
            {
                if (_isRunning)
                    throw new InvalidOperationException("Monitoring is already running.");

                _targetProcess = Path.GetFileNameWithoutExtension(targetProcess.Trim()).ToLowerInvariant();
                _monitoredPids.Clear();
                foreach (var process in Process.GetProcessesByName(_targetProcess))
                    _monitoredPids.Add((uint)process.Id);

                _powerShellLoggingEnabled = enablePowerShellLogging;

                MapToData.ResetSession();
                MapToData.LoadData(dataFilePath);
                MapToData.SuspiciousEventObserved += OnSuspiciousEventObserved;

                try
                {
                    var monitoredDirs = SystemDiscovery.GetMonitoredDirectories(
                        MapToData.SensitiveDirs as IReadOnlyList<string>);
                    _baselineSnapshot = SystemDiscovery.TakeDirectorySnapshot(monitoredDirs);
                }
                catch (Exception ex)
                {
                    _baselineSnapshot = null;
                }

                StartSysmonWatcher();
                StartEtwSessions();
                _snapshotTimer = new Timer(_ => MapToData.TakeAnomalySnapshot(), null, 2000, 2000);
                _isRunning = true;
            }
        }

        public MonitoringSessionResult Stop()
        {
            lock (_sync)
            {
                if (!_isRunning)
                    return BuildResult();

                _isRunning = false;
            }

            MapToData.SuspiciousEventObserved -= OnSuspiciousEventObserved;

            try { _snapshotTimer?.Dispose(); } catch { }
            _snapshotTimer = null;

            try
            {
                if (_sysmonWatcher != null)
                {
                    _sysmonWatcher.Enabled = false;
                    _sysmonWatcher.EventRecordWritten -= SysmonWatcher_EventRecordWritten;
                    _sysmonWatcher.Dispose();
                }
            }
            catch { }

            StopSession(_kernelSession, _kernelThread);
            StopSession(_userSession, _userThread);
            StopSession(_dnsSession, _dnsThread);
            StopSession(_psSession, _psThread);

            _sysmonWatcher = null;
            _kernelSession = null;
            _userSession = null;
            _dnsSession = null;
            _psSession = null;
            _kernelThread = null;
            _userThread = null;
            _dnsThread = null;
            _psThread = null;

            return BuildResult();
        }

        public void Dispose()
        {
            Stop();
        }

        private void StartSysmonWatcher()
        {
            string query = "*[System]";
            var eventLogQuery = new EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName, query);
            _sysmonWatcher = new EventLogWatcher(eventLogQuery);
            _sysmonWatcher.EventRecordWritten += SysmonWatcher_EventRecordWritten;
            _sysmonWatcher.Enabled = true;
        }

        private void SysmonWatcher_EventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
        {
            if (!IsRunning || e.EventRecord == null)
                return;

            ProcessSysmonEvent(e.EventRecord);
        }

        private void ProcessSysmonEvent(EventRecord record)
        {
            Program.ProcessSysmonEvent(record, _targetProcess);
        }

        private void StartEtwSessions()
        {
            _userSession = new TraceEventSession($"DPAPIMonitorSession-{Guid.NewGuid():N}");
            _dnsSession = new TraceEventSession($"DNSMonitorSession-{Guid.NewGuid():N}");
            _kernelSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName);

            _userSession.EnableProvider(
                new Guid("89fe8f40-cdce-464e-8217-15ef97d4c7c3"),
                Microsoft.Diagnostics.Tracing.TraceEventLevel.Verbose);

            _userSession.Source.Dynamic.All += UserSource_All;

            _dnsSession.EnableProvider("Microsoft-Windows-DNS-Client");
            _dnsSession.Source.Dynamic.All += DnsSource_All;

            _kernelSession.EnableKernelProvider(
                KernelTraceEventParser.Keywords.FileIO |
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.Registry |
                KernelTraceEventParser.Keywords.DiskFileIO |
                KernelTraceEventParser.Keywords.NetworkTCPIP);

            _kernelSession.Source.Kernel.FileIOWrite += data =>
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
                {
                    FireActivity("File Write", data.FileName ?? "", data.ProcessName ?? "", data.ProcessID);
                    MapToData.EvaluateFileOperation(data.ProcessID, data.ProcessName ?? "", data.FileName ?? "", "FileWrite");
                }
            };

            _kernelSession.Source.Kernel.FileIOCreate += data =>
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID) && !string.IsNullOrEmpty(data.FileName))
                {
                    FireActivity("File Open", data.FileName, data.ProcessName ?? "", data.ProcessID);
                    MapToData.EvaluateFileOperation(data.ProcessID, data.ProcessName ?? "", data.FileName, "FileOpen");
                }
            };

            _kernelSession.Source.Kernel.FileIORead += data =>
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID) && !string.IsNullOrEmpty(data.FileName))
                    MapToData.EvaluateFileOperation(data.ProcessID, data.ProcessName ?? "", data.FileName, "FileRead");
            };

            _kernelSession.Source.Kernel.FileIODelete += data =>
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
                {
                    FireActivity("File Delete", data.FileName ?? "", data.ProcessName ?? "", data.ProcessID);
                    MapToData.EvaluateFileOperation(data.ProcessID, data.ProcessName ?? "", data.FileName ?? "", "FileDelete");
                }
            };

            _kernelSession.Source.Kernel.FileIORename += data =>
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
                {
                    FireActivity("File Rename", data.FileName ?? "", data.ProcessName ?? "", data.ProcessID);
                    MapToData.EvaluateFileOperation(data.ProcessID, data.ProcessName ?? "", data.FileName ?? "", "FileRename");
                }
            };

            _kernelSession.Source.Kernel.RegistryCreate += data =>
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
                {
                    FireActivity("Registry", data.KeyName ?? "", data.ProcessName ?? "", data.ProcessID);
                    MapToData.EvaluateRegistryAccess(data.ProcessID, data.ProcessName ?? "", data.KeyName ?? "", "Create");
                }
            };

            _kernelSession.Source.Kernel.RegistryOpen += data =>
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
                    MapToData.EvaluateRegistryAccess(data.ProcessID, data.ProcessName ?? "", data.KeyName ?? "", "Open");
            };

            _kernelSession.Source.Kernel.RegistrySetValue += data =>
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
                {
                    FireActivity("Registry", data.KeyName ?? "", data.ProcessName ?? "", data.ProcessID);
                    MapToData.EvaluateRegistryAccess(data.ProcessID, data.ProcessName ?? "", data.KeyName ?? "", "SetValue");
                }
            };

            _kernelSession.Source.Kernel.TcpIpConnect += data =>
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
                {
                    string ip = data.daddr?.ToString() ?? "";
                    string displayAddr = MapToData._recentDnsQueries.TryGetValue(data.ProcessID, out string? domain)
                        ? domain
                        : ip;
                    FireActivity("Network", displayAddr, data.ProcessName ?? "", data.ProcessID);
                    MapToData.EvaluateNetworkConnection(data.ProcessID, data.ProcessName ?? "", ip);
                }
            };

            _kernelSession.Source.Kernel.ProcessStart += data =>
            {
                if (_monitoredPids.Contains((uint)data.ParentID))
                {
                    _monitoredPids.Add((uint)data.ProcessID);

                    string childName = !string.IsNullOrEmpty(data.ImageFileName)
                        ? Path.GetFileName(data.ImageFileName)
                        : (data.ProcessName ?? "unknown");

                    string childLower = Path.GetFileNameWithoutExtension(childName).ToLowerInvariant();
                    if (childLower == "conhost")
                        return;

                    FireActivity("Process", $"{childName} {data.CommandLine ?? ""}".Trim(), childName, data.ProcessID);
                    MapToData.EvaluateProcessSpawn(data.ParentID, _targetProcess, data.ProcessID, childName, data.CommandLine ?? "");
                }
            };

            _userThread = new Thread(() => _userSession.Source.Process()) { IsBackground = true };
            _dnsThread = new Thread(() => _dnsSession.Source.Process()) { IsBackground = true };
            _kernelThread = new Thread(() => _kernelSession.Source.Process()) { IsBackground = true };

            _userThread.Start();
            _dnsThread.Start();
            _kernelThread.Start();

            if (_powerShellLoggingEnabled)
                StartPowerShellSession();
        }

        private void StartPowerShellSession()
        {
            _psSession = new TraceEventSession($"PSMonitorSession-{Guid.NewGuid():N}");
            _psSession.EnableProvider("Microsoft-Windows-PowerShell",
                Microsoft.Diagnostics.Tracing.TraceEventLevel.Verbose,
                ulong.MaxValue);

            _psSession.Source.Dynamic.All += data =>
            {
                if (!IsRunning) return;
                if ((int)data.ID != 4104) return;
                if (!ShouldMonitor(data.ProcessName, (uint)data.ProcessID)) return;

                try
                {
                    string scriptText = "";
                    int idx = Array.IndexOf(data.PayloadNames, "ScriptBlockText");
                    if (idx >= 0)
                        scriptText = data.PayloadValue(idx)?.ToString() ?? "";

                    if (string.IsNullOrWhiteSpace(scriptText)) return;

                    string display = scriptText.Length > 300
                        ? scriptText[..300] + "..."
                        : scriptText;

                    FireActivity("PowerShell", display, data.ProcessName ?? "", data.ProcessID);
                    MapToData.AddEventToProfile(
                        data.ProcessID, data.ProcessName ?? "",
                        "PowerShell_Script", display, display,
                        "powershell_script", "PowerShell");
                }
                catch { }
            };

            _psThread = new Thread(() => _psSession.Source.Process()) { IsBackground = true };
            _psThread.Start();
        }

        [SupportedOSPlatform("windows")]
        public static bool IsScriptBlockLoggingEnabled()
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging");
            return key?.GetValue("EnableScriptBlockLogging") is int v && v == 1;
        }

        [SupportedOSPlatform("windows")]
        public static void EnableScriptBlockLogging()
        {
            using var key = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging");
            key.SetValue("EnableScriptBlockLogging", 1, RegistryValueKind.DWord);
        }

        private void UserSource_All(Microsoft.Diagnostics.Tracing.TraceEvent data)
        {
            if (!IsRunning) return;

            if (data.ProviderGuid == new Guid("89fe8f40-cdce-464e-8217-15ef97d4c7c3") &&
                ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
            {
                FireActivity("Credential Access", data.EventName ?? "", data.ProcessName ?? "Unknown", data.ProcessID);
                MapToData.AddEventToProfile(
                    data.ProcessID,
                    data.ProcessName ?? "Unknown",
                    "DPAPI_Decrypt",
                    "dpapi_decrypt",
                    data.EventName ?? "",
                    "dpapi_decrypt",
                    "DPAPI");
            }
        }

        private void DnsSource_All(Microsoft.Diagnostics.Tracing.TraceEvent dnsData)
        {
            if (!IsRunning) return;

            if (!dnsData.EventName.Contains("Query", StringComparison.OrdinalIgnoreCase) &&
                dnsData.EventName != "EventID(3008)")
                return;

            try
            {
                string queriedDomain = "";
                if (Array.IndexOf(dnsData.PayloadNames, "QueryName") >= 0)
                {
                    queriedDomain = ((string)dnsData.PayloadValue(
                        dnsData.PayloadIndex("QueryName")))?.ToLowerInvariant() ?? "";
                }

                if (string.IsNullOrEmpty(queriedDomain)) return;

                MapToData._recentDnsQueries[dnsData.ProcessID] = queriedDomain;

                if (!ShouldMonitor(dnsData.ProcessName, (uint)dnsData.ProcessID))
                    return;

                FireActivity("DNS", queriedDomain, dnsData.ProcessName ?? "Unknown", dnsData.ProcessID);

                if (MapToData._networkDomains.Contains(queriedDomain))
                {
                    MapToData.AddEventToProfile(
                        dnsData.ProcessID,
                        dnsData.ProcessName ?? "Unknown",
                        "DNS_Query",
                        queriedDomain,
                        queriedDomain,
                        "dns_c2",
                        "DNS");
                }
            }
            catch { }
        }

        private bool ShouldMonitor(string? processName, uint pid)
        {
            if (_monitoredPids.Contains(pid)) return true;
            if (string.IsNullOrEmpty(processName)) return false;
            string lower = processName.ToLowerInvariant();
            if (lower == _targetProcess || lower == _targetProcess + ".exe")
            {
                _monitoredPids.Add(pid);
                return true;
            }
            return false;
        }

        private void OnSuspiciousEventObserved(MonitoringEventUpdate update)
        {
            EventObserved?.Invoke(update);
        }

        private void FireActivity(string activityType, string detail, string processName, int pid)
        {
            if (string.IsNullOrEmpty(detail)) return;
            if (IsNoisePath(activityType, detail)) return;

            ActivityObserved?.Invoke(new RawActivityUpdate
            {
                ActivityType = activityType,
                Detail = detail,
                ProcessName = processName,
                ProcessId = pid,
                Timestamp = DateTime.Now
            });
        }

        private static bool IsNoisePath(string activityType, string detail)
        {
            string lower = detail.ToLowerInvariant();

            if (lower.StartsWith("\\device\\") || lower.StartsWith("\\??\\pipe\\"))
                return true;

            if (activityType.StartsWith("File"))
            {
                string ext = Path.GetExtension(lower);
                if (ext is ".dll" or ".sys" or ".pnf" or ".mui" or ".nls" or ".dat"
                        or ".ttf" or ".otf" or ".ttc" or ".cat" or ".manifest"
                        or ".etl" or ".log" or ".blf" or ".regtrans-ms")
                    return true;

                if (lower.Contains("\\windows\\system32\\") ||
                    lower.Contains("\\windows\\syswow64\\") ||
                    lower.Contains("\\windows\\winsxs\\") ||
                    lower.Contains("\\windows\\fonts\\") ||
                    lower.Contains("\\windows\\globalization\\") ||
                    lower.Contains("\\windows\\assembly\\") ||
                    lower.Contains("\\windows\\microsoft.net\\") ||
                    lower.Contains("\\windows\\installer\\"))
                    return true;

                if (lower.Contains("\\.nuget\\") ||
                    lower.Contains("\\assembly\\nativeimages") ||
                    lower.Contains("\\microsoft\\clr_"))
                    return true;
            }

            if (activityType == "Registry")
            {
                if (lower.Contains("\\software\\classes\\") ||
                    lower.Contains("\\software\\microsoft\\windows\\currentversion\\explorer\\") ||
                    lower.Contains("\\software\\microsoft\\windows nt\\currentversion\\fontsubstitutes") ||
                    lower.Contains("\\software\\microsoft\\windows nt\\currentversion\\gre_initialize") ||
                    lower.Contains("\\software\\policies\\") ||
                    lower.Contains("\\control panel\\desktop\\") ||
                    lower.Contains("\\currentcontrolset\\control\\nls\\") ||
                    lower.Contains("\\currentcontrolset\\control\\session manager\\") ||
                    lower.Contains("\\environment") ||
                    lower.Contains("\\.default\\") ||
                    lower.Contains("\\volatile environment"))
                    return true;
            }

            return false;
        }

        private MonitoringSessionResult BuildResult()
        {
            var mergedProfiles = MapToData.GetMergedProfiles();
            var narratives = mergedProfiles
                .Select(profile =>
                {
                    profile.DirectorySnapshotBefore = _baselineSnapshot;
                    var report = BehaviorAnalyzer.Analyze(profile);
                    return AttackNarrator.BuildNarrative(profile, report);
                })
                .OrderByDescending(n => GradeRank(n.Grade))
                .ThenByDescending(n => n.TotalSeconds)
                .ToList();

            var top = narratives.FirstOrDefault();
            return new MonitoringSessionResult
            {
                TargetProcess = _targetProcess,
                OverallGrade = top?.Grade ?? "SAFE",
                OverallStory = top?.OverallStory ?? "SAFE — No suspicious activity detected.",
                Narratives = narratives,
                MergedProfiles = mergedProfiles
            };
        }

        private static void StopSession(TraceEventSession? session, Thread? thread)
        {
            try { session?.Stop(); } catch { }
            try
            {
                if (thread != null && thread.IsAlive)
                    thread.Join(1500);
            }
            catch { }
            try { session?.Dispose(); } catch { }
        }

        private static int GradeRank(string grade) => grade switch
        {
            "MALICIOUS" => 4,
            "SUSPICIOUS" => 3,
            "INCONCLUSIVE" => 2,
            _ => 1
        };
    }
}