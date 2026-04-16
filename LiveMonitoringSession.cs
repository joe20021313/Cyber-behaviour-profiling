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
using System.Xml;

namespace Cyber_behaviour_profiling
{
    public class MonitoringEventUpdate
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

    public class RawActivityUpdate
    {
        public string ActivityType { get; init; } = "";
        public string Detail { get; init; } = "";
        public string ProcessName { get; init; } = "";
        public string TargetProcess { get; init; } = "";
        public int ProcessId { get; init; }
        public DateTime Timestamp { get; init; }
    }

    public class MonitoringSessionResult
    {
        public List<string> TargetProcesses { get; init; } = new();
        public string TargetProcess => string.Join(", ", TargetProcesses);
        public string OverallGrade { get; init; } = "SAFE";
        public string DiagnosticTrace { get; init; } = "";

        public List<AttackNarrative> Narratives { get; init; } = new();
        public List<ProcessProfile> MergedProfiles { get; init; } = new();
    }

    public class LiveMonitoringSession : IDisposable
    {
        private readonly object _sync = new();
        private readonly HashSet<uint> _monitoredPids = new();
        private readonly Dictionary<uint, string> _pidToTarget = new();

        private TraceEventSession? _userSession;
        private TraceEventSession? _dnsSession;
        private TraceEventSession? _kernelSession;
        private TraceEventSession? _psSession;
        private EventLogWatcher? _sysmonWatcher;
        private Thread? _userThread;
        private Thread? _dnsThread;
        private Thread? _kernelThread;
        private Thread? _psThread;
        private HashSet<string> _targetProcesses = new(StringComparer.OrdinalIgnoreCase);
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

        public static LiveMonitoringSession? ActiveInstance { get; private set; }

        public void Start(IEnumerable<string> targetProcesses, string dataFilePath, bool enablePowerShellLogging = false)
        {
            var targets = targetProcesses
                .Select(t => Path.GetFileNameWithoutExtension(t.Trim()).ToLowerInvariant())
                .Where(t => !string.IsNullOrEmpty(t))
                .ToList();

            if (targets.Count == 0)
                throw new ArgumentException("At least one process name is required.", nameof(targetProcesses));

            if (!File.Exists(dataFilePath))
                throw new FileNotFoundException("Could not find data.json for the monitoring rules.", dataFilePath);

            lock (_sync)
            {
                if (_isRunning)
                    throw new InvalidOperationException("Monitoring is already running.");

                _targetProcesses = new HashSet<string>(targets, StringComparer.OrdinalIgnoreCase);
                _monitoredPids.Clear();
                _pidToTarget.Clear();
                foreach (var name in _targetProcesses)
                    foreach (var process in Process.GetProcessesByName(name))
                    {
                        uint pid = (uint)process.Id;
                        _monitoredPids.Add(pid);
                        _pidToTarget[pid] = name;
                    }

                _powerShellLoggingEnabled = enablePowerShellLogging;

                MapToData.ResetSession();
                MapToData.LoadData(dataFilePath);

                string baselinePath = MapToData.ResolveBaselinePath(dataFilePath);
                MapToData.LoadBaselines(baselinePath);

                MapToData.SuspiciousEventObserved += OnSuspiciousEventObserved;

                try
                {
                    var monitoredDirs = SystemDiscovery.GetMonitoredDirectories(
                        MapToData.SensitiveDirs as IReadOnlyList<string>);
                    _baselineSnapshot = SystemDiscovery.TakeDirectorySnapshot(monitoredDirs);
                }
                catch
                {
                    _baselineSnapshot = null;
                }

                StartSysmonWatcher();
                StartEtwSessions();
                _snapshotTimer = new Timer(_ => MapToData.TakeAnomalySnapshot(), null, 1000, 1000);

                _isRunning = true;
                ActiveInstance = this;
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

            if (_sysmonWatcher != null)
            {
                _sysmonWatcher.Enabled = false;
                _sysmonWatcher.EventRecordWritten -= SysmonWatcher_EventRecordWritten;
                _sysmonWatcher.Dispose();
            }

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
            _pidToTarget.Clear();

            if (ActiveInstance == this)
                ActiveInstance = null;

            return BuildResult();
        }

        public void AddBaselineTarget(string processName)
        {
            string nameNoExt = Path.GetFileNameWithoutExtension(processName).ToLowerInvariant();
            _targetProcesses.Add(nameNoExt);

            foreach (var proc in Process.GetProcessesByName(nameNoExt))
            {
                uint pid = (uint)proc.Id;
                _monitoredPids.Add(pid);
                _pidToTarget[pid] = nameNoExt;

                MapToData.ActiveProfiles.GetOrAdd(proc.Id, id => new ProcessProfile
                {
                    ProcessId = id,
                    ProcessName = processName,
                    FirstSeen = DateTime.Now
                });
            }
        }

        public void RemoveBaselineTarget(string processName)
        {
            string nameNoExt = Path.GetFileNameWithoutExtension(processName).ToLowerInvariant();
            _targetProcesses.Remove(nameNoExt);
        }

        public void Dispose()
        {
            Stop();
        }

        private bool _isBaselineMode;
        private string? _baselineInjectedTarget;

        public void StartForBaseline(IEnumerable<string> targetProcesses, string dataFilePath)
        {
            var targets = targetProcesses
                .Select(t => Path.GetFileNameWithoutExtension(t.Trim()).ToLowerInvariant())
                .Where(t => !string.IsNullOrEmpty(t))
                .ToList();

            if (targets.Count == 0)
                throw new ArgumentException("At least one process name is required.", nameof(targetProcesses));

            MapToData.LoadData(dataFilePath);
            MapToData.LoadBaselines(MapToData.ResolveBaselinePath(dataFilePath));

            var existingSession = ActiveInstance;
            if (existingSession != null)
            {

                _baselineInjectedTarget = targets[0];
                existingSession.AddBaselineTarget(_baselineInjectedTarget);

                _snapshotTimer = new Timer(_ => MapToData.TakeAnomalySnapshot(), null, 1000, 1000);
                _isBaselineMode = true;
                _isRunning = true;
                return;
            }

            lock (_sync)
            {
                if (_isRunning)
                    throw new InvalidOperationException("Session already running.");

                _targetProcesses = new HashSet<string>(targets, StringComparer.OrdinalIgnoreCase);
                _monitoredPids.Clear();
                _pidToTarget.Clear();

                foreach (var name in _targetProcesses)
                    foreach (var process in Process.GetProcessesByName(name))
                    {
                        uint pid = (uint)process.Id;
                        _monitoredPids.Add(pid);
                        _pidToTarget[pid] = name;

                        MapToData.ActiveProfiles.GetOrAdd(process.Id, id => new ProcessProfile
                        {
                            ProcessId = id,
                            ProcessName = name + ".exe",
                            FirstSeen = DateTime.Now
                        });
                    }

                _kernelSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName);

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
                        MapToData.EvaluateFileOperation(data.ProcessID, data.ProcessName ?? "", data.FileName ?? "", "FileWrite");
                };

                _kernelSession.Source.Kernel.FileIODelete += data =>
                {
                    if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
                        MapToData.EvaluateFileOperation(data.ProcessID, data.ProcessName ?? "", data.FileName ?? "", "FileDelete");
                };

                _kernelSession.Source.Kernel.FileIORead += data =>
                {
                    if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID) &&
                        !string.IsNullOrEmpty(data.FileName))
                    {
                        MapToData.EvaluateFileOperation(data.ProcessID, data.ProcessName ?? "", data.FileName, "FileRead");
                    }
                };

                _kernelSession.Source.Kernel.ProcessStart += data =>
                {
                    string imageName = Path.GetFileName(data.ImageFileName ?? data.ProcessName ?? "").ToLowerInvariant();
                    string imageNoExt = imageName.EndsWith(".exe") ? imageName[..^4] : imageName;

                    if (_targetProcesses.Contains(imageNoExt) || _targetProcesses.Contains(imageName))
                    {
                        uint childPid = (uint)data.ProcessID;
                        _monitoredPids.Add(childPid);
                        _pidToTarget[childPid] = imageNoExt;

                        MapToData.ActiveProfiles.GetOrAdd((int)childPid, id => new ProcessProfile
                        {
                            ProcessId = id,
                            ProcessName = imageName,
                            FirstSeen = DateTime.Now
                        });
                    }
                };

                _kernelThread = new Thread(() => _kernelSession.Source.Process()) { IsBackground = true };
                _kernelThread.Start();

                _snapshotTimer = new Timer(_ => MapToData.TakeAnomalySnapshot(), null, 1000, 1000);

                _isBaselineMode = true;
                _isRunning = true;
            }
        }

        public void StopBaseline()
        {
            lock (_sync)
            {
                if (!_isRunning) return;
                _isRunning = false;
            }

            try { _snapshotTimer?.Dispose(); } catch { }
            _snapshotTimer = null;

            if (_baselineInjectedTarget != null)
            {
                ActiveInstance?.RemoveBaselineTarget(_baselineInjectedTarget);
                _baselineInjectedTarget = null;
            }
            else
            {

                StopSession(_kernelSession, _kernelThread);
                _kernelSession = null;
                _kernelThread = null;
            }

            _pidToTarget.Clear();
            _isBaselineMode = false;
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
            try
            {
                string xml = record.ToXml();
                var doc = new XmlDocument();
                doc.LoadXml(xml);

                var eventId = record.Id;
                var nsMgr = new XmlNamespaceManager(doc.NameTable);
                nsMgr.AddNamespace("ns", "http://schemas.microsoft.com/win/2004/08/events/event");

                var imageNode = doc.SelectSingleNode("//ns:Data[@Name='Image']", nsMgr);
                string image = imageNode?.InnerText?.ToLower() ?? "";
                if (!_targetProcesses.Any(t => image.Contains(t))) return;

                var dataNodes = doc.SelectNodes("//ns:Data", nsMgr);
                string destinationHostname = "";
                string targetImage = "";
                int pid = 0;
                foreach (XmlNode node in dataNodes)
                {
                    string name = node.Attributes?["Name"]?.Value ?? "";
                    string value = node.InnerText;
                    if (name == "DestinationHostname") destinationHostname = value;
                    if (name == "TargetImage") targetImage = value.ToLower();
                    if (name == "ProcessId" && int.TryParse(value, out int parsedPid)) pid = parsedPid;
                }

                if (eventId == 3 && !string.IsNullOrEmpty(destinationHostname))
                    MapToData.EvaluateNetworkConnection(pid, image, destinationHostname);

                if (eventId == 10 && targetImage.Contains("lsass"))
                    MapToData.AddEventToProfile(pid, image, "LsassAccess", "lsass.exe", targetImage, "lsass_access", "Sysmon");

                if (eventId == 8 && !string.IsNullOrEmpty(targetImage))
                    MapToData.AddEventToProfile(pid, image, "RemoteThreadInjection", targetImage, targetImage, "process_injection", "Sysmon");

                if (eventId == 25)
                    MapToData.AddEventToProfile(pid, image, "ProcessTampering", image, image, "process_tampering", "Sysmon");
            }
            catch { }
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
                    string displayAddr = MapToData.FormatNetworkDestination(data.ProcessID, ip, out _);
                    FireActivity("Network", displayAddr, data.ProcessName ?? "", data.ProcessID);
                    MapToData.EvaluateNetworkConnection(data.ProcessID, data.ProcessName ?? "", ip);
                }
            };

            _kernelSession.Source.Kernel.ProcessStart += data =>
            {
                if (_monitoredPids.Contains((uint)data.ParentID))
                {
                    string childImagePath = data.ImageFileName ?? "";
                    string childName = !string.IsNullOrEmpty(childImagePath)
                        ? Path.GetFileName(childImagePath)
                        : (data.ProcessName ?? "unknown");

                    string childLower = Path.GetFileNameWithoutExtension(childName).ToLowerInvariant();
                    if (childLower == "conhost")
                        return;

                    _monitoredPids.Add((uint)data.ProcessID);
                    if (_pidToTarget.TryGetValue((uint)data.ParentID, out var parentTarget))
                        _pidToTarget[(uint)data.ProcessID] = parentTarget;

                    FireActivity("Process", $"{childName} {data.CommandLine ?? ""}".Trim(), childName, data.ProcessID);
                    string parentName = MapToData.ActiveProfiles.TryGetValue(data.ParentID, out var pp)
                        ? pp.ProcessName : "unknown";
                    MapToData.EvaluateProcessSpawn(data.ParentID, parentName, data.ProcessID, childName, childImagePath, data.CommandLine ?? "");
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
            if (key != null)
            {
                var value = key.GetValue("EnableScriptBlockLogging");
                return value is int v && v == 1;
            }
            return false;
        }

        [SupportedOSPlatform("windows")]
        public static void EnableScriptBlockLogging()
        {
            using var key = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging");
            key.SetValue("EnableScriptBlockLogging", 1, RegistryValueKind.DWord);
        }

        [SupportedOSPlatform("windows")]
        public static void DisableScriptBlockLogging()
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", writable: true);
            if (key == null) return;
            key.DeleteValue("EnableScriptBlockLogging", throwOnMissingValue: false);
            var parent = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\PowerShell", writable: true);
            parent?.DeleteSubKeyTree("ScriptBlockLogging", throwOnMissingSubKey: false);
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
            string noExt = lower.EndsWith(".exe") ? lower[..^4] : lower;
            if (_targetProcesses.Contains(lower) || _targetProcesses.Contains(noExt))
            {
                _monitoredPids.Add(pid);
                string target = _targetProcesses.Contains(noExt) ? noExt : lower;
                _pidToTarget[pid] = target;
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
            if (detail.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)) return;
            if (detail.StartsWith(@"\??\pipe\", StringComparison.OrdinalIgnoreCase)) return;

            string target = _pidToTarget.TryGetValue((uint)pid, out var t) ? t : processName;

            ActivityObserved?.Invoke(new RawActivityUpdate
            {
                ActivityType = activityType,
                Detail = detail,
                ProcessName = processName,
                TargetProcess = target,
                ProcessId = pid,
                Timestamp = DateTime.Now
            });
        }

        private MonitoringSessionResult BuildResult()
        {
            InvestigationLog.Section("Result Build");
            var analysisProfiles = MapToData.GetAnalysisProfiles();
            InvestigationLog.WriteStage("session",
                $"Building final result from {analysisProfiles.Count} collected profile(s) for {string.Join(", ", _targetProcesses.OrderBy(t => t, StringComparer.OrdinalIgnoreCase))}.");

            var profileNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in analysisProfiles)
                profileNames.Add(p.ProcessName?.ToLowerInvariant() ?? "");

            foreach (var target in _targetProcesses)
            {
                if (!profileNames.Contains(target))
                {
                    analysisProfiles.Add(new ProcessProfile
                    {
                        ProcessId = 0,
                        ProcessName = target,
                        FirstSeen = DateTime.Now,
                    });
                }
            }

            var narratives = new List<AttackNarrative>();
            foreach (var profile in analysisProfiles)
            {
                profile.DirectorySnapshotBefore = _baselineSnapshot;
                InvestigationLog.WriteStage("session",
                    $"Finalizing profile pid={profile.ProcessId} process='{profile.ProcessName}' events={profile.EventTimeline.Count}.");
                var report = BehaviorAnalyzer.Analyze(profile);
                var narrative = AttackNarrator.BuildNarrative(profile, report);
                InvestigationLog.WriteStage("session",
                    $"Narrative built pid={profile.ProcessId} process='{profile.ProcessName}' grade={narrative.Grade} steps={narrative.Timeline.Count} reasons={narrative.DecisionReasons.Count}.");
                narratives.Add(narrative);
            }

            narratives.Sort((a, b) =>
            {
                int gradeCompare = GradeRank(b.Grade).CompareTo(GradeRank(a.Grade));
                if (gradeCompare != 0) return gradeCompare;
                return b.TotalSeconds.CompareTo(a.TotalSeconds);
            });

            AttackNarrative top = narratives.Count > 0 ? narratives[0] : null;
            string overallGrade = top?.Grade ?? "SAFE";
            InvestigationLog.EndSession(overallGrade, analysisProfiles.Count, narratives.Count);
            string diagnosticTrace = InvestigationLog.GetContents();

            return new MonitoringSessionResult
            {
                TargetProcesses = _targetProcesses.ToList(),
                OverallGrade = overallGrade,
                DiagnosticTrace = diagnosticTrace,

                Narratives = narratives,
                MergedProfiles = analysisProfiles
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