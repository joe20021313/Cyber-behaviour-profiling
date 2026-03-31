using System;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Xml;
using System.Diagnostics;
using System.Threading;
using System.IO;
using System.Collections.Concurrent;
using System.Text.Json;
using Cyber_behaviour_profiling;

public partial class Program
{
    private static List<string> logEntries = new List<string>();
    private static object logLock = new object();
    private static Cyber_behaviour_profiling.DirectorySnapshot? _baselineSnapshot;

    public static void Main(string[] args)
    {
        logEntries.Add("Activity Log " + DateTime.Now);
        string targetProcess = Console.ReadLine()?.ToLower() ?? "";

        if (string.IsNullOrWhiteSpace(targetProcess))
            return;

        Console.CancelKeyPress += (sender, e) =>
        {
            e.Cancel = true;
            SaveAllLogsToFile("log.txt");
            MapToData.SaveToFile("profiles.json");

            var mergedProfiles = MapToData.ActiveProfiles.Values
                .GroupBy(p => p.ProcessName?.ToLowerInvariant() ?? "")
                .Select(g =>
                {
                    var primary = g.OrderByDescending(p => p.EventTimeline.Count).First();
                    if (g.Count() == 1) return primary;

                    var merged = new ProcessProfile
                    {
                        ProcessId   = primary.ProcessId,
                        ProcessName = primary.ProcessName,
                        FirstSeen   = g.Min(p => p.FirstSeen),
                    };
                    foreach (var p in g)
                    {
                        foreach (var ev in p.EventTimeline)
                            merged.EventTimeline.Add(ev);
                        foreach (var path in p.ExeDropPaths)
                            merged.ExeDropPaths.Add(path);
                        foreach (var path in p.DeletedPaths)
                            merged.DeletedPaths.Add(path);
                        foreach (var cmd in p.SpawnedCommandLines)
                            merged.SpawnedCommandLines.Add(cmd);
                        foreach (var kvp in p.WriteDirectories)
                            merged.WriteDirectories.AddOrUpdate(kvp.Key, kvp.Value, (_, c) => c + kvp.Value);
                        Interlocked.Add(ref merged.TotalFileWrites, p.TotalFileWrites);
                        Interlocked.Add(ref merged.TotalFileDeletes, p.TotalFileDeletes);
                        merged.AnomalyHistory.AddRange(p.AnomalyHistory);
                    }
                    return merged;
                })
                .OrderByDescending(p => p.EventTimeline.Count);

            foreach (var profile in mergedProfiles)
            {
                profile.DirectorySnapshotBefore = _baselineSnapshot;
                var finalReport = BehaviorAnalyzer.Analyze(profile);
                var narrative   = AttackNarrator.BuildNarrative(profile, finalReport);
                AttackNarrator.PrintNarrative(narrative);
            }

            try
            {
                string metadataText = MetadataExporter.Generate(mergedProfiles.ToList());
                string metadataPath = Path.Combine(AppContext.BaseDirectory, "lifecycle_metadata.txt");
                File.WriteAllText(metadataPath, metadataText, System.Text.Encoding.UTF8);
            }
            catch { }

            Environment.Exit(0);
        };

        Thread workerThread = new Thread(new ThreadStart(() => MonitorSysmon(targetProcess)));
        workerThread.Start();
        Thread workerThread1 = new Thread(new ThreadStart(() => MonitorProcess(targetProcess)));
        workerThread1.Start();
    }

    public static void MonitorSysmon(string targetProcess)
    {
        string query = "*[System]";
        var eventLogQuery = new EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName, query);
        using (var watcher = new EventLogWatcher(eventLogQuery))
        {
            watcher.EventRecordWritten += (sender, e) =>
            {
                if (e.EventRecord != null)
                    ProcessSysmonEvent(e.EventRecord, targetProcess);
            };

            watcher.Enabled = true;
            while (true) Thread.Sleep(1000);
        }
    }

    public static void ProcessSysmonEvent(EventRecord record, string targetProcess)
    {
        try
        {
            string xml = record.ToXml();
            var doc = new XmlDocument();
            doc.LoadXml(xml);

            var eventId = record.Id;
            var nsMgr = new XmlNamespaceManager(doc.NameTable);
            nsMgr.AddNamespace("ns", "http://schemas.microsoft.com/win/2004/08/events/event");

            var imageNode = doc.SelectSingleNode("
            string image = imageNode?.InnerText?.ToLower() ?? "";
            if (!image.Contains(targetProcess)) return;

            var dataNodes = doc.SelectNodes("
            string destinationHostname = "";
            int pid = 0;
            foreach (XmlNode node in dataNodes)
            {
                string name = node.Attributes?["Name"]?.Value ?? "";
                string value = node.InnerText;
                if (name == "DestinationHostname") destinationHostname = value;
                if (name == "ProcessId" && int.TryParse(value, out int parsedPid)) pid = parsedPid;
            }

            if (eventId == 3 && !string.IsNullOrEmpty(destinationHostname))
            {
                AddLogEntry($"Sysmon Network | {image} | PID: {pid} | Dest: {destinationHostname}");
                MapToData.EvaluateNetworkConnection(pid, image, destinationHostname);
            }
        }
        catch { }
    }

    static string GetEventName(int eventId) => eventId switch
    {
        1  => "ProcessCreate",
        3  => "NetworkConnect",
        10 => "ProcessAccess",
        11 => "FileCreate",
        23 => "FileDelete",
        _  => $"Event {eventId}"
    };

    public static void MonitorProcess(string targetProcess)
    {
        MapToData.LoadData("data.json");

        try
        {
            Cyber_behaviour_profiling.InvestigationLog.Section("CONSOLE SESSION START — BASELINE SNAPSHOT");
            var monitoredDirs = Cyber_behaviour_profiling.SystemDiscovery.GetMonitoredDirectories(
                MapToData.SensitiveDirs as IReadOnlyList<string>);
            _baselineSnapshot = Cyber_behaviour_profiling.SystemDiscovery.TakeDirectorySnapshot(monitoredDirs);
        }
        catch (Exception ex)
        {
            Cyber_behaviour_profiling.InvestigationLog.Write($"Baseline snapshot failed: {ex.Message}");
        }

        var monitoredPids = new HashSet<uint>();
        foreach (var p in Process.GetProcessesByName(targetProcess))
            monitoredPids.Add((uint)p.Id);

        bool ShouldMonitor(string processName, uint pid) =>
            processName?.ToLower().Contains(targetProcess) == true || monitoredPids.Contains(pid);

        using var userSession = new TraceEventSession("DPAPIMonitorSession");
        using var dnsSession  = new TraceEventSession("DNSMonitorSession");
        using var session     = new TraceEventSession(KernelTraceEventParser.KernelSessionName);

        userSession.EnableProvider(
            new Guid("89fe8f40-cdce-464e-8217-15ef97d4c7c3"),
            Microsoft.Diagnostics.Tracing.TraceEventLevel.Verbose);

        userSession.Source.Dynamic.All += data =>
        {
            if (data.ProviderGuid == new Guid("89fe8f40-cdce-464e-8217-15ef97d4c7c3"))
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
                {
                    AddLogEntry($"[DPAPI] {data.ProcessName} PID:{data.ProcessID} Event:{data.EventName}");

                    MapToData.AddEventToProfile(
                        data.ProcessID, data.ProcessName ?? "Unknown",
                        "DPAPI_Decrypt", "dpapi_decrypt", data.EventName ?? "", "dpapi_decrypt");
                }
            }
        };

        dnsSession.EnableProvider("Microsoft-Windows-DNS-Client");
        dnsSession.Source.Dynamic.All += dnsData =>
        {
            if (dnsData.EventName.Contains("Query", StringComparison.OrdinalIgnoreCase)
                || dnsData.EventName == "EventID(3008)")
            {
                try
                {
                    string queriedDomain = "";
                    if (Array.IndexOf(dnsData.PayloadNames, "QueryName") >= 0)
                        queriedDomain = ((string)dnsData.PayloadValue(
                            dnsData.PayloadIndex("QueryName")))?.ToLowerInvariant() ?? "";

                    if (!string.IsNullOrEmpty(queriedDomain))
                    {
                        MapToData._recentDnsQueries[dnsData.ProcessID] = queriedDomain;

                        if (MapToData._networkDomains.Contains(queriedDomain))
                        {
                            MapToData.AddEventToProfile(
                                dnsData.ProcessID, dnsData.ProcessName ?? "Unknown",
                                "DNS_Query", queriedDomain,
                                queriedDomain, "dns_c2");
                        }
                    }
                }
                catch { }
            }
        };

        Console.CancelKeyPress += (sender, e) =>
        {
            session.Stop();
            userSession.Stop();
            dnsSession.Stop();
        };

        session.EnableKernelProvider(
            KernelTraceEventParser.Keywords.FileIO     |
            KernelTraceEventParser.Keywords.Process    |
            KernelTraceEventParser.Keywords.FileIOInit |
            KernelTraceEventParser.Keywords.Registry   |
            KernelTraceEventParser.Keywords.DiskFileIO |
            KernelTraceEventParser.Keywords.NetworkTCPIP);

        session.Source.Kernel.FileIOWrite += data =>
        {
            if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
            {
                AddLogEntry($"FileWrite | {data.ProcessName} | {data.FileName} | {data.IoSize}b");
                MapToData.EvaluateFileOperation(data.ProcessID, data.ProcessName ?? "", data.FileName ?? "", "FileWrite");
            }
        };

        session.Source.Kernel.FileIOCreate += data =>
        {
            if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
            {
                if (string.IsNullOrEmpty(data.FileName)) return;
                MapToData.EvaluateFileOperation(data.ProcessID, data.ProcessName, data.FileName, "FileOpen");
                ConsoleSummarizer.TrackFileAccess(data.ProcessID, data.ProcessName, data.FileName, "Open");
            }
        };

        session.Source.Kernel.FileIORead += data =>
        {
            if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
            {
                if (string.IsNullOrEmpty(data.FileName)) return;
                MapToData.EvaluateFileOperation(data.ProcessID, data.ProcessName, data.FileName, "FileRead");
                ConsoleSummarizer.TrackFileAccess(data.ProcessID, data.ProcessName, data.FileName, "Read");
            }
        };

        session.Source.Kernel.FileIODelete += data =>
        {
            if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
            {
                AddLogEntry($"FileDelete | {data.ProcessName} | {data.FileName}");
                MapToData.EvaluateFileOperation(data.ProcessID, data.ProcessName ?? "", data.FileName ?? "", "FileDelete");
            }
        };

        session.Source.Kernel.FileIORename += data =>
        {
            if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
            {
                AddLogEntry($"FileRename | {data.ProcessName} | {data.FileName}");
                MapToData.EvaluateFileOperation(data.ProcessID, data.ProcessName ?? "", data.FileName ?? "", "FileRename");
            }
        };

        session.Source.Kernel.RegistryCreate += data =>
        {
            if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
            {
                MapToData.EvaluateRegistryAccess(data.ProcessID, data.ProcessName ?? "", data.KeyName ?? "", "Create");
                ConsoleSummarizer.TrackRegistryAccess(data.ProcessID, data.ProcessName, data.KeyName, "Create");
            }
        };

        session.Source.Kernel.RegistryOpen += data =>
        {
            if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
            {
                MapToData.EvaluateRegistryAccess(data.ProcessID, data.ProcessName ?? "", data.KeyName ?? "", "Open");
                ConsoleSummarizer.TrackRegistryAccess(data.ProcessID, data.ProcessName, data.KeyName, "Open");
            }
        };

        session.Source.Kernel.RegistrySetValue += data =>
        {
            if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
            {
                MapToData.EvaluateRegistryAccess(data.ProcessID, data.ProcessName ?? "", data.KeyName ?? "", "SetValue");
                ConsoleSummarizer.TrackRegistryAccess(data.ProcessID, data.ProcessName, data.KeyName, "Write");
            }
        };

        session.Source.Kernel.TcpIpConnect += data =>
        {
            if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
            {
                string msg = $"[NET] {data.ProcessName} → {data.daddr}:{data.dport}";
                AddLogEntry(msg);
                MapToData.EvaluateNetworkConnection(data.ProcessID, data.ProcessName ?? "", data.daddr?.ToString() ?? "");
            }
        };

        session.Source.Kernel.ProcessStart += data =>
        {
            if (monitoredPids.Contains((uint)data.ParentID))
            {
                monitoredPids.Add((uint)data.ProcessID);
                AddLogEntry($"SPAWN: {targetProcess} -> {data.ImageFileName} [{data.CommandLine}]");
                MapToData.EvaluateProcessSpawn(data.ParentID, targetProcess, data.ProcessID, data.ProcessName ?? "", data.CommandLine ?? "");
            }
        };

        Thread dpapiThread = new Thread(() => userSession.Source.Process()) { IsBackground = true };
        dpapiThread.Start();

        Thread dnsThread = new Thread(() => dnsSession.Source.Process()) { IsBackground = true };
        dnsThread.Start();

        session.Source.Process();
    }

    private static void AddLogEntry(string entry)
    {
        lock (logLock) { logEntries.Add(entry); }
    }

    private static void SaveAllLogsToFile(string fileName)
    {
        lock (logLock)
        {
            if (logEntries.Count == 0) return;
            string logPath = Path.Combine(Directory.GetCurrentDirectory(), fileName);
            try { File.WriteAllLines(logPath, logEntries); }
            catch { }
        }
    }
}

public class MappedRule
{
    public string Pattern     { get; set; } = "";
    public string Category    { get; set; } = "";
    public string Description { get; set; } = "";
}

public class NamedIndicator
{
    public string name        { get; set; } = "";
    public string description { get; set; } = "";
}

public class CommandIndicator
{
    public string pattern     { get; set; } = "";
    public string description { get; set; } = "";
}

public class SuspiciousEvent
{
    public DateTime Timestamp        { get; set; }
    public DateTime LastSeen         { get; set; }
    public string   Tactic           { get; set; }
    public string   TechniqueId      { get; set; }
    public string   TechniqueName    { get; set; }
    public string   EventType        { get; set; }
    public string   MatchedIndicator { get; set; }
    public string   RawData          { get; set; }
    public int      AttemptCount     { get; set; } = 1;
}

public class ProcessProfile
{
    public int      ProcessId              { get; set; }
    public string   ProcessName            { get; set; }
    public DateTime FirstSeen              { get; set; }
    public DateTime LastAnalyzed           { get; set; } = DateTime.MinValue;
    public DateTime LastNarrativePrint     { get; set; } = DateTime.MinValue;
    public string   LastReportedSeverity   { get; set; } = "BENIGN";
    public ConcurrentBag<SuspiciousEvent>                EventTimeline { get; set; } = new();
    public ConcurrentDictionary<string, SuspiciousEvent> DedupCache    { get; set; } = new();
    public ConcurrentDictionary<string, int> WriteDirectories { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public ConcurrentBag<string> ExeDropPaths { get; set; } = new();
    public ConcurrentBag<string> DeletedPaths { get; set; } = new();
    public ConcurrentBag<(string ChildName, string CommandLine)> SpawnedCommandLines { get; set; } = new();
    public int TotalFileWrites;
    public int TotalFileDeletes;

    public List<double[]> AnomalyHistory { get; set; } = new();
    public List<double> KnnScores { get; set; } = new();
    public int PrevFileWrites;
    public int PrevFileDeletes;
    public int PrevEventCount;
    public DateTime PrevSnapshotTime = DateTime.MinValue;

    [System.Text.Json.Serialization.JsonIgnore]
    public DirectorySnapshot? DirectorySnapshotBefore { get; set; }
}

public class FileOperationsData
{
    public List<string> sensitive_directories { get; set; }
    public List<string> sensitive_files       { get; set; }
    public List<string> uncommon_writes       { get; set; }
    public List<string> context_signals       { get; set; }
    public List<string> suspicious_overwrites { get; set; }
}

public class RegistryData
{
    public List<string> persistence       { get; set; }
    public List<string> tampering         { get; set; }
    public List<string> uac_bypass        { get; set; }
    public List<string> credential_access { get; set; }
}

public class NetworkData
{
    public List<string> suspicious_domains { get; set; }
    public List<int>    suspicious_ports   { get; set; }
}

public class ProcessesData
{
    public List<NamedIndicator>   lolbins                { get; set; }
    public List<NamedIndicator>   accessibility_binaries { get; set; }
    public List<CommandIndicator> suspicious_commands    { get; set; }
}

public class ThreatData
{
    public FileOperationsData         file_operations          { get; set; }
    public RegistryData               registry                 { get; set; }
    public NetworkData                network                  { get; set; }
    public ProcessesData              processes                { get; set; }
    public List<NamedIndicator>       discovery_commands       { get; set; }
    public Dictionary<string, int>    tactic_weights           { get; set; }
    public List<KillChainRule>        kill_chains              { get; set; }
    public ScoringConfig              scoring                  { get; set; }
    public ProcessTrustData           process_trust            { get; set; }
    public IndicatorClassification    indicator_classification { get; set; }
    public AreaWeightsConfig          area_weights             { get; set; }
    public List<ConfirmationChain>    confirmation_chains      { get; set; }
}

public class KillChainRule
{
    public string       name        { get; set; }
    public List<string> sequence    { get; set; }
    public int          bonus       { get; set; }
    public string       description { get; set; }
}

public class ScoringConfig
{
    public int low_threshold                     { get; set; }
    public int medium_threshold                  { get; set; }
    public int review_threshold                  { get; set; }
    public int high_threshold                    { get; set; }
    public int critical_threshold                { get; set; }
    public int velocity_window_seconds           { get; set; }
    public int velocity_event_threshold          { get; set; }
    public int velocity_bonus                    { get; set; }
    public int breadth_bonus_2                   { get; set; }
    public int breadth_bonus_3plus               { get; set; }
}

public class IndicatorClassification
{
    public List<string> hard_indicators { get; set; } = new();
    public List<string> soft_indicators { get; set; } = new();
}

public class AreaWeightsConfig
{
    public List<string> high_value   { get; set; } = new();
    public List<string> medium_value { get; set; } = new();
    public List<string> low_value    { get; set; } = new();
}

public class ConfirmationChain
{
    public string       name                  { get; set; } = "";
    public List<string> required_tactics      { get; set; } = new();
    public List<string> corroborating_tactics { get; set; } = new();
    public List<string> corroborating_events  { get; set; } = new();
}

public class ProcessTrustData
{
    public List<string>? trusted_publishers  { get; set; }
    public TrustCategory trusted_system     { get; set; }
    public TrustCategory trusted_user_apps  { get; set; }
    public TrustCategory shell_interpreters { get; set; }
    public TrustCategory lolbin_tools       { get; set; }
    public TrustCategory blacklisted        { get; set; }
}

public class TrustCategory
{
    public double       multiplier { get; set; }
    public List<string> processes  { get; set; }
}

public static class MapToData
{
    public static event Action<Cyber_behaviour_profiling.MonitoringEventUpdate>? SuspiciousEventObserved;

    private static List<MappedRule> _registryRules = new();
    private static List<MappedRule> _writeRules     = new();
    private static List<MappedRule> _overwriteRules = new();
    private static List<MappedRule> _networkRules   = new();
    private static List<MappedRule> _lolbinRules    = new();
    private static List<MappedRule> _commandRules   = new();
    private static List<MappedRule> _discoveryRules = new();

    public static IReadOnlyList<MappedRule> LolbinRules    => _lolbinRules;
    public static IReadOnlyList<MappedRule> CommandRules   => _commandRules;
    public static IReadOnlyList<MappedRule> DiscoveryRules => _discoveryRules;

    private static List<string> _sensitiveDirs  = new();
    private static List<string> _sensitiveFiles = new();

    public static IReadOnlyList<string> SensitiveDirs => _sensitiveDirs;

    public static List<string>   _networkDomains  = new();
    public static ConcurrentDictionary<int, ProcessProfile> ActiveProfiles    = new();
    public static ConcurrentDictionary<int, string>         _recentDnsQueries = new();

    public static Dictionary<string, int>    _tacticWeights           = new();
    public static List<KillChainRule>        _killChains              = new();
    public static ScoringConfig              _scoring                 = new();
    public static IndicatorClassification    _indicatorClassification = new();
    public static AreaWeightsConfig          _areaWeights             = new();
    public static List<ConfirmationChain>    _confirmationChains      = new();
    public static List<string>               _trustedSystem           = new();
    public static List<string>               _trustedUserApps         = new();
    public static Dictionary<string, double> _processTrustMultipliers = new(StringComparer.OrdinalIgnoreCase);
    public static HashSet<string>            _blacklistedProcesses    = new(StringComparer.OrdinalIgnoreCase);
    public static HashSet<string>            _trustedPublishers       = new(StringComparer.OrdinalIgnoreCase);
    public static List<string>               _contextSignalPaths      = new();

    private static volatile bool _profilesDirty = false;
    private static readonly System.Threading.Timer _saveTimer = new(_ =>
    {
        if (_profilesDirty) { _profilesDirty = false; SaveToFile("profiles.json"); }
    }, null, 5000, 5000);

    public static void ResetSession()
    {
        ActiveProfiles.Clear();
        _recentDnsQueries.Clear();
        _profilesDirty = false;
    }

      public static void TakeAnomalySnapshot()
    {
        foreach (var profile in ActiveProfiles.Values)
        {
            var now = DateTime.Now;
            double elapsed = profile.PrevSnapshotTime == DateTime.MinValue
                ? 0
                : (now - profile.PrevSnapshotTime).TotalSeconds;

            if (elapsed < 0.5)
            {
                if (profile.PrevSnapshotTime == DateTime.MinValue)
                {
                    profile.PrevFileWrites  = profile.TotalFileWrites;
                    profile.PrevFileDeletes = profile.TotalFileDeletes;
                    profile.PrevEventCount  = profile.EventTimeline.Count;
                    profile.PrevSnapshotTime = now;
                }
                continue;
            }

            double writeRate  = (profile.TotalFileWrites  - profile.PrevFileWrites)  / elapsed;
            double deleteRate = (profile.TotalFileDeletes - profile.PrevFileDeletes) / elapsed;
            double eventRate  = (profile.EventTimeline.Count - profile.PrevEventCount) / elapsed;
            double netConns   = 0;

            profile.AnomalyHistory.Add(new[] { writeRate, deleteRate, eventRate, netConns });

            profile.PrevFileWrites  = profile.TotalFileWrites;
            profile.PrevFileDeletes = profile.TotalFileDeletes;
            profile.PrevEventCount  = profile.EventTimeline.Count;
            profile.PrevSnapshotTime = now;
        }
    }

    public static List<ProcessProfile> GetMergedProfiles()
    {
        return ActiveProfiles.Values
            .GroupBy(p => p.ProcessName?.ToLowerInvariant() ?? "")
            .Select(g =>
            {
                var primary = g.OrderByDescending(p => p.EventTimeline.Count).First();
                if (g.Count() == 1) return primary;

                var merged = new ProcessProfile
                {
                    ProcessId   = primary.ProcessId,
                    ProcessName = primary.ProcessName,
                    FirstSeen   = g.Min(p => p.FirstSeen),
                };

                foreach (var p in g)
                {
                    foreach (var ev in p.EventTimeline)
                        merged.EventTimeline.Add(ev);
                    foreach (var path in p.ExeDropPaths)
                        merged.ExeDropPaths.Add(path);
                    foreach (var path in p.DeletedPaths)
                        merged.DeletedPaths.Add(path);
                    foreach (var cmd in p.SpawnedCommandLines)
                        merged.SpawnedCommandLines.Add(cmd);
                    foreach (var kvp in p.WriteDirectories)
                        merged.WriteDirectories.AddOrUpdate(kvp.Key, kvp.Value, (_, c) => c + kvp.Value);
                    Interlocked.Add(ref merged.TotalFileWrites, p.TotalFileWrites);
                    Interlocked.Add(ref merged.TotalFileDeletes, p.TotalFileDeletes);
                    merged.AnomalyHistory.AddRange(p.AnomalyHistory);
                }

                return merged;
            })
            .OrderByDescending(p => p.EventTimeline.Count)
            .ToList();
    }

    private static MappedRule R(string pattern, string category, string description = "") =>
        new() { Pattern = pattern.ToLowerInvariant(), Category = category, Description = description };

    private static string NormalizeRegKey(string key) =>
        key.Replace("HKCU\\", "")
           .Replace("HKEY_LOCAL_MACHINE\\", "")
           .Replace("HKEY_CURRENT_USER\\", "")
           .ToLowerInvariant();

    public static void LoadData(string jsonFilePath)
    {
        string json = File.ReadAllText(jsonFilePath);
        var data = JsonSerializer.Deserialize<ThreatData>(json)!;

        _registryRules.Clear();
        foreach (var k in data.registry?.persistence ?? new())
            _registryRules.Add(R(NormalizeRegKey(k), "registry_persistence"));
        foreach (var k in data.registry?.tampering ?? new())
            _registryRules.Add(R(NormalizeRegKey(k), "registry_defense_evasion"));
        foreach (var k in data.registry?.uac_bypass ?? new())
            _registryRules.Add(R(NormalizeRegKey(k), "registry_privilege_escalation"));
        foreach (var k in data.registry?.credential_access ?? new())
            _registryRules.Add(R(NormalizeRegKey(k), "registry_credential_access"));

        _sensitiveDirs  = data.file_operations?.sensitive_directories?.Select(d => d.ToLowerInvariant()).ToList() ?? new();
        _sensitiveFiles = data.file_operations?.sensitive_files?.Select(f => f.ToLowerInvariant()).ToList() ?? new();

        _writeRules.Clear();
        foreach (var w in data.file_operations?.uncommon_writes ?? new())
            _writeRules.Add(R(w, "file_defense_evasion"));

        _overwriteRules.Clear();
        foreach (var o in data.file_operations?.suspicious_overwrites ?? new())
            _overwriteRules.Add(R(o, "file_persistence"));

        _networkRules.Clear();
        _networkDomains.Clear();
        foreach (var d in data.network?.suspicious_domains ?? new())
        {
            string lower = d.ToLowerInvariant();
            _networkDomains.Add(lower);
            _networkRules.Add(R(lower, "network_c2"));
        }

        _lolbinRules.Clear();
        foreach (var p in data.processes?.lolbins ?? new())
            _lolbinRules.Add(R(p.name, "process_lolbin", p.description));
        foreach (var p in data.processes?.accessibility_binaries ?? new())
            _lolbinRules.Add(R(p.name, "process_accessibility", p.description));

        _commandRules.Clear();
        foreach (var c in data.processes?.suspicious_commands ?? new())
            _commandRules.Add(R(c.pattern, "process_defense_evasion", c.description));

        _discoveryRules.Clear();
        foreach (var c in data.discovery_commands ?? new())
            _discoveryRules.Add(R(c.name, "process_discovery", c.description));

        _processTrustMultipliers.Clear();
        void RegisterTrust(TrustCategory? cat)
        {
            if (cat?.processes == null) return;
            foreach (var p in cat.processes)
                _processTrustMultipliers[p.ToLowerInvariant()] = cat.multiplier;
        }
        RegisterTrust(data.process_trust?.trusted_system);
        RegisterTrust(data.process_trust?.trusted_user_apps);
        RegisterTrust(data.process_trust?.shell_interpreters);
        RegisterTrust(data.process_trust?.lolbin_tools);
        RegisterTrust(data.process_trust?.blacklisted);

        _blacklistedProcesses.Clear();
        foreach (var p in data.process_trust?.blacklisted?.processes ?? new())
            _blacklistedProcesses.Add(p.ToLowerInvariant());

        _trustedPublishers = new HashSet<string>(data.process_trust?.trusted_publishers ?? new(), StringComparer.OrdinalIgnoreCase);
        _trustedSystem   = data.process_trust?.trusted_system?.processes?.Select(p => p.ToLowerInvariant()).ToList() ?? new();
        _trustedUserApps = data.process_trust?.trusted_user_apps?.processes?.Select(p => p.ToLowerInvariant()).ToList() ?? new();

        _contextSignalPaths = data.file_operations?.context_signals?.Select(p => p.ToLowerInvariant()).ToList() ?? new();

        _tacticWeights           = data.tactic_weights           ?? new();
        _killChains              = data.kill_chains              ?? new();
        _scoring                 = data.scoring                 ?? new();
        _indicatorClassification = data.indicator_classification ?? new();
        _areaWeights             = data.area_weights             ?? new();
        _confirmationChains      = data.confirmation_chains      ?? new();
    }

    public static void EvaluateFileOperation(int pid, string processName, string filePath, string eventType)
    {
        if (string.IsNullOrEmpty(filePath)) return;

        string lowerPath = filePath.ToLowerInvariant();
        string fileName  = Path.GetFileName(lowerPath);

        var profile = ActiveProfiles.GetOrAdd(pid, id => new ProcessProfile
        {
            ProcessId = id, ProcessName = processName, FirstSeen = DateTime.Now
        });

        if (eventType == "FileWrite")
        {
            profile.TotalFileWrites++;
            string dir = Path.GetDirectoryName(lowerPath) ?? "";
            if (!string.IsNullOrEmpty(dir))
                profile.WriteDirectories.AddOrUpdate(dir, 1, (_, c) => c + 1);
        }
        if (eventType == "FileDelete")
        {
            profile.TotalFileDeletes++;
            if (!fileName.StartsWith("__psscriptpolicytest_") &&
                !fileName.StartsWith("__pssessionconfigurationtest_"))
                profile.DeletedPaths.Add(filePath);
        }

        if (eventType == "FileWrite")
        {
            string ext = Path.GetExtension(lowerPath);
            if (ext is ".exe" or ".dll" or ".scr" or ".pif"
                    or ".bat" or ".ps1" or ".cmd" or ".vbs" or ".hta" or ".wsf")
            {
                bool isBenignDrop =
                    fileName.StartsWith("__psscriptpolicytest_") ||
                    fileName.StartsWith("__pssessionconfigurationtest_");

                if (!isBenignDrop)
                    profile.ExeDropPaths.Add(filePath);

                bool isSuspiciousDropPath =
                    lowerPath.Contains(@"\appdata\") ||
                    lowerPath.Contains(@"\temp\")    ||
                    lowerPath.Contains(@"\programdata\") ||
                    lowerPath.Contains(@"\users\public\") ||
                    lowerPath.Contains(@"\windows\temp\") ||
                    lowerPath.Contains(@"\$recycle.bin\");

                bool isLegitimateDropPath =
                    lowerPath.Contains(@"\program files\") ||
                    lowerPath.Contains(@"\program files (x86)\") ||
                    lowerPath.Contains(@"\windows\system32\") ||
                    lowerPath.Contains(@"\windows\syswow64\");

                if (isSuspiciousDropPath && !isLegitimateDropPath && !isBenignDrop)
                    AddEventToProfile(pid, processName, "Executable Drop", ext, filePath, "file_exe_drop", "FileWrite");
            }
        }

        string? dirMatch = _sensitiveDirs.FirstOrDefault(dir => lowerPath.Contains(dir));
        if (dirMatch != null)
        {
            string? fileMatch = _sensitiveFiles.FirstOrDefault(f => fileName.Contains(f) || lowerPath.EndsWith(f));
            if (fileMatch != null)
            {
                AddEventToProfile(pid, processName, eventType, fileMatch, filePath, "credential_file_access", eventType);
            }
            else
            {
                if (dirMatch.Contains("\\appdata\\local\\packages\\"))
                    return;

                if (eventType != "FileRead")
                    return;

                if (lowerPath.Contains(@"\program files\putty\") ||
                    lowerPath.Contains(@"\windows\system32\openssh\"))
                    return;

                AddEventToProfile(pid, processName, "SensitiveDirAccess", dirMatch, filePath, "collection", eventType);
            }
            return;
        }

        if (eventType == "FileWrite")
        {
            var contextMatch = _contextSignalPaths.FirstOrDefault(p => lowerPath.Contains(p));
            if (contextMatch != null)
            {
                AddEventToProfile(pid, processName, "ContextSignal", contextMatch, filePath, "context_signal", eventType);
                return;
            }

            var writeRule = _writeRules.FirstOrDefault(w => lowerPath.Contains(w.Pattern));
            if (writeRule != null)
            {
                if (writeRule.Pattern.Contains("fonts"))
                {
                    string ext = Path.GetExtension(lowerPath);
                    if (ext is ".ttf" or ".otf" or ".fon" or ".fnt" or ".ttc" or ".eot")
                        return;
                }

                AddEventToProfile(pid, processName, "UncommonWrite", writeRule.Pattern, filePath, writeRule.Category, eventType);
                return;
            }
        }

        var overwriteRule = _overwriteRules.FirstOrDefault(o => fileName.Contains(o.Pattern));
        if (overwriteRule != null)
        {
            AddEventToProfile(pid, processName, "AccessibilityBinaryOverwrite", overwriteRule.Pattern, filePath, overwriteRule.Category, eventType);
        }
    }

    public static void EvaluateRegistryAccess(int pid, string processName, string registryKey, string operation = "Open")
    {
        if (string.IsNullOrEmpty(registryKey)) return;

        string lowerKey = registryKey.ToLowerInvariant()
            .Replace("\\registry\\machine\\", "")
            .Replace("\\registry\\user\\",    "");

        var rule = _registryRules.FirstOrDefault(r => lowerKey.Contains(r.Pattern));
        if (rule == null) return;

        if ((rule.Category == "registry_defense_evasion" || rule.Category == "registry_persistence") && operation == "Open")
            return;

        if (rule.Pattern == "system\\currentcontrolset\\services" && operation == "Open")
            return;

        if (rule.Pattern == "system\\currentcontrolset\\services")
        {
            string[] benignPrefixes = {
                "services\\winsock", "services\\tcpip", "services\\dnscache",
                "services\\dns",     "services\\afunix", "services\\crypt32", "services\\ccg"
            };
            if (benignPrefixes.Any(p => lowerKey.Contains(p))) return;
        }

        AddEventToProfile(pid, processName, "Registry", rule.Pattern, registryKey, rule.Category, "Registry");
    }

    public static void EvaluateProcessSpawn(int parentPid, string parentProcessName,
        int childPid, string childProcessName, string commandLine)
    {
        string lowerChild = childProcessName.ToLowerInvariant();

        var profile = ActiveProfiles.GetOrAdd(parentPid, id => new ProcessProfile
        {
            ProcessId = id, ProcessName = parentProcessName, FirstSeen = DateTime.Now
        });
        if (!string.IsNullOrEmpty(commandLine))
            profile.SpawnedCommandLines.Add((childProcessName, commandLine));

        if (_blacklistedProcesses.Contains(lowerChild) ||
            _blacklistedProcesses.Contains(lowerChild + ".exe"))
        {
            AddEventToProfile(parentPid, parentProcessName, "BlacklistedProcess", childProcessName,
                childProcessName, "process_blacklisted", "Process");
        }

        var lolbinRule = _lolbinRules.FirstOrDefault(r =>
            lowerChild.Contains(r.Pattern) ||
            r.Pattern.Contains(lowerChild));
        if (lolbinRule != null)
        {
            AddEventToProfile(parentPid, parentProcessName, "ProcessSpawn", childProcessName,
                childProcessName, lolbinRule.Category, "Process");
        }

        var discoveryRule = _discoveryRules.FirstOrDefault(r => lowerChild.Contains(r.Pattern));
        if (discoveryRule != null)
        {
            AddEventToProfile(parentPid, parentProcessName, "DiscoverySpawn", childProcessName,
                childProcessName, discoveryRule.Category, "Process");
        }

        if (!string.IsNullOrEmpty(commandLine))
        {
            string lowerCmd = commandLine.ToLowerInvariant();
            var cmdRule = _commandRules.FirstOrDefault(r => lowerCmd.Contains(r.Pattern));
            if (cmdRule != null)
            {
                AddEventToProfile(parentPid, parentProcessName, "SuspiciousCommand", cmdRule.Pattern,
                    commandLine, cmdRule.Category, "Process");
            }
        }
    }

    public static void EvaluateNetworkConnection(int pid, string processName, string destination)
    {
        if (string.IsNullOrEmpty(destination)) return;

        _recentDnsQueries.TryGetValue(pid, out string? knownDomain);
        string fullDest  = knownDomain != null ? $"{knownDomain} ({destination})" : destination;
        string lowerDest = fullDest.ToLowerInvariant();

        var netRule = _networkRules.FirstOrDefault(r => lowerDest.Contains(r.Pattern));
        if (netRule != null)
        {
            AddEventToProfile(pid, processName, "NetworkConnect", netRule.Pattern,
                fullDest, netRule.Category, "Network");
        }
        else if (destination is not ("127.0.0.1" or "::1" or "0.0.0.0" or "localhost"))
        {
            string indicator = knownDomain ?? destination;
            AddEventToProfile(pid, processName, "NetworkConnect", indicator,
                fullDest, "network_outbound", "Network");
        }
    }

    public static void AddEventToProfile(int pid, string processName, string eventType,
        string matchedRule, string rawData, string category = "", string activityType = "")
    {
        var profile = ActiveProfiles.GetOrAdd(pid, newId => new ProcessProfile
        {
            ProcessId   = newId,
            ProcessName = processName,
            FirstSeen   = DateTime.Now
        });

        string fingerprint = $"{pid}|{eventType}|{category}|{matchedRule}";
        bool isNew = false;

        if (profile.DedupCache.TryGetValue(fingerprint, out SuspiciousEvent? existing))
        {
            existing.AttemptCount++;
            existing.LastSeen = DateTime.Now;
        }
        else
        {
            isNew = true;
            var (tactic, techniqueId, techniqueName) = AttackNarrator.ResolveCategory(category);
            var ev = new SuspiciousEvent
            {
                Timestamp        = DateTime.Now,
                LastSeen         = DateTime.Now,
                Tactic           = tactic,
                TechniqueId      = techniqueId,
                TechniqueName    = techniqueName,
                EventType        = eventType,
                MatchedIndicator = matchedRule,
                RawData          = rawData,
                AttemptCount     = 1
            };
            profile.EventTimeline.Add(ev);
            profile.DedupCache[fingerprint] = ev;
        }

        var updateEvent = profile.DedupCache[fingerprint];
        SuspiciousEventObserved?.Invoke(new Cyber_behaviour_profiling.MonitoringEventUpdate
        {
            ProcessId = pid,
            ProcessName = processName,
            EventType = eventType,
            Category = category,
            RawData = rawData,
            ActivityType = activityType,
            Timestamp = updateEvent.LastSeen,
            AttemptCount = updateEvent.AttemptCount
        });

        _profilesDirty = true;

        if (!isNew && (DateTime.Now - profile.LastAnalyzed).TotalSeconds < 2.0) return;

        profile.LastAnalyzed = DateTime.Now;

        var report = BehaviorAnalyzer.Analyze(profile);

        string newSeverity = report.FinalScore >= _scoring.critical_threshold ? "CRITICAL" :
                             report.FinalScore >= _scoring.high_threshold     ? "HIGH"     :
                             report.FinalScore >= _scoring.medium_threshold   ? "MEDIUM"   :
                             report.FinalScore >= _scoring.low_threshold      ? "LOW"      : "BENIGN";

        string prevSeverity = profile.LastReportedSeverity ?? "BENIGN";
        bool severityEscalated = SeverityRank(newSeverity) > SeverityRank(prevSeverity);
        bool highValueNewEvent = isNew && newSeverity == "CRITICAL" &&
            AttackNarrator.IsHighValueCategory(category);

        if (severityEscalated || highValueNewEvent)
            profile.LastReportedSeverity = newSeverity;
    }

    private static int SeverityRank(string s) => s switch {
        "CRITICAL" => 4, "HIGH" => 3, "MEDIUM" => 2, "LOW" => 1, _ => 0
    };

    public static void SaveToFile(string outputPath)
    {
        try
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(ActiveProfiles.Values, options);
            File.WriteAllText(outputPath, json);
        }
        catch { }
    }
}
