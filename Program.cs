using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Cyber_behaviour_profiling;

public partial class Program
{
    public static void Main(string[] args) { }
}



public class MappedRule
{
    public string Pattern { get; set; } = "";
    public string Category { get; set; } = "";
    public string Description { get; set; } = "";
}

public class NamedIndicator
{
    public string name { get; set; } = "";
    public string description { get; set; } = "";
}

public class CommandIndicator
{
    public string pattern { get; set; } = "";
    public string description { get; set; } = "";
}

public class SpawnedProcess
{
    public int Pid { get; set; }
    public string Name { get; set; } = "";
    public string ImagePath { get; set; } = "";
    public string CommandLine { get; set; } = "";
    public DateTime StartTime { get; set; }
}

public class SuspiciousEvent
{
    public DateTime Timestamp { get; set; }
    public DateTime LastSeen { get; set; }
    public string Tactic { get; set; } = "";
    public string TechniqueId { get; set; } = "";
    public string TechniqueName { get; set; } = "";
    public string Category { get; set; } = "";
    public string EventType { get; set; }
    public string MatchedIndicator { get; set; }
    public string RawData { get; set; }
    public int AttemptCount { get; set; } = 1;
}

public class ProcessProfile
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastAnalyzed { get; set; } = DateTime.MinValue;
    public DateTime LastNarrativePrint { get; set; } = DateTime.MinValue;
    public string LastReportedSeverity { get; set; } = "BENIGN";
    public ConcurrentBag<SuspiciousEvent> EventTimeline { get; set; } = new();
    public ConcurrentDictionary<string, SuspiciousEvent> DedupCache { get; set; } = new();
    public ConcurrentDictionary<string, int> WriteDirectories { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public ConcurrentDictionary<string, byte> ExeDropPaths { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public ConcurrentBag<string> DeletedPaths { get; set; } = new();
    public ConcurrentBag<SpawnedProcess> SpawnedCommandLines { get; set; } = new();
    public string? ImagePath { get; set; }
    public int TotalFileWrites;
    public int TotalFileDeletes;

    // KNN anomaly detection state
    public List<double[]> AnomalyHistory { get; set; } = new();
    public List<double> KnnScores { get; set; } = new();
    public int PrevFileWrites;
    public int PrevFileDeletes;
    public int PrevEventCount;
    public DateTime PrevSnapshotTime = DateTime.MinValue;

    // Pre-monitoring directory snapshot for investigation
    [System.Text.Json.Serialization.JsonIgnore]
    public DirectorySnapshot? DirectorySnapshotBefore { get; set; }
}

public class FileOperationsData
{
    public List<string> sensitive_directories { get; set; }
    public List<string> sensitive_files { get; set; }
    public List<string> uncommon_writes { get; set; }
    public List<string> context_signals { get; set; }
    public List<string> suspicious_overwrites { get; set; }
    public List<string> executable_extensions { get; set; }
    public List<string> font_extensions { get; set; }
    public List<string> benign_drop_prefixes { get; set; }
    public List<string> noise_extensions { get; set; }
    public List<string> noise_paths { get; set; }
    public List<string> malware_artifacts { get; set; }
}

public class RegistryData
{
    public List<string> persistence { get; set; }
    public List<string> tampering { get; set; }
    public List<string> uac_bypass { get; set; }
    public List<string> credential_access { get; set; }
    public List<string> benign_services { get; set; }
}

public class NetworkData
{
    public List<string> suspicious_domains { get; set; }
}

public class ProcessesData
{
    public List<NamedIndicator> lolbins { get; set; }
    public List<NamedIndicator> accessibility_binaries { get; set; }
    public List<string> office_apps { get; set; }
    public List<CommandIndicator> suspicious_commands { get; set; }
}

public class ThreatData
{
    public FileOperationsData file_operations { get; set; }
    public RegistryData registry { get; set; }
    public NetworkData network { get; set; }
    public ProcessesData processes { get; set; }
    public List<NamedIndicator> discovery_commands { get; set; }
    public ScoringConfig scoring { get; set; }
    public ProcessTrustData process_trust { get; set; }
    public AreaWeightsConfig area_weights { get; set; }
}

public class ScoringConfig
{
    public int low_threshold { get; set; }
    public int medium_threshold { get; set; }
    public int review_threshold { get; set; }
    public int high_threshold { get; set; }
    public int critical_threshold { get; set; }
}

public class AreaWeightsConfig
{
    public List<string> high_value { get; set; } = new();
    public List<string> medium_value { get; set; } = new();
}

public class ProcessTrustData
{
    public List<string>? trusted_publishers { get; set; }
    public TrustCategory trusted_system { get; set; }
    public TrustCategory trusted_user_apps { get; set; }
    public TrustCategory shell_interpreters { get; set; }
    public TrustCategory lolbin_tools { get; set; }
    public TrustCategory blacklisted { get; set; }
}

public class TrustCategory
{
    public double multiplier { get; set; }
    public List<string> processes { get; set; }
}

public static class MapToData
{
    public static event Action<Cyber_behaviour_profiling.MonitoringEventUpdate>? SuspiciousEventObserved;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);

    private static readonly Lazy<Dictionary<string, string>> _ntVolumeMap = new(BuildNtVolumeMap);

    private static Dictionary<string, string> BuildNtVolumeMap()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var drive in System.IO.DriveInfo.GetDrives())
        {
            string letter = drive.Name.Substring(0, 2);
            var sb = new StringBuilder(260);
            if (QueryDosDevice(letter, sb, 260) > 0)
                map[sb.ToString()] = letter;
        }
        return map;
    }

    public static string NormalizeNtPath(string path)
    {
        if (!path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            return path;
        foreach (var kvp in _ntVolumeMap.Value)
        {
            if (path.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
                return kvp.Value + path.Substring(kvp.Key.Length);
        }
        return path;
    }

    private static List<MappedRule> _registryRules = new();
    private static List<MappedRule> _writeRules = new();
    private static List<MappedRule> _overwriteRules = new();
    private static List<MappedRule> _networkRules = new();
    private static List<MappedRule> _lolbinRules = new();
    private static List<MappedRule> _commandRules = new();
    private static List<MappedRule> _discoveryRules = new();

    // Public read-only access for the report layer
    public static IReadOnlyList<MappedRule> LolbinRules => _lolbinRules;
    public static IReadOnlyList<MappedRule> CommandRules => _commandRules;
    public static IReadOnlyList<MappedRule> DiscoveryRules => _discoveryRules;

    private static List<string> _sensitiveDirs = new();
    private static List<string> _sensitiveFiles = new();

    public static IReadOnlyList<string> SensitiveDirs => _sensitiveDirs;

    public static List<string> _networkDomains = new();
    public static ConcurrentDictionary<int, ProcessProfile> ActiveProfiles = new();
    public static ConcurrentDictionary<int, string> _recentDnsQueries = new();

    public static ScoringConfig _scoring = new();
    public static AreaWeightsConfig _areaWeights = new();
    public static List<string> _trustedSystem = new();
    public static List<string> _trustedUserApps = new();
    public static Dictionary<string, double> _processTrustMultipliers = new(StringComparer.OrdinalIgnoreCase);
    public static HashSet<string> _blacklistedProcesses = new(StringComparer.OrdinalIgnoreCase);
    public static HashSet<string> _trustedPublishers = new(StringComparer.OrdinalIgnoreCase);
    public static List<string> _contextSignalPaths = new();
    public static HashSet<string> _executableExtensions = new(StringComparer.OrdinalIgnoreCase);
    public static HashSet<string> _fontExtensions = new(StringComparer.OrdinalIgnoreCase);
    public static List<string> _benignDropPrefixes = new();
    public static HashSet<string> _noiseExtensions = new(StringComparer.OrdinalIgnoreCase);
    public static List<string> _noisePaths = new();
    public static HashSet<string> _malwareArtifacts = new(StringComparer.OrdinalIgnoreCase);
    public static List<string> _benignServices = new();
    public static HashSet<string> _officeApps = new(StringComparer.OrdinalIgnoreCase);

    public static void ResetSession()
    {
        ActiveProfiles.Clear();
        _recentDnsQueries.Clear();
    }

    public static void TakeAnomalySnapshot() // runs every 1 second via timer in LiveMonitoringSession
    {
        foreach (var profile in ActiveProfiles.Values)
        {
            var now = DateTime.Now;

            if (profile.PrevSnapshotTime == DateTime.MinValue)
            {
                profile.PrevFileWrites = profile.TotalFileWrites;
                profile.PrevFileDeletes = profile.TotalFileDeletes;
                profile.PrevEventCount = profile.EventTimeline.Count;
                profile.PrevSnapshotTime = now;
                continue;
            }

            double elapsed = (now - profile.PrevSnapshotTime).TotalSeconds;
            if (elapsed < 0.5)
                continue;

            double writeRate  = (profile.TotalFileWrites  - profile.PrevFileWrites)  / elapsed;
            double deleteRate = (profile.TotalFileDeletes - profile.PrevFileDeletes) / elapsed;
            double eventRate  = (profile.EventTimeline.Count - profile.PrevEventCount) / elapsed;

            profile.AnomalyHistory.Add(new[] { writeRate, deleteRate, eventRate, 0.0 }); // network connections are filled at Evaluate time

            profile.PrevFileWrites  = profile.TotalFileWrites;
            profile.PrevFileDeletes = profile.TotalFileDeletes;
            profile.PrevEventCount  = profile.EventTimeline.Count;
            profile.PrevSnapshotTime = now;
        }
    }

    public static List<ProcessProfile> GetMergedProfiles()
    {
        var result = new List<ProcessProfile>();

        var byName = ActiveProfiles.Values
            .GroupBy(p => p.ProcessName?.ToLowerInvariant() ?? "");

        foreach (var group in byName)
        {
            var primary = group.OrderByDescending(p => p.EventTimeline.Count).First();
            result.Add(group.Count() == 1 ? primary : MergeGroup(group, primary));
        }

        result.Sort((a, b) => b.EventTimeline.Count.CompareTo(a.EventTimeline.Count));
        return result;
    }

    private static ProcessProfile MergeGroup(IEnumerable<ProcessProfile> group, ProcessProfile primary)
    {
        var merged = new ProcessProfile
        {
            ProcessId   = primary.ProcessId,
            ProcessName = primary.ProcessName,
            FirstSeen   = group.Min(p => p.FirstSeen),
            ImagePath   = group.Select(p => p.ImagePath).FirstOrDefault(p => !string.IsNullOrEmpty(p)),
        };

        foreach (var p in group)
        {
            foreach (var ev   in p.EventTimeline)       merged.EventTimeline.Add(ev);
            foreach (var kvp  in p.ExeDropPaths)        merged.ExeDropPaths.TryAdd(kvp.Key, 0);
            foreach (var path in p.DeletedPaths)        merged.DeletedPaths.Add(path);
            foreach (var cmd  in p.SpawnedCommandLines) merged.SpawnedCommandLines.Add(cmd);
            foreach (var kvp  in p.WriteDirectories)
                merged.WriteDirectories.AddOrUpdate(kvp.Key, kvp.Value, (_, c) => c + kvp.Value);
            Interlocked.Add(ref merged.TotalFileWrites,  p.TotalFileWrites);
            Interlocked.Add(ref merged.TotalFileDeletes, p.TotalFileDeletes);
            merged.AnomalyHistory.AddRange(p.AnomalyHistory);
        }

        return merged;
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

        _sensitiveDirs = data.file_operations?.sensitive_directories?.Select(d => d.ToLowerInvariant()).ToList() ?? new();
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
        _trustedSystem = data.process_trust?.trusted_system?.processes?.Select(p => p.ToLowerInvariant()).ToList() ?? new();
        _trustedUserApps = data.process_trust?.trusted_user_apps?.processes?.Select(p => p.ToLowerInvariant()).ToList() ?? new();

        _contextSignalPaths = data.file_operations?.context_signals?.Select(p => p.ToLowerInvariant()).ToList() ?? new();

        _executableExtensions = new HashSet<string>(
            data.file_operations?.executable_extensions ?? new(),
            StringComparer.OrdinalIgnoreCase);
        _fontExtensions = new HashSet<string>(
            data.file_operations?.font_extensions ?? new(),
            StringComparer.OrdinalIgnoreCase);
        _benignDropPrefixes = data.file_operations?.benign_drop_prefixes?
            .Select(p => p.ToLowerInvariant()).ToList() ?? new();
        _noiseExtensions = new HashSet<string>(
            data.file_operations?.noise_extensions ?? new(),
            StringComparer.OrdinalIgnoreCase);
        _noisePaths = data.file_operations?.noise_paths?
            .Select(s => s.ToLowerInvariant()).ToList() ?? new();
        _malwareArtifacts = new HashSet<string>(
            data.file_operations?.malware_artifacts ?? new(),
            StringComparer.OrdinalIgnoreCase);
        _benignServices = data.registry?.benign_services?
            .Select(s => s.ToLowerInvariant()).ToList() ?? new();
        _officeApps = new HashSet<string>(
            data.processes?.office_apps ?? new(),
            StringComparer.OrdinalIgnoreCase);

        _scoring = data.scoring ?? new();
        _areaWeights = data.area_weights ?? new();
    }

    public static void EvaluateFileOperation(int pid, string processName, string filePath, string eventType)
    {
        if (string.IsNullOrEmpty(filePath)) return;

        filePath = NormalizeNtPath(filePath);
        string lowerPath = filePath.ToLowerInvariant();
        string fileName = Path.GetFileName(lowerPath);

        var profile = ActiveProfiles.GetOrAdd(pid, id => new ProcessProfile
        {
            ProcessId = id,
            ProcessName = processName,
            FirstSeen = DateTime.Now
        });

        if (eventType == "FileWrite")
        {
            profile.TotalFileWrites++;
            string dir = Path.GetDirectoryName(lowerPath) ?? "";
            if (!string.IsNullOrEmpty(dir))
                profile.WriteDirectories.AddOrUpdate(dir, 1, (_, c) => c + 1);

            bool isExecutable = _executableExtensions.Contains(Path.GetExtension(lowerPath));
            bool isBenignDrop = _benignDropPrefixes.Any(p => fileName.StartsWith(p));
            if (isExecutable && !isBenignDrop)
                profile.ExeDropPaths.TryAdd(filePath, 0);
        }

        if (eventType == "FileDelete")
        {
            profile.TotalFileDeletes++;
            bool isBenignDrop = _benignDropPrefixes.Any(p => fileName.StartsWith(p));
            if (!isBenignDrop)
                profile.DeletedPaths.Add(filePath);
        }

        // Check if this path touches a sensitive directory
        string? dirMatch = _sensitiveDirs.FirstOrDefault(dir => lowerPath.Contains(dir));
        if (dirMatch != null)
        {
            string? fileMatch = _sensitiveFiles.FirstOrDefault(f => fileName.Contains(f) || lowerPath.EndsWith(f));
            if (fileMatch != null)
            {
                AddEventToProfile(pid, processName, eventType, fileMatch, filePath, "credential_file_access", eventType);
                return;
            }

            bool isNoise = dirMatch.Contains("\\appdata\\local\\packages\\") ||
                           eventType != "FileRead" ||
                           lowerPath.Contains(@"\program files\putty\") ||
                           lowerPath.Contains(@"\windows\system32\openssh\");
            if (!isNoise)
                AddEventToProfile(pid, processName, "SensitiveDirAccess", dirMatch, filePath, "collection", eventType);
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
                // Don't flag actual font files written to the fonts directory
                bool isFont = writeRule.Pattern.Contains("fonts") && _fontExtensions.Contains(Path.GetExtension(lowerPath));
                if (!isFont)
                    AddEventToProfile(pid, processName, "UncommonWrite", writeRule.Pattern, filePath, writeRule.Category, eventType);
                return;
            }
        }

        var overwriteRule = _overwriteRules.FirstOrDefault(o => fileName.Contains(o.Pattern));
        if (overwriteRule != null)
            AddEventToProfile(pid, processName, "AccessibilityBinaryOverwrite", overwriteRule.Pattern, filePath, overwriteRule.Category, eventType);
    }

    public static void EvaluateRegistryAccess(int pid, string processName, string registryKey, string operation = "Open")
    {
        if (string.IsNullOrEmpty(registryKey)) return;

        string lowerKey = registryKey.ToLowerInvariant()
            .Replace("\\registry\\machine\\", "")
            .Replace("\\registry\\user\\", "");

        var rule = _registryRules.FirstOrDefault(r => lowerKey.Contains(r.Pattern));
        if (rule == null) return;

        bool isReadOnlyNoise = rule.Category is "registry_defense_evasion" or "registry_persistence"
            && operation == "Open";
        if (isReadOnlyNoise) return;

        if (rule.Pattern == "system\\currentcontrolset\\services")
        {
            if (operation == "Open" || _benignServices.Any(s => lowerKey.Contains(s)))
                return;
        }

        AddEventToProfile(pid, processName, "Registry", rule.Pattern, registryKey, rule.Category, "Registry");
    }

    public static void EvaluateProcessSpawn(int parentPid, string parentProcessName,
        int childPid, string childProcessName, string childImagePath, string commandLine)
    {
        string lowerChild = childProcessName.ToLowerInvariant();

        var profile = ActiveProfiles.GetOrAdd(parentPid, id => new ProcessProfile
        {
            ProcessId = id,
            ProcessName = parentProcessName,
            FirstSeen = DateTime.Now
        });
        childImagePath = NormalizeNtPath(childImagePath ?? "");
        profile.SpawnedCommandLines.Add(new SpawnedProcess
        {
            Pid = childPid,
            Name = childProcessName,
            ImagePath = childImagePath,
            CommandLine = commandLine,
            StartTime = DateTime.Now
        });

        // Store the full image path on the child's own profile so GatherSystemContext can use it as fallback
        var childProfile = ActiveProfiles.GetOrAdd(childPid, id => new ProcessProfile // ensures that child is recorded before it exits
        {
            ProcessId = id,
            ProcessName = childProcessName,
            FirstSeen = DateTime.Now
        });
        if (string.IsNullOrEmpty(childProfile.ImagePath) && !string.IsNullOrEmpty(childImagePath))
            childProfile.ImagePath = childImagePath;

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
        string fullDest = knownDomain != null ? $"{knownDomain} ({destination})" : destination;
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
            ProcessId = newId,
            ProcessName = processName,
            FirstSeen = DateTime.Now
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
            var ev = new SuspiciousEvent
            {
                Timestamp = DateTime.Now,
                LastSeen = DateTime.Now,
                Category = category,
                EventType = eventType,
                MatchedIndicator = matchedRule,
                RawData = rawData,
                AttemptCount = 1
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

        if (!isNew && (DateTime.Now - profile.LastAnalyzed).TotalSeconds < 2.0) return;

        profile.LastAnalyzed = DateTime.Now;

        var report = BehaviorAnalyzer.Analyze(profile);

        string newSeverity = report.FinalVerdict switch
        {
            Cyber_behaviour_profiling.ThreatImpact.Malicious    => "CRITICAL",
            Cyber_behaviour_profiling.ThreatImpact.Suspicious   => "HIGH",
            Cyber_behaviour_profiling.ThreatImpact.Inconclusive => "MEDIUM",
            _                                                    => "BENIGN"
        };

        string prevSeverity = profile.LastReportedSeverity ?? "BENIGN";
        bool severityEscalated = SeverityRank(newSeverity) > SeverityRank(prevSeverity);
        bool highValueNewEvent = isNew && newSeverity == "CRITICAL" &&
            AttackNarrator.IsHighValueCategory(category);

        if (severityEscalated || highValueNewEvent)
            profile.LastReportedSeverity = newSeverity;
    }

    private static int SeverityRank(string s) => s switch
    {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0
    };


}
