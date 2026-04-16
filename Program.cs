using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
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

public class InheritedCommandContext
{
    public DateTime Timestamp { get; set; }
    public int ParentProcessId { get; set; }
    public string ParentProcessName { get; set; } = "";
    public string CommandLine { get; set; } = "";
}

public class SuspiciousEvent
{
    public DateTime Timestamp { get; set; }
    public DateTime LastSeen { get; set; }
    public string Category { get; set; } = "";
    public string EventType { get; set; }
    public string MatchedIndicator { get; set; }
    public string RawData { get; set; }
    public int AttemptCount { get; set; } = 1;
}

public class SnapshotObservation
{
    public DateTime Timestamp { get; set; }
    public string EventType { get; set; } = "";
    public string Category { get; set; } = "";
    public string RawData { get; set; } = "";
}

public class ProcessProfile
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime SpawnedAt { get; set; } = DateTime.MinValue;
    public DateTime LastAnalyzed { get; set; } = DateTime.MinValue;
    public int ParentProcessIdAtSpawn { get; set; }
    public string ParentProcessNameAtSpawn { get; set; } = "";
    public string ParentImagePathAtSpawn { get; set; } = "";
    public string LaunchCommandLineAtSpawn { get; set; } = "";
    public ConcurrentBag<SuspiciousEvent> EventTimeline { get; set; } = new();
    public ConcurrentQueue<SnapshotObservation> SnapshotObservations { get; set; } = new();
    public ConcurrentDictionary<string, SuspiciousEvent> DedupCache { get; set; } = new();
    public ConcurrentDictionary<string, int> WriteDirectories { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public ConcurrentDictionary<string, byte> ExeDropPaths { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public ConcurrentDictionary<string, byte> RuntimeArtifactPaths { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public ConcurrentBag<string> DeletedPaths { get; set; } = new();
    public ConcurrentBag<string> DeletedRuntimeArtifacts { get; set; } = new();
    public ConcurrentBag<SpawnedProcess> SpawnedCommandLines { get; set; } = new();
    public ConcurrentBag<InheritedCommandContext> InheritedCommandContexts { get; set; } = new();
    public string? ImagePath { get; set; }
    public int TotalFileWrites;
    public int TotalFileDeletes;
    public int TotalFilteredWrites;
    public int TotalFilteredDeletes;
    public int TotalRuntimeArtifactWrites;
    public int TotalRuntimeArtifactDeletes;
    public int TotalPayloadLikeWrites;
    public int TotalSensitiveAccessEvents;
    public int TotalContextSignalWrites;
    public int TotalUncommonWriteEvents;

    public List<double[]> AnomalyHistory { get; set; } = new();
    public int PrevFileWrites;
    public int PrevFileDeletes;
    public int PrevFilteredWrites;
    public int PrevFilteredDeletes;
    public int PrevPayloadLikeWrites;
    public int PrevSensitiveAccessEvents;
    public int PrevContextSignalWrites;
    public int PrevUncommonWriteEvents;
    public DateTime PrevSnapshotTime = DateTime.MinValue;

    [System.Text.Json.Serialization.JsonIgnore]
    public object KnnStateLock { get; } = new();

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
    public List<string> runtime_artifact_markers { get; set; }
    public List<string> noise_extensions { get; set; }
    public List<string> noise_paths { get; set; }
    public List<string> malware_artifacts { get; set; }
    public List<string> browser_credential_dirs { get; set; }
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
    public List<string> browser_processes { get; set; }
    public List<CommandIndicator> suspicious_commands { get; set; }
}

public class HeuristicThresholds
{
    public double burst_seconds { get; set; }
    public double diversity_seconds { get; set; }
    public int    diversity_min_tactics { get; set; }
    public int    massive_count_threshold { get; set; }
    public int    massive_count_window_seconds { get; set; }

    public List<double>? knn_scale_floors { get; set; }

    public int? max_baseline_snapshots { get; set; }

    public int? max_anomaly_history { get; set; }

    public double? snapshot_observation_retention_minutes { get; set; }

    public double? z_threshold    { get; set; }
    public double? distance_floor { get; set; }
}

public class SemanticHeuristicsData
{
    public List<string> harvest_high_confidence { get; set; }
    public List<string> harvest_suspicious_keywords { get; set; }
    public List<string> generic_shells { get; set; }
    public HeuristicThresholds thresholds { get; set; }
}

public class ThreatData
{
    public FileOperationsData file_operations { get; set; }
    public RegistryData registry { get; set; }
    public NetworkData network { get; set; }
    public ProcessesData processes { get; set; }
    public List<NamedIndicator> discovery_commands { get; set; }
    public ProcessTrustData process_trust { get; set; }
    public SemanticHeuristicsData semantic_heuristics { get; set; }
}

public class ProcessTrustData
{
    public List<string>? trusted_publishers { get; set; }
    public TrustCategory trusted_system { get; set; }
    public TrustCategory trusted_user_apps { get; set; }
    public TrustCategory shell_interpreters { get; set; }
    public TrustCategory lolbin_tools { get; set; }
}

public class TrustCategory
{
    public double multiplier { get; set; }
    public List<string> processes { get; set; }
}

public static class MapToData
{
    public static event Action<Cyber_behaviour_profiling.MonitoringEventUpdate>? SuspiciousEventObserved;

    private static int      MaxAnomalyHistory             = 120;
    private static TimeSpan SnapshotObservationRetention  = TimeSpan.FromMinutes(10);
    private static readonly Regex ExecutableSuffixPattern = new(@"(?<=\b[\w.-]+)\.exe\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex MultiWhitespacePattern = new(@"\s+", RegexOptions.Compiled);

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

    public static string ResolveBaselinePath(string? anchorPath = null)
    {
        string? startDir = null;
        if (!string.IsNullOrWhiteSpace(anchorPath))
        {
            string fullAnchor = Path.GetFullPath(anchorPath);
            startDir = Directory.Exists(fullAnchor)
                ? fullAnchor
                : Path.GetDirectoryName(fullAnchor);
        }

        startDir ??= AppContext.BaseDirectory;

        string? farthestBaseline = null;
        string? farthestDataDir = null;
        string? dir = startDir;

        for (int i = 0; i < 10 && !string.IsNullOrWhiteSpace(dir); i++)
        {
            string baselineCandidate = Path.Combine(dir, "baselines.json");
            string dataCandidate = Path.Combine(dir, "data.json");

            if (File.Exists(dataCandidate))
                farthestDataDir = dir;

            if (File.Exists(baselineCandidate))
                farthestBaseline = baselineCandidate;

            dir = Path.GetDirectoryName(dir);
        }

        if (!string.IsNullOrWhiteSpace(farthestBaseline))
            return farthestBaseline;

        if (!string.IsNullOrWhiteSpace(farthestDataDir))
            return Path.Combine(farthestDataDir, "baselines.json");

        return Path.Combine(AppContext.BaseDirectory, "baselines.json");
    }

    private static List<MappedRule> _registryRules = new();
    private static List<MappedRule> _writeRules = new();
    private static List<MappedRule> _overwriteRules = new();
    private static List<MappedRule> _networkRules = new();
    private static List<MappedRule> _lolbinRules = new();
    private static List<MappedRule> _commandRules = new();
    private static List<MappedRule> _discoveryRules = new();

    public static IReadOnlyList<MappedRule> LolbinRules => _lolbinRules;
    public static IReadOnlyList<MappedRule> CommandRules => _commandRules;
    public static IReadOnlyList<MappedRule> DiscoveryRules => _discoveryRules;

    private static List<string> _sensitiveDirs = new();
    private static List<string> _sensitiveFiles = new();

    public static IReadOnlyList<string> SensitiveDirs => _sensitiveDirs;

    public static List<string> _networkDomains = new();
    public static ConcurrentDictionary<int, ProcessProfile> ActiveProfiles = new();
    public static ConcurrentDictionary<int, string> _recentDnsQueries = new();

    public static List<string> _trustedSystem = new();
    public static List<string> _trustedUserApps = new();
    public static Dictionary<string, double> _processTrustMultipliers = new(StringComparer.OrdinalIgnoreCase);

    public static List<string> HarvestHighConfidence = new();
    public static List<string> HarvestSuspiciousKeywords = new();
    public static HashSet<string> GenericShells = new(StringComparer.OrdinalIgnoreCase);

    public static double BurstSeconds = 2.0;
    public static double DiversitySeconds = 5.0;
    public static int DiversityMinTactics = 3;
    public static int MassiveCountThreshold = 1000;
    public static int MassiveCountWindowSeconds = 60;

    public static HashSet<string> _trustedPublishers = new(StringComparer.OrdinalIgnoreCase);
    public static List<string> _contextSignalPaths = new();
    public static List<string> _runtimeArtifactMarkers = new();
    public static HashSet<string> _executableExtensions = new(StringComparer.OrdinalIgnoreCase);
    public static HashSet<string> _fontExtensions = new(StringComparer.OrdinalIgnoreCase);
    public static List<string> _benignDropPrefixes = new();
    public static HashSet<string> _noiseExtensions = new(StringComparer.OrdinalIgnoreCase);
    public static List<string> _noisePaths = new();
    public static HashSet<string> _malwareArtifacts = new(StringComparer.OrdinalIgnoreCase);
    public static List<string> _browserCredentialDirs = new();
    public static List<string> _benignServices = new();
    public static HashSet<string> _officeApps = new(StringComparer.OrdinalIgnoreCase);
    public static HashSet<string> _browserProcesses = new(StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> _browserProcessFallbackNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "msedge",
        "chrome",
        "firefox",
        "iexplore",
        "opera",
        "brave",
        "vivaldi",
        "waterfox",
        "palemoon",
        "torbrowser",
        "microsoftedge"
    };

    public static void ResetSession()
    {
        ActiveProfiles.Clear();
        _recentDnsQueries.Clear();
    }

    public static string? GetContextSignalBucket(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;

        string lowerPath = path.ToLowerInvariant();
        return _contextSignalPaths
            .Where(marker => lowerPath.Contains(marker))
            .OrderByDescending(marker => marker.Length)
            .FirstOrDefault();
    }

    private static string NormalizeProcessNameNoExtension(string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName))
            return "";

        string candidate = processName.Trim().Trim('"');
        int firstSpace = candidate.IndexOf(' ');
        if (firstSpace > 0)
            candidate = candidate[..firstSpace];

        candidate = Path.GetFileName(candidate);
        candidate = Path.GetFileNameWithoutExtension(candidate);
        return candidate.ToLowerInvariant();
    }

    public static bool IsKnownBrowserProcessName(string? processName)
    {
        string normalized = NormalizeProcessNameNoExtension(processName);
        if (string.IsNullOrWhiteSpace(normalized))
            return false;

        if (_browserProcessFallbackNames.Contains(normalized))
            return true;

        return _browserProcesses.Any(p =>
            string.Equals(NormalizeProcessNameNoExtension(p), normalized, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsRuntimeArtifactPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        string lowerPath = path.ToLowerInvariant();
        return _runtimeArtifactMarkers.Any(marker => lowerPath.Contains(marker));
    }

    private static void RecordSnapshotObservation(
        ProcessProfile profile, DateTime timestamp, string eventType, string category, string rawData)
    {
        profile.SnapshotObservations.Enqueue(new SnapshotObservation
        {
            Timestamp = timestamp,
            EventType = eventType,
            Category = category,
            RawData = rawData
        });

        DateTime cutoff = timestamp - SnapshotObservationRetention;
        while (profile.SnapshotObservations.TryPeek(out var oldest) && oldest.Timestamp < cutoff)
            profile.SnapshotObservations.TryDequeue(out _);
    }

    public static void TakeAnomalySnapshot()
    {
        foreach (var profile in ActiveProfiles.Values)
        {
            lock (profile.KnnStateLock)
            {
                var now = DateTime.Now;

                if (profile.PrevSnapshotTime == DateTime.MinValue)
                {
                    profile.PrevSnapshotTime = profile.FirstSeen;
                }

                double elapsed = (now - profile.PrevSnapshotTime).TotalSeconds;
                if (elapsed < 0.5)
                    continue;

                int currentFilteredWrites = profile.TotalFilteredWrites;
                int currentFilteredDeletes = profile.TotalFilteredDeletes;
                int currentPayloadLikeWrites = profile.TotalPayloadLikeWrites;
                int currentSensitiveAccessEvents = profile.TotalSensitiveAccessEvents;

                double filteredWriteRate = Math.Max(0, currentFilteredWrites - profile.PrevFilteredWrites) / elapsed;
                double filteredDeleteRate = Math.Max(0, currentFilteredDeletes - profile.PrevFilteredDeletes) / elapsed;
                double payloadRate = Math.Max(0, currentPayloadLikeWrites - profile.PrevPayloadLikeWrites) / elapsed;
                double sensitiveRate = Math.Max(0, currentSensitiveAccessEvents - profile.PrevSensitiveAccessEvents) / elapsed;

                double[] snapshot = { filteredWriteRate, filteredDeleteRate, payloadRate, sensitiveRate };

                profile.AnomalyHistory.Add(snapshot);
                while (profile.AnomalyHistory.Count > MaxAnomalyHistory)
                    profile.AnomalyHistory.RemoveAt(0);

                profile.PrevFilteredWrites = currentFilteredWrites;
                profile.PrevFilteredDeletes = currentFilteredDeletes;
                profile.PrevPayloadLikeWrites = currentPayloadLikeWrites;
                profile.PrevSensitiveAccessEvents = currentSensitiveAccessEvents;
                profile.PrevFileWrites = profile.TotalFileWrites;
                profile.PrevFileDeletes = profile.TotalFileDeletes;
                profile.PrevContextSignalWrites = profile.TotalContextSignalWrites;
                profile.PrevUncommonWriteEvents = profile.TotalUncommonWriteEvents;
                profile.PrevSnapshotTime = now;
            }
        }
    }

    public static List<ProcessProfile> GetAnalysisProfiles() =>
        ActiveProfiles.Values
            .OrderByDescending(p => p.EventTimeline.Count)
            .ThenBy(p => p.FirstSeen)
            .ToList();

    private static MappedRule CreateRule(string pattern, string category, string description = "") =>
        new() { Pattern = pattern.ToLowerInvariant(), Category = category, Description = description };

    private static string NormalizeRegistryKey(string key) =>
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
            _registryRules.Add(CreateRule(NormalizeRegistryKey(k), "registry_persistence"));
        foreach (var k in data.registry?.tampering ?? new())
            _registryRules.Add(CreateRule(NormalizeRegistryKey(k), "registry_defense_evasion"));
        foreach (var k in data.registry?.uac_bypass ?? new())
            _registryRules.Add(CreateRule(NormalizeRegistryKey(k), "registry_privilege_escalation"));
        foreach (var k in data.registry?.credential_access ?? new())
            _registryRules.Add(CreateRule(NormalizeRegistryKey(k), "registry_credential_access"));

        _sensitiveDirs = data.file_operations?.sensitive_directories?.Select(d => d.ToLowerInvariant()).ToList() ?? new();
        _sensitiveFiles = data.file_operations?.sensitive_files?.Select(f => f.ToLowerInvariant()).ToList() ?? new();

        _writeRules.Clear();
        foreach (var w in data.file_operations?.uncommon_writes ?? new())
            _writeRules.Add(CreateRule(w, "file_defense_evasion"));

        _overwriteRules.Clear();
        foreach (var o in data.file_operations?.suspicious_overwrites ?? new())
            _overwriteRules.Add(CreateRule(o, "file_persistence"));

        _networkRules.Clear();
        _networkDomains.Clear();
        foreach (var d in data.network?.suspicious_domains ?? new())
        {
            string lower = d.ToLowerInvariant();
            _networkDomains.Add(lower);
            _networkRules.Add(CreateRule(lower, "network_c2"));
        }

        _lolbinRules.Clear();
        foreach (var p in data.processes?.lolbins ?? new())
            _lolbinRules.Add(CreateRule(p.name, "process_lolbin", p.description));
        foreach (var p in data.processes?.accessibility_binaries ?? new())
            _lolbinRules.Add(CreateRule(p.name, "process_accessibility", p.description));

        _commandRules.Clear();
        foreach (var c in data.processes?.suspicious_commands ?? new())
            _commandRules.Add(CreateRule(c.pattern, "process_defense_evasion", c.description));

        _discoveryRules.Clear();
        foreach (var c in data.discovery_commands ?? new())
            _discoveryRules.Add(CreateRule(c.name, "process_discovery", c.description));

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

        _trustedPublishers = new HashSet<string>(data.process_trust?.trusted_publishers ?? new(), StringComparer.OrdinalIgnoreCase);
        _trustedSystem = data.process_trust?.trusted_system?.processes?.Select(p => p.ToLowerInvariant()).ToList() ?? new();
        _trustedUserApps = data.process_trust?.trusted_user_apps?.processes?.Select(p => p.ToLowerInvariant()).ToList() ?? new();

        _contextSignalPaths = data.file_operations?.context_signals?.Select(p => p.ToLowerInvariant()).ToList() ?? new();
        _runtimeArtifactMarkers = data.file_operations?.runtime_artifact_markers?
            .Select(p => p.ToLowerInvariant()).ToList() ?? new();

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
        _browserCredentialDirs = data.file_operations?.browser_credential_dirs?
            .Select(s => s.ToLowerInvariant()).ToList() ?? new();
        _benignServices = data.registry?.benign_services?
            .Select(s => s.ToLowerInvariant()).ToList() ?? new();
        _officeApps = new HashSet<string>(
            data.processes?.office_apps ?? new(),
            StringComparer.OrdinalIgnoreCase);
        _browserProcesses = new HashSet<string>(
            data.processes?.browser_processes ?? new(),
            StringComparer.OrdinalIgnoreCase);

        var heuristics = data.semantic_heuristics;
        if (heuristics != null)
        {
            HarvestHighConfidence = heuristics.harvest_high_confidence?
                .Select(s => s.ToLowerInvariant()).ToList() ?? new();
            HarvestSuspiciousKeywords = heuristics.harvest_suspicious_keywords?
                .Select(s => s.ToLowerInvariant()).ToList() ?? new();
            GenericShells = new HashSet<string>(
                heuristics.generic_shells ?? new(), StringComparer.OrdinalIgnoreCase);

            if (heuristics.thresholds != null)
            {
                BurstSeconds = heuristics.thresholds.burst_seconds;
                DiversitySeconds = heuristics.thresholds.diversity_seconds;
                DiversityMinTactics = heuristics.thresholds.diversity_min_tactics;
                MassiveCountThreshold = heuristics.thresholds.massive_count_threshold;
                MassiveCountWindowSeconds = heuristics.thresholds.massive_count_window_seconds;

                if (heuristics.thresholds.knn_scale_floors?.Count >= 4)
                    AnomalyDetector.ConfigureScaleFloors(
                        heuristics.thresholds.knn_scale_floors.ToArray());

                if (heuristics.thresholds.max_baseline_snapshots.HasValue)
                    AnomalyDetector.ConfigureMaxSnapshots(
                        heuristics.thresholds.max_baseline_snapshots.Value);

                if (heuristics.thresholds.max_anomaly_history.HasValue)
                    MaxAnomalyHistory = Math.Max(1, heuristics.thresholds.max_anomaly_history.Value);

                if (heuristics.thresholds.snapshot_observation_retention_minutes.HasValue)
                    SnapshotObservationRetention = TimeSpan.FromMinutes(
                        Math.Max(0.1, heuristics.thresholds.snapshot_observation_retention_minutes.Value));

                if (heuristics.thresholds.z_threshold.HasValue || heuristics.thresholds.distance_floor.HasValue)
                    AnomalyDetector.ConfigureDetector(
                        heuristics.thresholds.z_threshold    ?? 2.5,
                        heuristics.thresholds.distance_floor ?? 0.5);
            }
        }
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

        bool isNoisePath = _noisePaths.Any(np => lowerPath.Contains(np));
        bool isNoiseExt = _noiseExtensions.Contains(Path.GetExtension(lowerPath));
        bool isAnomalyNoise = isNoisePath || isNoiseExt;

        if (eventType == "FileWrite")
        {
            profile.TotalFileWrites++;
            if (!isAnomalyNoise)
                profile.TotalFilteredWrites++;

            string dir = Path.GetDirectoryName(lowerPath) ?? "";
            if (!string.IsNullOrEmpty(dir))
                profile.WriteDirectories.AddOrUpdate(dir, 1, (_, c) => c + 1);

            bool isExecutable = _executableExtensions.Contains(Path.GetExtension(lowerPath));
            bool isBenignDrop = _benignDropPrefixes.Any(p => fileName.StartsWith(p));
            bool isRuntimeArtifact = IsRuntimeArtifactPath(filePath);
            if (isRuntimeArtifact)
            {
                profile.TotalRuntimeArtifactWrites++;
                if (isExecutable)
                    profile.RuntimeArtifactPaths.TryAdd(filePath, 0);
            }
            else if (isExecutable && !isBenignDrop)
            {
                profile.TotalPayloadLikeWrites++;
                profile.ExeDropPaths.TryAdd(filePath, 0);
            }
        }

        if (eventType == "FileDelete")
        {
            profile.TotalFileDeletes++;
            if (!isAnomalyNoise)
                profile.TotalFilteredDeletes++;

            bool isBenignDrop = _benignDropPrefixes.Any(p => fileName.StartsWith(p));
            bool isRuntimeArtifact = IsRuntimeArtifactPath(filePath);
            if (isRuntimeArtifact)
            {
                profile.TotalRuntimeArtifactDeletes++;
                profile.DeletedRuntimeArtifacts.Add(filePath);
            }
            else if (!isBenignDrop)
                profile.DeletedPaths.Add(filePath);
        }

        string? dirMatch = _sensitiveDirs.FirstOrDefault(dir => lowerPath.Contains(dir));
        if (dirMatch != null)
        {
            string? fileMatch = _sensitiveFiles.FirstOrDefault(f => fileName.Contains(f) || lowerPath.EndsWith(f));
            if (fileMatch != null)
            {
                profile.TotalSensitiveAccessEvents++;
                if (IsKnownBrowserProcessName(processName))
                {
                    AddEventToProfile(pid, processName, "SensitiveDirAccess", dirMatch, filePath, "collection", eventType);
                }
                else
                {
                    AddEventToProfile(pid, processName, eventType, fileMatch, filePath, "credential_file_access", eventType);
                }
                return;
            }

            bool isNoise = dirMatch.Contains("\\appdata\\local\\packages\\") ||
                           eventType != "FileRead" ||
                           lowerPath.Contains(@"\program files\putty\") ||
                           lowerPath.Contains(@"\windows\system32\openssh\");
            if (!isNoise)
            {
                profile.TotalSensitiveAccessEvents++;
                AddEventToProfile(pid, processName, "SensitiveDirAccess", dirMatch, filePath, "collection", eventType);
            }
            return;
        }

        if (eventType == "FileWrite")
        {
            var contextMatch = GetContextSignalBucket(lowerPath);
            if (contextMatch != null)
            {
                profile.TotalContextSignalWrites++;
                AddEventToProfile(pid, processName, "ContextSignal", contextMatch, filePath, "context_signal", eventType);
                return;
            }

            var writeRule = _writeRules.FirstOrDefault(w => lowerPath.Contains(w.Pattern));
            if (writeRule != null)
            {
                profile.TotalUncommonWriteEvents++;
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
        string observedCommandLine = commandLine ?? "";

        var profile = ActiveProfiles.GetOrAdd(parentPid, id => new ProcessProfile
        {
            ProcessId = id,
            ProcessName = parentProcessName,
            FirstSeen = DateTime.Now
        });
        childImagePath = NormalizeNtPath(childImagePath ?? "");
        DateTime spawnTimestamp = DateTime.Now;
        profile.SpawnedCommandLines.Add(new SpawnedProcess
        {
            Pid = childPid,
            Name = childProcessName,
            ImagePath = childImagePath,
            CommandLine = observedCommandLine,
            StartTime = spawnTimestamp
        });

        var childProfile = ActiveProfiles.GetOrAdd(childPid, id => new ProcessProfile
        {
            ProcessId = id,
            ProcessName = childProcessName,
            FirstSeen = spawnTimestamp,
            SpawnedAt = spawnTimestamp
        });
        if (childProfile.SpawnedAt == DateTime.MinValue)
            childProfile.SpawnedAt = spawnTimestamp;
        if (string.IsNullOrEmpty(childProfile.ImagePath) && !string.IsNullOrEmpty(childImagePath))
            childProfile.ImagePath = childImagePath;
        if (childProfile.ParentProcessIdAtSpawn <= 0)
            childProfile.ParentProcessIdAtSpawn = parentPid;
        if (string.IsNullOrWhiteSpace(childProfile.ParentProcessNameAtSpawn))
            childProfile.ParentProcessNameAtSpawn = parentProcessName;
        if (string.IsNullOrWhiteSpace(childProfile.ParentImagePathAtSpawn) &&
            !string.IsNullOrWhiteSpace(profile.ImagePath))
        {
            childProfile.ParentImagePathAtSpawn = profile.ImagePath;
        }
        if (string.IsNullOrWhiteSpace(childProfile.LaunchCommandLineAtSpawn) &&
            !string.IsNullOrWhiteSpace(observedCommandLine))
        {
            childProfile.LaunchCommandLineAtSpawn = observedCommandLine;
        }

        if (!string.IsNullOrWhiteSpace(observedCommandLine))
        {
            childProfile.InheritedCommandContexts.Add(new InheritedCommandContext
            {
                Timestamp = spawnTimestamp,
                ParentProcessId = parentPid,
                ParentProcessName = parentProcessName,
                CommandLine = observedCommandLine
            });
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

        if (!string.IsNullOrEmpty(observedCommandLine))
        {
            var cmdRule = _commandRules.FirstOrDefault(r => CommandLineMatchesRule(observedCommandLine, r.Pattern));
            if (cmdRule != null)
            {
                AddEventToProfile(parentPid, parentProcessName, "SuspiciousCommand", cmdRule.Pattern,
                    observedCommandLine, cmdRule.Category, "Process");
            }
        }
    }

    public static bool CommandLineMatchesRule(string commandLine, string rulePattern)
    {
        if (string.IsNullOrWhiteSpace(commandLine) || string.IsNullOrWhiteSpace(rulePattern))
            return false;

        string normalizedCommandLine = NormalizeCommandText(commandLine);
        string normalizedRulePattern = NormalizeCommandText(rulePattern);
        return normalizedCommandLine.Contains(normalizedRulePattern, StringComparison.Ordinal);
    }

    private static string NormalizeCommandText(string value)
    {
        string normalized = value.ToLowerInvariant().Replace('"', ' ');
        normalized = ExecutableSuffixPattern.Replace(normalized, string.Empty);
        normalized = MultiWhitespacePattern.Replace(normalized, " ").Trim();
        return normalized;
    }

    public static string FormatNetworkDestination(int pid, string destination, out string? knownDomain)
    {
        knownDomain = null;
        if (string.IsNullOrWhiteSpace(destination))
            return destination;

        _recentDnsQueries.TryGetValue(pid, out knownDomain);
        return !string.IsNullOrWhiteSpace(knownDomain)
            ? $"{knownDomain} ({destination})"
            : destination;
    }

    public static void EvaluateNetworkConnection(int pid, string processName, string destination)
    {
        if (string.IsNullOrEmpty(destination)) return;

        string fullDest = FormatNetworkDestination(pid, destination, out string? knownDomain);
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

        DateTime observedAt = DateTime.Now;

        string fingerprint = $"{pid}|{eventType}|{category}|{matchedRule}";
        bool isNew = false;

        if (profile.DedupCache.TryGetValue(fingerprint, out SuspiciousEvent? existing))
        {
            existing.AttemptCount++;
            existing.LastSeen = observedAt;
        }
        else
        {
            isNew = true;
            var ev = new SuspiciousEvent
            {
                Timestamp = observedAt,
                LastSeen = observedAt,
                Category = category,
                EventType = eventType,
                MatchedIndicator = matchedRule,
                RawData = rawData,
                AttemptCount = 1
            };
            profile.EventTimeline.Add(ev);
            profile.DedupCache[fingerprint] = ev;
        }

        RecordSnapshotObservation(profile, observedAt, eventType, category, rawData);

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

        if (!isNew && (observedAt - profile.LastAnalyzed).TotalSeconds < 2.0) return;

        profile.LastAnalyzed = observedAt;

        BehaviorAnalyzer.Analyze(profile);
    }

    public static void LoadBaselines(string jsonFilePath)
    {
        if (!File.Exists(jsonFilePath))
        {
            AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());
            return;
        }

        try
        {
            string json = File.ReadAllText(jsonFilePath);
            var store = System.Text.Json.JsonSerializer.Deserialize<BaselineStore>(json,
                new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new BaselineStore();
            AnomalyDetector.LoadBaselines(store.Baselines);
        }
        catch
        {
            AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());
        }
    }

    public static void SaveBaseline(string processName, ProcessBaseline baseline, string jsonFilePath)
    {
        BaselineStore store;
        if (File.Exists(jsonFilePath))
        {
            string json = File.ReadAllText(jsonFilePath);
            store = System.Text.Json.JsonSerializer.Deserialize<BaselineStore>(json,
                new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new BaselineStore();
        }
        else
            store = new BaselineStore();

        string key = Path.GetFileNameWithoutExtension(processName).ToLowerInvariant();
        baseline.Source = "user";
        baseline.RecordedAt = DateTime.Now.ToString("o");
        store.Baselines[key] = baseline;

        File.WriteAllText(jsonFilePath,
            System.Text.Json.JsonSerializer.Serialize(store, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        AnomalyDetector.LoadBaselines(store.Baselines);
    }

    public static void DeleteBaseline(string processName, string jsonFilePath)
    {
        if (!File.Exists(jsonFilePath)) return;
        string json = File.ReadAllText(jsonFilePath);
        var store = System.Text.Json.JsonSerializer.Deserialize<BaselineStore>(json,
            new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new BaselineStore();

        string key = Path.GetFileNameWithoutExtension(processName).ToLowerInvariant();
        store.Baselines.Remove(key);

        File.WriteAllText(jsonFilePath,
            System.Text.Json.JsonSerializer.Serialize(store, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        AnomalyDetector.LoadBaselines(store.Baselines);
    }

}