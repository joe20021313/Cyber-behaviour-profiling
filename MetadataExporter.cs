using System.Text;

public static class MetadataExporter
{
    private static readonly Dictionary<string, string> _eventLabels = new(StringComparer.OrdinalIgnoreCase)
    {
        ["FileWrite"]                  = "File Write",
        ["FileRead"]                   = "File Read",
        ["FileOpen"]                   = "File Open",
        ["FileDelete"]                 = "File Delete",
        ["FileRename"]                 = "File Rename",
        ["SensitiveDirAccess"]         = "Sensitive Directory Access",
        ["UncommonWrite"]              = "Uncommon File Write",
        ["AccessibilityBinaryOverwrite"] = "Accessibility Binary Overwrite",
        ["Executable Drop"]            = "Executable Drop",
        ["Registry"]                   = "Registry",
        ["NetworkConnect"]             = "Network Connection",
        ["DNS_Query"]                  = "DNS Query",
        ["ProcessSpawn"]               = "Process Spawn",
        ["SuspiciousCommand"]          = "Suspicious Command",
        ["DiscoverySpawn"]             = "Discovery Spawn",
        ["DPAPI_Decrypt"]              = "DPAPI Decrypt",
        ["LsassAccess"]                = "LSASS Access",
        ["RemoteThreadInjection"]      = "Remote Thread Injection",
        ["ProcessTampering"]           = "Process Tampering",
        ["ContextSignal"]              = "Context Signal",
    };

    private static string FriendlyLabel(string? eventType) =>
        eventType != null && _eventLabels.TryGetValue(eventType, out var label) ? label : (eventType ?? "Unknown");

    private static string FormatTimelineCount(int count) =>
        count == 1 ? "1 timeline event" : $"{count} timeline events";

    public static string Generate(List<ProcessProfile> profiles)
    {
        var sb = new StringBuilder();
        string line = new string('═', 80);
        string thin = new string('─', 80);

        sb.AppendLine(line);
        sb.AppendLine($"  Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine(line);
        sb.AppendLine();
        sb.AppendLine("  This file contains all raw telemetry collected during the monitoring session.");
        sb.AppendLine("  Tip: Use Ctrl+F to search for keywords (file paths, IPs, domains, etc.).");
        sb.AppendLine();

        sb.AppendLine(thin);
        sb.AppendLine("  TABLE OF CONTENTS");
        sb.AppendLine(thin);
        int sectionNum = 1;
        foreach (var p in profiles)
        {
            sb.AppendLine($"  [{sectionNum}] {p.ProcessName} (PID {p.ProcessId}) — {FormatTimelineCount(p.EventTimeline.Count)}");
            sectionNum++;
        }
        sb.AppendLine();

        sectionNum = 1;
        foreach (var p in profiles)
        {
            sb.AppendLine(line);
            sb.AppendLine($"  [{sectionNum}] PROCESS: {p.ProcessName}");
            sb.AppendLine($"      PID:         {p.ProcessId}");
            sb.AppendLine($"      First seen:  {p.FirstSeen:yyyy-MM-dd HH:mm:ss.fff}");
            sb.AppendLine($"      File writes: {p.TotalFileWrites}    File deletes: {p.TotalFileDeletes}");
            sb.AppendLine(line);
            sb.AppendLine();

            var events = p.EventTimeline.OrderBy(e => e.Timestamp).ToList();
            bool anyContent = events.Count > 0;

            if (anyContent)
            {
                sb.AppendLine($"  ── EVENT LOG ({events.Count} entries) ──────────────────────────────────");
                sb.AppendLine();

                foreach (var e in events)
                {
                    string time  = e.Timestamp.ToString("HH:mm:ss.fff");
                    string label = FriendlyLabel(e.EventType);

                    sb.AppendLine($"  [{time}]  {label}");

                    if (!string.IsNullOrWhiteSpace(e.RawData))
                        sb.AppendLine($"             Data:      {e.RawData}");
                    if (!string.IsNullOrWhiteSpace(e.MatchedIndicator))
                        sb.AppendLine($"             Indicator: {e.MatchedIndicator}");
                }

                sb.AppendLine();
            }

            var spawned = p.SpawnedCommandLines.OrderBy(s => s.StartTime).ToList();
            if (spawned.Count > 0)
            {
                anyContent = true;
                sb.AppendLine($"  ── SPAWNED PROCESSES ({spawned.Count} total) ──────────────────────────");
                sb.AppendLine();
                foreach (var s in spawned)
                {
                    string time = s.StartTime != default ? s.StartTime.ToString("HH:mm:ss.fff") : "??:??:??.???";
                    sb.AppendLine($"  [{time}]  Process Spawn  →  {s.Name}  (PID {s.Pid})");
                    if (!string.IsNullOrWhiteSpace(s.ImagePath))
                        sb.AppendLine($"             Path:    {s.ImagePath}");
                    if (!string.IsNullOrWhiteSpace(s.CommandLine))
                        sb.AppendLine($"             Command: {s.CommandLine}");
                }
                sb.AppendLine();
            }

            var dropped = p.ExeDropPaths.Keys.OrderBy(x => x).ToList();
            if (dropped.Count > 0)
            {
                anyContent = true;
                sb.AppendLine($"  ── DROPPED EXECUTABLES ({dropped.Count} total) ──────────────────────");
                sb.AppendLine();
                foreach (var path in dropped)
                    sb.AppendLine($"             {path}");
                sb.AppendLine();
            }

            var deleted = p.DeletedPaths.OrderBy(x => x).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (deleted.Count > 0)
            {
                anyContent = true;
                sb.AppendLine($"  ── DELETED FILES ({deleted.Count} total) ───────────────────────────");
                sb.AppendLine();
                foreach (var path in deleted)
                    sb.AppendLine($"             {path}");
                sb.AppendLine();
            }

            var writeDirs = p.WriteDirectories
                .OrderByDescending(kvp => kvp.Value)
                .ToList();
            if (writeDirs.Count > 0)
            {
                anyContent = true;
                sb.AppendLine($"  ── WRITTEN DIRECTORIES ({writeDirs.Count} dirs, {p.TotalFileWrites} total writes) ──");
                sb.AppendLine();
                foreach (var kvp in writeDirs)
                    sb.AppendLine($"             {kvp.Key}  (×{kvp.Value})");
                sb.AppendLine();
            }

            if (!anyContent)
            {
                sb.AppendLine("  (no events recorded for this process)");
                sb.AppendLine();
            }

            sectionNum++;
        }

        sb.AppendLine(line);
        sb.AppendLine("  END OF METADATA");
        sb.AppendLine(line);

        return sb.ToString();
    }
}
