using System.Text;

public static class MetadataExporter
{
    public static string Generate(List<ProcessProfile> profiles)
    {
        var sb = new StringBuilder();
        string line = new string('═', 80);
        string thin = new string('─', 80);

        sb.AppendLine(line);
        sb.AppendLine("  PROGRAM LIFECYCLE METADATA");
        sb.AppendLine($"  Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine(line);
        sb.AppendLine();
        sb.AppendLine("  This file contains all raw telemetry collected during the monitoring session.");
        sb.AppendLine("  Data is grouped by process, then by event type.");
        sb.AppendLine("  Tip: Use Ctrl+F to search for keywords (file paths, IPs, domains, etc.).");
        sb.AppendLine();

        sb.AppendLine(thin);
        sb.AppendLine("  TABLE OF CONTENTS");
        sb.AppendLine(thin);
        int sectionNum = 1;
        foreach (var p in profiles)
        {
            int eventCount = p.EventTimeline.Count
                + p.ExeDropPaths.Count
                + p.DeletedPaths.Count
                + p.SpawnedCommandLines.Count;
            sb.AppendLine($"  [{sectionNum}] {p.ProcessName} (PID {p.ProcessId}) — {eventCount} events");
            sectionNum++;
        }
        sb.AppendLine();

        sectionNum = 1;
        foreach (var p in profiles)
        {
            sb.AppendLine(line);
            sb.AppendLine($"  [{sectionNum}] PROCESS: {p.ProcessName}");
            sb.AppendLine($"      PID:        {p.ProcessId}");
            sb.AppendLine($"      First seen: {p.FirstSeen:yyyy-MM-dd HH:mm:ss.fff}");
            sb.AppendLine($"      File writes: {p.TotalFileWrites}    File deletes: {p.TotalFileDeletes}");
            sb.AppendLine(line);
            sb.AppendLine();

            var events = p.EventTimeline.OrderBy(e => e.Timestamp).ToList();

            var grouped = events
                .GroupBy(e => e.EventType ?? "Unknown")
                .OrderBy(g => g.Key);

            bool anyContent = false;

            foreach (var group in grouped)
            {
                anyContent = true;
                sb.AppendLine($"  ┌─ {group.Key} ({group.Count()} events)");
                sb.AppendLine($"  │");

                var collapsed = CollapseRepeats(group.ToList());

                foreach (var entry in collapsed)
                {
                    string time = entry.Timestamp.ToString("HH:mm:ss.fff");
                    string repeat = entry.AttemptCount > 1 ? $" (×{entry.AttemptCount})" : "";
                    string lastSeen = entry.AttemptCount > 1 && entry.LastSeen > entry.Timestamp
                        ? $"  last: {entry.LastSeen:HH:mm:ss.fff}"
                        : "";

                    sb.AppendLine($"  │  [{time}]{repeat}{lastSeen}");

                    if (!string.IsNullOrWhiteSpace(entry.Tactic))
                        sb.AppendLine($"  │    Tactic:    {entry.Tactic}");
                    if (!string.IsNullOrWhiteSpace(entry.TechniqueId))
                        sb.AppendLine($"  │    Technique: {entry.TechniqueId} — {entry.TechniqueName}");
                    if (!string.IsNullOrWhiteSpace(entry.MatchedIndicator))
                        sb.AppendLine($"  │    Indicator: {entry.MatchedIndicator}");
                    if (!string.IsNullOrWhiteSpace(entry.RawData))
                        sb.AppendLine($"  │    Data:      {entry.RawData}");
                    sb.AppendLine($"  │");
                }

                sb.AppendLine($"  └─");
                sb.AppendLine();
            }

            var spawned = p.SpawnedCommandLines.ToList();
            if (spawned.Count > 0)
            {
                anyContent = true;
                sb.AppendLine($"  ┌─ Spawned Processes ({spawned.Count} total)");
                sb.AppendLine($"  │");

                var spawnCollapsed = spawned
                    .GroupBy(s => $"{s.ChildName}|{s.CommandLine}", StringComparer.OrdinalIgnoreCase)
                    .Select(g => (g.First().ChildName, g.First().CommandLine, Count: g.Count()))
                    .OrderBy(s => s.ChildName);

                foreach (var (child, cmd, count) in spawnCollapsed)
                {
                    string repeat = count > 1 ? $" (×{count})" : "";
                    sb.AppendLine($"  │  {child}{repeat}");
                    if (!string.IsNullOrWhiteSpace(cmd))
                        sb.AppendLine($"  │    Command: {cmd}");
                    sb.AppendLine($"  │");
                }

                sb.AppendLine($"  └─");
                sb.AppendLine();
            }

            var dropped = p.ExeDropPaths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (dropped.Count > 0)
            {
                anyContent = true;
                sb.AppendLine($"  ┌─ Dropped Executables ({dropped.Count} total)");
                sb.AppendLine($"  │");
                foreach (var path in dropped)
                    sb.AppendLine($"  │  {path}");
                sb.AppendLine($"  │");
                sb.AppendLine($"  └─");
                sb.AppendLine();
            }

            var deleted = p.DeletedPaths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (deleted.Count > 0)
            {
                anyContent = true;
                sb.AppendLine($"  ┌─ Deleted Files ({deleted.Count} total)");
                sb.AppendLine($"  │");
                foreach (var path in deleted)
                    sb.AppendLine($"  │  {path}");
                sb.AppendLine($"  │");
                sb.AppendLine($"  └─");
                sb.AppendLine();
            }

            var writeDirs = p.WriteDirectories
                .OrderByDescending(kvp => kvp.Value)
                .ToList();
            if (writeDirs.Count > 0)
            {
                anyContent = true;
                sb.AppendLine($"  ┌─ Write Directories ({writeDirs.Count} total, {p.TotalFileWrites} writes)");
                sb.AppendLine($"  │");
                foreach (var kvp in writeDirs)
                    sb.AppendLine($"  │  {kvp.Key}  (×{kvp.Value})");
                sb.AppendLine($"  │");
                sb.AppendLine($"  └─");
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

    private static List<SuspiciousEvent> CollapseRepeats(List<SuspiciousEvent> events)
    {
        var result = new List<SuspiciousEvent>();
        var seen = new Dictionary<string, SuspiciousEvent>(StringComparer.OrdinalIgnoreCase);

        foreach (var e in events)
        {
            string key = $"{e.Tactic}|{e.TechniqueId}|{e.RawData}";

            if (seen.TryGetValue(key, out var existing))
            {
                existing.AttemptCount += e.AttemptCount;
                if (e.Timestamp > existing.LastSeen)
                    existing.LastSeen = e.Timestamp;
            }
            else
            {
                var clone = new SuspiciousEvent
                {
                    Timestamp        = e.Timestamp,
                    LastSeen         = e.LastSeen > e.Timestamp ? e.LastSeen : e.Timestamp,
                    Tactic           = e.Tactic,
                    TechniqueId      = e.TechniqueId,
                    TechniqueName    = e.TechniqueName,
                    EventType        = e.EventType,
                    MatchedIndicator = e.MatchedIndicator,
                    RawData          = e.RawData,
                    AttemptCount     = e.AttemptCount,
                };
                seen[key] = clone;
                result.Add(clone);
            }
        }

        return result;
    }
}
