using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace Cyber_behaviour_profiling
{
    public static class ConsoleSummarizer
    {
        private class PidStats
        {
            public string ProcessName { get; set; }
            public ConcurrentDictionary<string, int> DirReadCounts  { get; } = new(StringComparer.OrdinalIgnoreCase);
            public ConcurrentDictionary<string, int> DirWriteCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
            public ConcurrentDictionary<string, int> DirOpenCounts  { get; } = new(StringComparer.OrdinalIgnoreCase);
            public ConcurrentDictionary<string, int> RegHiveCounts  { get; } = new(StringComparer.OrdinalIgnoreCase);
            public ConcurrentDictionary<string, int> RegWriteCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
            public DateTime LastFlushed { get; set; } = DateTime.Now;
        }

        private static readonly ConcurrentDictionary<int, PidStats> _stats = new();
        private static readonly Timer _flushTimer;

        static ConsoleSummarizer()
        {
            _flushTimer = new Timer(_ => FlushAll(), null, 3000, 3000);
        }

        public static void TrackFileAccess(int pid, string processName, string filePath, string mode)
        {
            if (string.IsNullOrEmpty(filePath)) return;

            var stats = _stats.GetOrAdd(pid, _ => new PidStats { ProcessName = processName });
            string dir = GetTopDirectory(filePath);

            switch (mode)
            {
                case "Read":  stats.DirReadCounts.AddOrUpdate(dir, 1, (_, c) => c + 1);  break;
                case "Write": stats.DirWriteCounts.AddOrUpdate(dir, 1, (_, c) => c + 1); break;
                case "Open":  stats.DirOpenCounts.AddOrUpdate(dir, 1, (_, c) => c + 1);  break;
            }
        }

        public static void TrackRegistryAccess(int pid, string processName, string keyPath, string mode)
        {
            if (string.IsNullOrEmpty(keyPath)) return;

            var stats = _stats.GetOrAdd(pid, _ => new PidStats { ProcessName = processName });
            string hive = GetRegistryHive(keyPath);

            if (mode == "Write")
                stats.RegWriteCounts.AddOrUpdate(hive, 1, (_, c) => c + 1);
            else
                stats.RegHiveCounts.AddOrUpdate(hive, 1, (_, c) => c + 1);
        }

        private static void FlushAll()
        {
            foreach (var (pid, stats) in _stats)
            {
                stats.DirReadCounts.Clear();
                stats.DirWriteCounts.Clear();
                stats.DirOpenCounts.Clear();
                stats.RegHiveCounts.Clear();
                stats.RegWriteCounts.Clear();
            }
        }

        private static string GetTopDirectory(string filePath)
        {
            try
            {
                string dir = Path.GetDirectoryName(filePath) ?? filePath;
                var parts = dir.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length <= 5) return dir;
                return string.Join("\\", parts.Take(5)) + "\\...";
            }
            catch { return filePath; }
        }

        private static string GetRegistryHive(string keyPath)
        {
            string norm = keyPath
                .Replace("\\Registry\\Machine\\", "HKLM\\")
                .Replace("\\Registry\\User\\", "HKU\\")
                .Replace("\\registry\\machine\\", "HKLM\\")
                .Replace("\\registry\\user\\", "HKU\\");

            var parts = norm.Split('\\', StringSplitOptions.RemoveEmptyEntries);
            return parts.Length >= 3 ? string.Join("\\", parts.Take(3)) : norm;
        }
    }
}
