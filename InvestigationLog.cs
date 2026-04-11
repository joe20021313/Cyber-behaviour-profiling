using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Cyber_behaviour_profiling
{
    public static class InvestigationLog
    {
        private static readonly StringBuilder _buffer = new();
        private static readonly object _lock = new();

        public static void Section(string title)
        {
            string line = new('─', 60);
            lock (_lock)
            {
                _buffer.AppendLine();
                _buffer.AppendLine(line);
                _buffer.AppendLine($"  {title}");
                _buffer.AppendLine(line);
            }
        }

        public static void Write(string message)
        {
            lock (_lock)
            {
                _buffer.AppendLine(message);
            }
        }

        public static void BeginSession(string sessionId, IEnumerable<string> targets, string dataFilePath,
            bool powerShellLoggingEnabled)
        {
            string[] orderedTargets = targets?
                .Where(target => !string.IsNullOrWhiteSpace(target))
                .ToArray() ?? Array.Empty<string>();

            lock (_lock)
            {
                _buffer.Clear();
                _buffer.AppendLine($"Session: {sessionId}");
                _buffer.AppendLine($"Started: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                _buffer.AppendLine($"Targets: {(orderedTargets.Length == 0 ? "none" : string.Join(", ", orderedTargets))}");
                _buffer.AppendLine($"Rules file: {dataFilePath}");
                _buffer.AppendLine($"PowerShell logging: {(powerShellLoggingEnabled ? "enabled" : "disabled")}");
            }
        }

        public static void WriteStage(string stage, string message)
        {
            string normalizedStage = string.IsNullOrWhiteSpace(stage) ? "session" : stage.Trim();
            Write($"[{DateTime.Now:HH:mm:ss}] [{normalizedStage}] {message}");
        }

        public static void EndSession(string overallGrade, int profileCount, int narrativeCount)
        {
            lock (_lock)
            {
                _buffer.AppendLine();
                _buffer.AppendLine($"Completed: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                _buffer.AppendLine($"Overall grade: {overallGrade}");
                _buffer.AppendLine($"Profiles analyzed: {profileCount}");
                _buffer.AppendLine($"Narratives generated: {narrativeCount}");
            }
        }

        public static string GetContents()
        {
            lock (_lock)
            {
                return _buffer.ToString();
            }
        }

        public static void Clear()
        {
            lock (_lock)
            {
                _buffer.Clear();
            }
        }

        public static void SaveToFile(string filePath)
        {
            string contents;
            lock (_lock)
            {
                contents = _buffer.ToString();
            }
            File.WriteAllText(filePath, contents, Encoding.UTF8);
        }
    }
}
