using System;
using System.IO;
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
