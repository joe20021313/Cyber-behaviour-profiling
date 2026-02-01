using System;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Xml;
using Microsoft.Diagnostics.Tracing.Parsers.IIS_Trace;

partial class Program
{
    Dictionary<string, string> ageMap = new Dictionary<string, string>();
    static void Main(string[] args)
    {
        Console.WriteLine("Enter process name to monitor");
        string targetProcess = Console.ReadLine()?.ToLower() ?? "";

        if (string.IsNullOrWhiteSpace(targetProcess))
        {
            Console.WriteLine("No process name provided. Exiting.");
            return;
        }

         MonitorSysmon(targetProcess);
    }

    public static void MonitorSysmon(string targetProcess)
    {
         if (!OperatingSystem.IsWindows())
        {
            Console.WriteLine("Sysmon monitoring via EventLogWatcher is only supported on Windows.");
            return;
        }

        string query = "*[System]";
        var eventLogQuery = new EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName, query);
        using (var watcher = new EventLogWatcher(eventLogQuery))
        {
            Console.WriteLine($"Monitoring '{targetProcess}' for file activity via Sysmon...");
            Console.WriteLine("Press Ctrl+C to stop.");

            watcher.EventRecordWritten += (sender, e) =>
            {
                 if (!OperatingSystem.IsWindows()) {
            Console.WriteLine("Sysmon monitoring via EventLogWatcher is only supported on Windows.");
            return;
        }
                if (e.EventRecord != null)
                {
                    ProcessSysmonEvent(e.EventRecord, targetProcess);
                }

            };

            watcher.Enabled = true;
            Console.ReadLine();

        }
    }

    static void ProcessSysmonEvent(EventRecord record, string targetProcess)
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

            Console.WriteLine($"[Event ID {eventId}] {GetEventName(eventId)}");

            var dataNodes = doc.SelectNodes("
            foreach (XmlNode node in dataNodes)
            {
                string name = node.Attributes?["Name"]?.Value ?? "";
                string value = node.InnerText;
                Console.WriteLine($"  {name}: {value}");
            }
            Console.WriteLine("---------------------------------------------------------");
        } catch (Exception ex)
        {
            Console.WriteLine($"Error processing Sysmon event: {ex.Message}");
        }
    }

    static string GetEventName(int eventId)
    {
        return eventId switch
        {
            1 => "ProcessCreate",
            3 => "NetworkConnect",
            10 => "ProcessAccess",
            11 => "FileCreate",
            23 => "FileDelete",
            _ => $"Event {eventId}"
        };
    }

    public static void MonitorProcess(string targetProcess)
    {
        using (var session = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
        {
            Console.CancelKeyPress += (sender, e) => { session.Stop(); };

            session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.FileIO |
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.Registry
            );

            Console.WriteLine($"Monitoring '{targetProcess}' for file activity...");
            Console.WriteLine("Press Ctrl+C to stop.");
            Console.WriteLine("---------------------------------------------------------");

            session.Source.Kernel.RegistryCreate += data =>
            {
                string process = data.ProcessName?.ToLower() ?? "";

                if (process.Contains(targetProcess))
                {
                    Console.WriteLine($"[WRITE] Process: {data.ProcessName}");
                      Console.WriteLine($"        Time: {data.KeyName}");
                    Console.WriteLine($"        Time: {data.TimeStamp}");
                    Console.WriteLine("---------------------------------------------------------");
                }
            };

              session.Source.Kernel.RegistryOpen += data =>
            {
                string process = data.ProcessName?.ToLower() ?? "";

                if (process.Contains(targetProcess))
                {
                    Console.WriteLine($"[WRITE] Process: {data.ProcessName}");
                      Console.WriteLine($"        Time: {data.KeyName}");
                    Console.WriteLine($"        Time: {data.TimeStamp}");
                    Console.WriteLine("---------------------------------------------------------");
                }
            };
            session.Source.Kernel.FileIOWrite += data =>
            {
                string process = data.ProcessName?.ToLower() ?? "";
                string file = data.FileName?.ToLower() ?? "";

                if (process.Contains(targetProcess))
                {
                    Console.WriteLine($"[WRITE] Process: {data.ProcessName}");
                    Console.WriteLine($"        File: {data.ID}");
                    Console.WriteLine($"        Size: {data.IoSize} bytes");
                    Console.WriteLine($"        Time: {data.TimeStamp}");
                    Console.WriteLine("---------------------------------------------------------");
                }
            };

            session.Source.Kernel.FileIORead += data =>
            {
                string process = data.ProcessName?.ToLower() ?? "";
                string file = data.FileName?.ToLower() ?? "";

                if (process.Contains(targetProcess))
                {
                    Console.WriteLine($"[READ] Process: {data.ProcessName}");
                    Console.WriteLine($"       ID: {data.ProcessID}");
                    Console.WriteLine($"       File: {data.FileName}");
                    Console.WriteLine($"       Size: {data.IoSize} bytes");
                    Console.WriteLine($"       Time: {data.TimeStamp}");
                    Console.WriteLine("---------------------------------------------------------");
                }
            };

            session.Source.Process();
        }
    }
}