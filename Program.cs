using System;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Xml;
using Microsoft.Diagnostics.Tracing.Parsers.IIS_Trace;
using System.Diagnostics;
using System.Threading;
using System.IO;
public partial class Program
{
    Dictionary<string, string> ageMap = new Dictionary<string, string>();
    private static List<string> logEntries = new List<string>();
    private static object logLock = new object();

    public static void Main(string[] args)

    {
        logEntries.Add("Activity Log - " + DateTime.Now);
        Console.WriteLine("Enter process name to monitor");
        string targetProcess = Console.ReadLine()?.ToLower() ?? "";

        if (string.IsNullOrWhiteSpace(targetProcess))
        {
            Console.WriteLine("No process name provided. Exiting.");
            return;
        }

        Console.CancelKeyPress += (sender, e) =>
        {
            e.Cancel = true;
            Console.WriteLine("\nSaving logs to file...");
            SaveAllLogsToFile("activity_log.txt");
            Console.WriteLine("Logs saved. Exiting.");
            Environment.Exit(0);
        };

        Thread workerThread = new Thread(new ThreadStart(() => MonitorSysmon(targetProcess)));
        workerThread.Start();
        Thread workerThread1 = new Thread(new ThreadStart(() => MonitorProcess(targetProcess)));
        workerThread1.Start();

        workerThread.Join();
        workerThread1.Join();
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
                if (!OperatingSystem.IsWindows())
                {
                    Console.WriteLine("Sysmon monitoring via EventLogWatcher is only supported on Windows.");
                    return;
                }
                if (e.EventRecord != null)
                {
                    ProcessSysmonEvent(e.EventRecord, targetProcess);
                }
            };

            watcher.Enabled = true;

            while (true)
            {
                Thread.Sleep(1000);
            }
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

        }
        catch (Exception ex)
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
                KernelTraceEventParser.Keywords.Registry |
                KernelTraceEventParser.Keywords.Memory
            );

            Console.WriteLine($"Monitoring '{targetProcess}' for file activity...");
            Console.WriteLine("Press Ctrl+C to stop.");
            Console.WriteLine("---------------------------------------------------------");

            session.Source.Kernel.RegistryCreate += data =>
            {
                string process = data.ProcessName?.ToLower() ?? "";

                if (process.Contains(targetProcess))
                {
                    Console.WriteLine($"Type: Registry create");
                    Console.WriteLine($"[WRITE] Process: {data.ProcessName}");
                    Console.WriteLine($"        Key path: {data.KeyName}");
                    Console.WriteLine($"        Time: {data.TimeStamp}");
                    Console.WriteLine("---------------------------------------------------------");

                    AddLogEntry($"Type: Registry create");
                    AddLogEntry($"[WRITE] Process: {data.ProcessName}");
                    AddLogEntry($"        Key path: {data.KeyName}");
                    AddLogEntry($"        Time: {data.TimeStamp}");
                    AddLogEntry("---------------------------------------------------------");
                }
            };

            session.Source.Kernel.RegistryOpen += data =>
            {
                string process = data.ProcessName?.ToLower() ?? "";

                if (process.Contains(targetProcess))
                {
                    Console.WriteLine($"Type: Registry open");
                    Console.WriteLine($"[WRITE] Process: {data.ProcessName}");
                    Console.WriteLine($"        Key path: {data.KeyName}");
                    Console.WriteLine($"        Time: {data.TimeStamp}");
                    Console.WriteLine("---------------------------------------------------------");

                    AddLogEntry($"Type: Registry open");
                    AddLogEntry($"[WRITE] Process: {data.ProcessName}");
                    AddLogEntry($"        Key path: {data.KeyName}");
                    AddLogEntry($"        Time: {data.TimeStamp}");
                    AddLogEntry("---------------------------------------------------------");
                }
            };

            session.Source.Kernel.RegistrySetValue += data =>
         {
             string process = data.ProcessName?.ToLower() ?? "";

             if (process.Contains(targetProcess))
             {
                 Console.WriteLine($"Type: Registry change");
                 Console.WriteLine($"[WRITE] Process: {data.ProcessName}");
                 Console.WriteLine($"        Key path: {data.KeyName}");
                 Console.WriteLine($"        Time: {data.TimeStamp}");
                 Console.WriteLine("---------------------------------------------------------");

                 AddLogEntry($"Type: Registry change");
                 AddLogEntry($"[WRITE] Process: {data.ProcessName}");
                 AddLogEntry($"        Key path: {data.KeyName}");
                 AddLogEntry($"        Time: {data.TimeStamp}");
                 AddLogEntry("---------------------------------------------------------");
             }
         };
            session.Source.Kernel.FileIOWrite += data =>
            {
                string process = data.ProcessName?.ToLower() ?? "";
                string file = data.FileName?.ToLower() ?? "";

                if (process.Contains(targetProcess))
                {
                    Console.WriteLine($"Type: File write");
                    Console.WriteLine($"[WRITE] Process: {data.ProcessName}");
                    Console.WriteLine($"       File: {data.FileName}");
                    Console.WriteLine($"        Size: {data.IoSize} bytes");
                    Console.WriteLine($"        Time: {data.TimeStamp}");
                    Console.WriteLine("---------------------------------------------------------");

                    AddLogEntry($"Type: File write");
                    AddLogEntry($"[WRITE] Process: {data.ProcessName}");
                    AddLogEntry($"        File: {data.FileName}");
                    AddLogEntry($"        Size: {data.IoSize} bytes");
                    AddLogEntry($"        Time: {data.TimeStamp}");
                    AddLogEntry("---------------------------------------------------------");
                }
            };

            session.Source.Kernel.FileIORead += data =>
            {
                string process = data.ProcessName?.ToLower() ?? "";
                string file = data.FileName?.ToLower() ?? "";

                if (process.Contains(targetProcess))
                {
                    Console.WriteLine($"Type: File read");
                    Console.WriteLine($"[READ] Process: {data.ProcessName}");
                    Console.WriteLine($"       ID: {data.ProcessID}");
                    Console.WriteLine($"       File: {data.FileName}");
                    Console.WriteLine($"       Size: {data.IoSize} bytes");
                    Console.WriteLine($"       Time: {data.TimeStamp}");
                    Console.WriteLine("---------------------------------------------------------");

                    AddLogEntry($"Type: File read");
                    AddLogEntry($"[READ] Process: {data.ProcessName}");
                    AddLogEntry($"       ID: {data.ProcessID}");
                    AddLogEntry($"       File: {data.FileName}");
                    AddLogEntry($"       Size: {data.IoSize} bytes");
                    AddLogEntry($"       Time: {data.TimeStamp}");
                    AddLogEntry("---------------------------------------------------------");
                }
            };

            session.Source.Process();
        }

    }

    static void readPowerShellCommands()
    {

    }

    static void dnsQuery()
    {

    }

    static void enableFirewallMonitoring()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "auditpol.exe",
                Arguments = "/set /subcategory:\"Filtering Platform Policy Change\" /success:enable /failure:enable",
                Verb = "runas",
                CreateNoWindow = true,
                UseShellExecute = true
            };
            using var proc = Process.Start(psi);
            proc.WaitForExit();
            if (proc.ExitCode == 0)
                Console.WriteLine("Firewall auditing policy enabled.");
            else
                Console.WriteLine("Failed to enable firewall auditing policy. Exit code: " + proc.ExitCode);
            Environment.Exit(1);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error enabling firewall auditing: " + ex.Message);
            Environment.Exit(1);
        }

    }

    private static void AddLogEntry(string entry)
    {
        lock (logLock)
        {
            logEntries.Add(entry);
        }
    }

    private static void SaveAllLogsToFile(string fileName)
    {
        lock (logLock)
        {
            if (logEntries.Count == 0)
            {
                Console.WriteLine("No log entries to save.");
                return;
            }

            string docPath = Directory.GetCurrentDirectory();
            string logPath = Path.Combine(docPath, fileName);

            try
            {
                File.WriteAllLines(logPath, logEntries);
                Console.WriteLine($"Saved {logEntries.Count} log entries to: {logPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving logs: {ex.Message}");
            }
        }
    }

}