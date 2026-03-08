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
using System.Collections.Concurrent;

using System.Text.Json;
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
        MapToData.LoadData("data.json");

        var monitoredPids = new HashSet<uint>();
        foreach (var p in Process.GetProcessesByName(targetProcess))
            monitoredPids.Add((uint)p.Id);

        bool ShouldMonitor(string processName, uint pid) =>
            processName?.ToLower().Contains(targetProcess) == true || monitoredPids.Contains(pid);

        using (var userSession = new TraceEventSession("DPAPIMonitorSession"))
        using (var dnsSession = new TraceEventSession("DNSMonitorSession"))
        using (var session = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
        {
            userSession.EnableProvider(
               new Guid("89fe8f40-cdce-464e-8217-15ef97d4c7c3"),
               Microsoft.Diagnostics.Tracing.TraceEventLevel.Verbose
           );

            userSession.Source.Dynamic.All += data =>
            {
                if (data.ProviderGuid == new Guid("89fe8f40-cdce-464e-8217-15ef97d4c7c3"))
                {
                    if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
                    {
                        string msg = $"[!] DPAPI DECRYPT - Process: {data.ProcessName} PID:{data.ProcessID} Event:{data.EventName} Time:{data.TimeStamp}";
                        Console.WriteLine(msg);
                        Console.WriteLine("---------------------------------------------------------");
                        AddLogEntry(msg);
                        AddLogEntry("---------------------------------------------------------");
                    }
                }
            };

            dnsSession.EnableProvider("Microsoft-Windows-DNS-Client");
            dnsSession.Source.Dynamic.All += dnsData =>
            {
                if (dnsData.EventName == "DNS_Query")
                {
                    string queriedDomain = (string)dnsData.PayloadByName("QueryName");

                    if (queriedDomain != null && MapToData._networkDomains.Contains(queriedDomain.ToLowerInvariant()))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"[ALERT] Malicious domain requested: {queriedDomain} (PID: {dnsData.ProcessID})");
                        Console.ResetColor();

                        MapToData.AddEventToProfile(dnsData.ProcessID, dnsData.ProcessName ?? "Unknown", "DNS_Query", queriedDomain, $"Requested domain: {queriedDomain}");
                    }
                }
            };

            Console.CancelKeyPress += (sender, e) =>
            {
                session.Stop();
                userSession.Stop();
                dnsSession.Stop();
            };

            session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.FileIO |
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.Registry |
                KernelTraceEventParser.Keywords.DiskFileIO |
                KernelTraceEventParser.Keywords.NetworkTCPIP
            );

            Console.WriteLine($"Monitoring '{targetProcess}' for file activity...");
            Console.WriteLine("Press Ctrl+C to stop.");
            Console.WriteLine("---------------------------------------------------------");

            session.Source.Kernel.ProcessStart += data =>
            {
                if (monitoredPids.Contains((uint)data.ParentID))
                {
                    monitoredPids.Add((uint)data.ProcessID);

                    Console.WriteLine($" PROCESS SPAWNED");
                    Console.WriteLine($"   Parent Process: {targetProcess}");
                    Console.WriteLine($"   New Process: {data.ImageFileName}");
                    Console.WriteLine($"   Command Line: {data.CommandLine}");
                    Console.WriteLine($"   Time: {data.TimeStamp}");
                    Console.WriteLine("---------------------------------------------------------");

                    AddLogEntry($" PROCESS SPAWNED");
                    AddLogEntry($"   Parent Process: {targetProcess}");
                    AddLogEntry($"   New Process: {data.ImageFileName}");
                    AddLogEntry($"   Command Line: {data.CommandLine}");
                    AddLogEntry($"   Time: {data.TimeStamp}");

                    MapToData.EvaluateProcessSpawn(data.ParentID, targetProcess, data.ProcessID, data.ProcessName ?? "", data.CommandLine ?? "");
                }
            };

            session.Source.Kernel.RegistryCreate += data =>
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
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

                    MapToData.EvaluateRegistryAccess(data.ProcessID, data.ProcessName ?? "", data.KeyName ?? "");
                }
            };

            session.Source.Kernel.RegistryOpen += data =>
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
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

                    MapToData.EvaluateRegistryAccess(data.ProcessID, data.ProcessName ?? "", data.KeyName ?? "");
                }
            };

            session.Source.Kernel.RegistrySetValue += data =>
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
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

                    MapToData.EvaluateRegistryAccess(data.ProcessID, data.ProcessName ?? "", data.KeyName ?? "");
                }
            };

            session.Source.Kernel.FileIOWrite += data =>
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
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

                    MapToData.EvaluateFileOperation(data.ProcessID, data.ProcessName ?? "", data.FileName ?? "", "FileWrite");
                }
            };

            session.Source.Kernel.FileIOCreate += data =>
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
                {
                    if (string.IsNullOrEmpty(data.FileName)) return;

                    MapToData.EvaluateFileOperation(data.ProcessID, data.ProcessName, data.FileName, "FileOpen");

                    Console.WriteLine($"Type: File Open");
                    Console.WriteLine($"[READ] Process: {data.ProcessName}");
                    Console.WriteLine($"       ID: {data.ProcessID}");
                    Console.WriteLine($"       File: {data.FileName}");
                    Console.WriteLine($"       Time: {data.TimeStamp}");
                    Console.WriteLine("---------------------------------------------------------");

                    AddLogEntry($"Type: File Open");
                    AddLogEntry($"[READ] Process: {data.ProcessName}");
                    AddLogEntry($"       ID: {data.ProcessID}");
                    AddLogEntry($"       File: {data.FileName}");
                    AddLogEntry($"       Time: {data.TimeStamp}");
                    AddLogEntry("---------------------------------------------------------");
                }
            };

            session.Source.Kernel.FileIORead += data =>
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
                {
                    if (string.IsNullOrEmpty(data.FileName)) return;

                    MapToData.EvaluateFileOperation(data.ProcessID, data.ProcessName, data.FileName, "FileRead");

                    Console.WriteLine($"Type: File read");
                    Console.WriteLine($"[READ] Process: {data.ProcessName}");
                    Console.WriteLine($"       ID: {data.ProcessID}");
                    Console.WriteLine($"       File: {data.FileName}");
                    Console.WriteLine($"       Time: {data.TimeStamp}");
                    Console.WriteLine("---------------------------------------------------------");

                    AddLogEntry($"Type: File read");
                    AddLogEntry($"[READ] Process: {data.ProcessName}");
                    AddLogEntry($"       ID: {data.ProcessID}");
                    AddLogEntry($"       File: {data.FileName}");
                    AddLogEntry($"       Time: {data.TimeStamp}");
                    AddLogEntry("---------------------------------------------------------");
                }
            };

            session.Source.Kernel.TcpIpConnect += data =>
            {
                if (ShouldMonitor(data.ProcessName, (uint)data.ProcessID))
                {
                    string msg = $"[!] NETWORK CONNECT - Process: {data.ProcessName} -> {data.daddr}:{data.dport} Time:{data.TimeStamp}";
                    Console.WriteLine(msg);
                    Console.WriteLine("---------------------------------------------------------");
                    AddLogEntry(msg);
                    AddLogEntry("---------------------------------------------------------");

                    MapToData.EvaluateNetworkConnection(data);
                }
            };

            Thread dpapiThread = new Thread(() => userSession.Source.Process());
            dpapiThread.IsBackground = true;
            dpapiThread.Start();

            Thread dnsThread = new Thread(() => dnsSession.Source.Process());
            dnsThread.IsBackground = true;
            dnsThread.Start();

            session.Source.Process();
        }
    }

    static void readPowerShellCommands()
    {

    }

    static void dnsQuery()
    {

    }
    public static void UACBypassRegistryKeys()
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

public class SuspiciousEvent
{
    public DateTime Timestamp { get; set; }
    public string EventType { get; set; }
    public string MatchedIndicator { get; set; }
    public string RawData { get; set; }
}

public class ProcessProfile
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; }
    public DateTime FirstSeen { get; set; }

    public ConcurrentBag<SuspiciousEvent> EventTimeline { get; set; } = new ConcurrentBag<SuspiciousEvent>();

}

public class FileOperationsData
{
    public List<string> suspicious_reads { get; set; } = new List<string>();
    public List<string> uncommon_writes { get; set; } = new List<string>();
    public List<string> suspicious_overwrites { get; set; } = new List<string>();
}

public class RegistryData
{
    public List<string> persistence { get; set; } = new List<string>();
    public List<string> tampering { get; set; } = new List<string>();
    public List<string> uac_bypass { get; set; } = new List<string>();
    public List<string> credential_access { get; set; } = new List<string>();
}

public class NetworkData
{
    public List<string> suspicious_domains { get; set; } = new List<string>();
    public List<int> suspicious_ports { get; set; } = new List<int>();
}

public class ProcessData
{
    public List<string> lolbins { get; set; } = new List<string>();
    public List<string> accessibility_binaries { get; set; } = new List<string>();
    public List<string> suspicious_commands { get; set; } = new List<string>();
}

public class ThreatData
{
    public FileOperationsData file_operations { get; set; } = new FileOperationsData();
    public RegistryData registry { get; set; } = new RegistryData();
    public NetworkData network { get; set; } = new NetworkData();
    public ProcessData processes { get; set; } = new ProcessData();
}

public static class MapToData
{
    private static FileOperationsData _fileOps = new FileOperationsData();
    private static RegistryData _registryOps = new RegistryData();
    public static List<string> _networkDomains = new List<string>();
    private static List<int> _suspiciousPorts = new List<int>();
    private static HashSet<string> _suspiciousProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static List<string> _suspiciousCommands = new List<string>();

    public static ConcurrentDictionary<int, ProcessProfile> ActiveProfiles = new ConcurrentDictionary<int, ProcessProfile>();

    private static List<string> FormatList(List<string> input)
    {
        if (input == null) return new List<string>();
        return input.Select(p => Environment.ExpandEnvironmentVariables(p.Replace("@", "")).ToLowerInvariant()).ToList();
    }

    public static void LoadData(string jsonFilePath)
    {
        string json = File.ReadAllText(jsonFilePath);
        var data = JsonSerializer.Deserialize<ThreatData>(json);
        if (data == null) return;

        if (data.file_operations != null)
        {
            _fileOps.suspicious_reads    = FormatList(data.file_operations.suspicious_reads);
            _fileOps.uncommon_writes     = FormatList(data.file_operations.uncommon_writes);
            _fileOps.suspicious_overwrites = FormatList(data.file_operations.suspicious_overwrites);
        }

        if (data.registry != null)
        {
            string clean(string r) => r.Replace("HKCU\\\\", "").Replace("HKEY_LOCAL_MACHINE\\\\", "").ToLowerInvariant();
            _registryOps.persistence       = data.registry.persistence?.Select(clean).ToList()       ?? new List<string>();
            _registryOps.tampering         = data.registry.tampering?.Select(clean).ToList()         ?? new List<string>();
            _registryOps.uac_bypass        = data.registry.uac_bypass?.Select(clean).ToList()        ?? new List<string>();
            _registryOps.credential_access = data.registry.credential_access?.Select(clean).ToList() ?? new List<string>();
        }

        if (data.network != null)
        {
            _networkDomains  = data.network.suspicious_domains?.Select(d => d.ToLowerInvariant()).ToList() ?? new List<string>();
            _suspiciousPorts = data.network.suspicious_ports ?? new List<int>();
        }

        _suspiciousProcesses.Clear();
        _suspiciousCommands.Clear();
        if (data.processes != null)
        {
            var all = (data.processes.lolbins ?? new List<string>())
                      .Concat(data.processes.accessibility_binaries ?? new List<string>());
            foreach (var p in all) _suspiciousProcesses.Add(p.ToLowerInvariant());
            _suspiciousCommands = data.processes.suspicious_commands?.Select(c => c.ToLowerInvariant()).ToList() ?? new List<string>();
        }
    }

    public static void EvaluateFileOperation(int pid, string processName, string filePath, string eventType)
    {
        string lowerPath = filePath.ToLowerInvariant();
        string match = null;
        string category = "FileOperation";

        if (eventType == "FileRead")
        {
            match = _fileOps.suspicious_reads.FirstOrDefault(r => lowerPath.Contains(r));
            if (match != null) category = "Sensitive File Read";
        }
        else if (eventType == "FileWrite" || eventType == "FileOpen")
        {
            match = _fileOps.uncommon_writes.FirstOrDefault(r => lowerPath.Contains(r));
            if (match != null) { category = "Uncommon Location Write"; }
            else
            {
                match = _fileOps.suspicious_overwrites.FirstOrDefault(r => lowerPath.Contains(r));
                if (match != null) category = "Suspicious Bin Overwrite";
            }
        }

        if (match != null) AddEventToProfile(pid, processName, category, match, filePath);
    }

    public static void EvaluateRegistryAccess(int pid, string processName, string registryKey)
    {
        string lowerKey = registryKey.ToLowerInvariant();
        string match = null;
        string category = "";

        if      ((match = _registryOps.persistence.FirstOrDefault(r => lowerKey.Contains(r)))       != null) category = "Registry Persistence";
        else if ((match = _registryOps.tampering.FirstOrDefault(r => lowerKey.Contains(r)))         != null) category = "Registry Tampering";
        else if ((match = _registryOps.uac_bypass.FirstOrDefault(r => lowerKey.Contains(r)))        != null) category = "Registry UAC Bypass";
        else if ((match = _registryOps.credential_access.FirstOrDefault(r => lowerKey.Contains(r))) != null) category = "Registry Credential Access";

        if (match != null) AddEventToProfile(pid, processName, category, match, registryKey);
    }

    public static void EvaluateProcessSpawn(int parentPid, string parentProcessName, int childPid, string childProcessName, string commandLine)
    {
        if (_suspiciousProcesses.Contains(childProcessName.ToLowerInvariant()))
            AddEventToProfile(parentPid, parentProcessName, "SuspiciousProcessSpawn", childProcessName, $"Spawned: {childProcessName} (PID: {childPid})");

        if (!string.IsNullOrEmpty(commandLine))
        {
            string lowerCmd = commandLine.ToLowerInvariant();
            string match = _suspiciousCommands.FirstOrDefault(rule => lowerCmd.Contains(rule));
            if (match != null) AddEventToProfile(parentPid, parentProcessName, "SuspiciousCommand", match, $"Command Line: {commandLine}");
        }
    }
    public static void SaveToFile(string outputPath)
    {
        var lines = new List<string>();
        int a = 1;
        foreach (var profile in ActiveProfiles.Values)
        {
            lines.Add($"  Process #{a}");
            lines.Add($"  Process Name : {profile.ProcessName}");
            lines.Add($"  Process ID   : {profile.ProcessId}");
            lines.Add($"  First Seen   : {profile.FirstSeen:yyyy-MM-dd HH:mm:ss}");
            lines.Add($"  Total Events : {profile.EventTimeline.Count}");
            a++;

            if (profile.EventTimeline.Count == 0)
            {
                lines.Add("  No suspicious events recorded.");
            }
            else
            {
                int i = 1;
                foreach (var ev in profile.EventTimeline.OrderBy(e => e.Timestamp))
                {
                    lines.Add($"  Event #{i}");
                    lines.Add($"  Timestamp        : {ev.Timestamp:yyyy-MM-dd HH:mm:ss.fff}");
                    lines.Add($"   Event Type       : {ev.EventType}");
                    lines.Add($"   Matched Indicator: {ev.MatchedIndicator}");
                    lines.Add($"   Raw Data         : {ev.RawData}");
                    lines.Add("===========================================================");
                    i++;
                }
            }

            File.WriteAllLines(outputPath, lines);
            Console.WriteLine($"[+] Profile dump saved to: {outputPath}");

        }

    }
    public static void AddEventToProfile(int pid, string processName, string eventType, string matchedRule, string rawData)
    {
        var profile = ActiveProfiles.GetOrAdd(pid, newId => new ProcessProfile
        {
            ProcessId = newId,
            ProcessName = processName,
            FirstSeen = DateTime.Now
        });

        profile.EventTimeline.Add(new SuspiciousEvent
        {
            Timestamp = DateTime.Now,
            EventType = eventType,
            MatchedIndicator = matchedRule,
            RawData = rawData
        });

        SaveToFile($"profile_{processName}_{pid}.txt");

    }

    public static void EvaluateNetworkConnection(Microsoft.Diagnostics.Tracing.Parsers.Kernel.TcpIpConnectTraceData data)
    {
        if (data.daddr == null) return;
        string destIp = data.daddr.ToString();
        int destPort = data.dport;
        string processName = data.ProcessName ?? "";

        bool isSuspiciousProcess = _suspiciousProcesses.Contains(processName.ToLowerInvariant());
        bool isSuspiciousPort    = _suspiciousPorts.Contains(destPort);

        if (isSuspiciousProcess || isSuspiciousPort)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[ALERT] Suspicious Network! {processName} (PID: {data.ProcessID}) -> {destIp}:{destPort}");
            Console.ResetColor();
            string rule = isSuspiciousPort ? $"Suspicious Port {destPort}" : "Suspicious Process Network";
            AddEventToProfile(data.ProcessID, processName, "NetworkConnect", rule, $"Connected to {destIp}:{destPort}");
        }
    }
}