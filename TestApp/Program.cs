using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;

[SupportedOSPlatform("windows")]
public static class Simulator
{
    private static readonly string Drop =
        Path.Combine(Path.GetTempPath(), $"sim_{Environment.ProcessId}");

    public static async Task Main()
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  CyberProfiler — Behaviour Simulator");
        Console.WriteLine("  ====================================");
        Console.ResetColor();
        Console.WriteLine($"  PID  : {Environment.ProcessId}");
        Console.WriteLine($"  Name : {Process.GetCurrentProcess().ProcessName}");
        Console.WriteLine();

        Console.WriteLine("  Choose a simulation mode:");
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("    [1]  Malicious    — Full attack chain (drops, persistence, creds, exfil, cleanup)");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.WriteLine("    [2]  Suspicious   — Reconnaissance only (looks around, no damage)");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("    [3]  Inconclusive — Ambiguous activity (borderline behaviour)");
        Console.ResetColor();
        Console.WriteLine();

        int mode = 0;
        while (mode < 1 || mode > 3)
        {
            Console.Write("  Enter 1, 2, or 3: ");
            int.TryParse(Console.ReadLine()?.Trim(), out mode);
        }

        Console.WriteLine();
        Console.WriteLine("  Start the profiler targeting this process, then press ENTER.");
        Console.ReadLine();

        Directory.CreateDirectory(Drop);

        try
        {
            switch (mode)
            {
                case 1: await RunMalicious();     break;
                case 2: await RunSuspicious();    break;
                case 3: await RunInconclusive();  break;
            }
        }
        finally
        {
            await Cleanup();
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  Simulation finished. Check the profiler for detections.");
        Console.ResetColor();
        Console.ReadLine();
    }

    static async Task RunMalicious()
    {
        await Phase("1 — BASELINE",                     Baseline);
        await Phase("2 — DOWNLOAD & DROP",              Mal_DownloadAndDrop);
        await Phase("3 — LOLBIN / POWERSHELL EXECUTION",Mal_LolbinExecution);
        await Phase("4 — REGISTRY PERSISTENCE",         Mal_RegistryPersistence);
        await Phase("5 — CREDENTIAL HARVESTING",        Mal_CredentialHarvest);
        await Phase("6 — EXFILTRATION BURST",           Mal_ExfiltrationBurst);
        await Phase("7 — FILE CHURN",                   Mal_FileChurn);
        await Phase("8 — SELF-DELETION",                Mal_SelfDeletion);
    }

    static async Task RunSuspicious()
    {
        await Phase("1 — BASELINE",                Baseline);
        await Phase("2 — DIRECTORY ENUMERATION",   Sus_DirectoryEnum);
        await Phase("3 — SYSTEM DISCOVERY TOOLS",  Sus_DiscoveryTools);
        await Phase("4 — PROCESS SPAWNING",        Sus_ProcessSpawns);
        await Phase("5 — NETWORK PROBING",         Sus_NetworkProbe);
        await Phase("6 — RAPID FILE WRITES",       Sus_RapidWrites);
    }

    static async Task RunInconclusive()
    {
        await Phase("1 — BASELINE",               Baseline);
        await Phase("2 — ORDINARY FILE ACTIVITY",  Inc_FileActivity);
        await Phase("3 — SINGLE NETWORK CALL",     Inc_SingleNetwork);
        await Phase("4 — TEMP FILE WRITES",        Inc_TempWrites);
        await Phase("5 — DIRECTORY CHECKS",        Inc_DirectoryChecks);
    }

    static async Task Baseline()
    {
        Log("Reading ordinary files to establish quiet baseline (~20s)...");
        string[] probes =
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.SystemDirectory,
        };
        for (int i = 0; i < 10; i++)
        {
            foreach (var dir in probes)
                _ = Directory.Exists(dir);
            await Task.Delay(2000);
            Log($"  baseline tick {i + 1}/10");
        }
    }

    static async Task Mal_DownloadAndDrop()
    {
        string staging = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "WindowsUpdate", "cache");
        Directory.CreateDirectory(staging);

        Log("Connecting to remote host to fetch payload...");
        byte[] bytes;
        try
        {
            using var http = new HttpClient();
            http.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");
            bytes = await http.GetByteArrayAsync("https://github.com");
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

        await File.WriteAllBytesAsync(exePath, bytes);
        await File.WriteAllTextAsync(batPath, "@echo off\r\necho installing...");
        await File.WriteAllTextAsync(ps1Path, "# stage loader");
        await File.WriteAllTextAsync(dllPath, "MZ");

        Log($"  Dropped: {exePath}");
        Log($"  Dropped: {batPath}");
        Log($"  Dropped: {ps1Path}");
        Log($"  Dropped: {dllPath}");

        _extraDirs.Add(staging);
        await Task.Delay(1000);
    }

    static async Task Mal_LolbinExecution()
    {
        Log("Spawning powershell.exe -ExecutionPolicy Bypass ...");
        await Spawn("powershell.exe",
            "-ExecutionPolicy Bypass -NoProfile -Command \"Write-Host 'Simulated payload execution'; Start-Sleep 2\"",
            showWindow: true);
        await Task.Delay(1500);

        string cmd     = "Write-Host 'payload'";
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(cmd));
        Log("Spawning powershell.exe -EncodedCommand <base64> ...");
        await Spawn("powershell.exe", $"-EncodedCommand {encoded}", showWindow: true);
        await Task.Delay(1500);

        Log("Spawning certutil.exe (LOLBin) ...");
        await Spawn("certutil.exe",
            "-hashfile \"" + Environment.GetCommandLineArgs()[0] + "\" MD5");
        await Task.Delay(1000);

        Log("Spawning mshta.exe (LOLBin) ...");
        await Spawn("mshta.exe", "about:blank");
        await Task.Delay(1000);
    }

    static async Task Mal_RegistryPersistence()
    {
        const string runKey  = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        const string valName = "SimUpdate";

        Log($"Writing HKCU\\{runKey}\\{valName} ...");
        using (var key = Registry.CurrentUser.OpenSubKey(runKey, writable: true))
            key?.SetValue(valName, @"C:\Windows\Temp\svcupdate.exe");
        await Task.Delay(2000);

        Log("  Removing persistence key...");
        using (var key = Registry.CurrentUser.OpenSubKey(runKey, writable: true))
            key?.DeleteValue(valName, throwOnMissingValue: false);

        Log("Reading Winlogon key...");
        using var wl = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
        Log($"  Userinit = {wl?.GetValue("Userinit") ?? "(no access)"}");
        await Task.Delay(500);
    }

    static async Task Mal_CredentialHarvest()
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
            try
            {
                bool exists = File.Exists(target) || Directory.Exists(target);
                Log($"  {(exists ? "[found]" : "[not found]")} {target}");
            }
            catch { Log($"  [denied]  {target}"); }
            await Task.Delay(200);
        }
    }

    static async Task Mal_ExfiltrationBurst()
    {
        string[] dirs = Enumerable.Range(0, 6)
            .Select(i => Path.Combine(Drop, $"exfil_{(char)('a' + i)}"))
            .ToArray();
        foreach (var d in dirs) Directory.CreateDirectory(d);

        Log("Writing 80 files across 6 directories rapidly...");
        int count = 0;
        for (int round = 0; round < 4; round++)
        {
            foreach (var dir in dirs)
            {
                string path = Path.Combine(dir, $"data_{count++}.bin");
                await File.WriteAllBytesAsync(path, Encoding.UTF8.GetBytes(new string('A', 2048)));
            }
            await Task.Delay(50);
        }
        Log($"  Wrote {count} files.");

        Log("Making outbound HTTP connections (exfiltration pattern)...");
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        foreach (var host in new[] { "https://github.com", "https://api.github.com" })
        {
            try   { _ = await http.GetStringAsync(host); Log($"  Connected: {host}"); }
            catch { Log($"  (no route to {host})"); }
            await Task.Delay(300);
        }
    }

    static async Task Mal_FileChurn()
    {
        string churnDir = Path.Combine(Drop, "churn");
        Directory.CreateDirectory(churnDir);
        var written = new List<string>();

        Log("Writing 30 files then deleting them (churn)...");
        for (int i = 0; i < 30; i++)
        {
            string p = Path.Combine(churnDir, $"tmp_{i}.dat");
            await File.WriteAllTextAsync(p, $"churn {i}");
            written.Add(p);
            await Task.Delay(30);
        }
        await Task.Delay(300);
        foreach (var p in written)
        {
            try { File.Delete(p); } catch { }
            await Task.Delay(15);
        }
        Log($"  Churned {written.Count} files.");
    }

    static async Task Mal_SelfDeletion()
    {
        string marker = Path.Combine(Drop, "marker.exe");
        await File.WriteAllTextAsync(marker, "marker");

        Log("Spawning cmd.exe to delete dropped file after delay (self-deletion pattern)...");
        await Spawn("cmd.exe",
            $"/c ping -n 3 127.0.0.1 > nul && del /f /q \"{marker}\"");
        await Task.Delay(4000);
        Log("  Done.");
    }

    static async Task Sus_DirectoryEnum()
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
            bool exists = Directory.Exists(dir);
            Log($"  {(exists ? "[exists]" : "[absent]")} {dir}");
            await Task.Delay(300);
        }
    }

    static async Task Sus_DiscoveryTools()
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
            Log($"  Spawning {exe} {args}");
            await Spawn(exe, args);
            await Task.Delay(800);
        }
    }

    static async Task Sus_ProcessSpawns()
    {
        Log("Spawning cmd.exe (no malicious payload)...");
        await Spawn("cmd.exe", "/c echo System check complete");
        await Task.Delay(1000);

        Log("Spawning powershell.exe (no bypass flags)...");
        await Spawn("powershell.exe",
            "-Command \"Get-Date; Get-Process | Select-Object -First 5\"",
            showWindow: true);
        await Task.Delay(1500);

        Log("Spawning certutil.exe (hash check only)...");
        await Spawn("certutil.exe",
            "-hashfile \"" + Environment.GetCommandLineArgs()[0] + "\" SHA256");
        await Task.Delay(1000);
    }

    static async Task Sus_NetworkProbe()
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
            try   { _ = await http.GetStringAsync(url); Log($"  Connected: {url}"); }
            catch { Log($"  (no route to {url})"); }
            await Task.Delay(500);
        }
    }

    static async Task Sus_RapidWrites()
    {
        string dir = Path.Combine(Drop, "scratch");
        Directory.CreateDirectory(dir);

        Log("Writing 20 temporary data files quickly...");
        for (int i = 0; i < 20; i++)
        {
            string p = Path.Combine(dir, $"note_{i}.txt");
            await File.WriteAllTextAsync(p, $"scratch data {i}");
            await Task.Delay(60);
        }
        Log("  Done.");
        await Task.Delay(500);
    }

    static async Task Inc_FileActivity()
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
            bool exists = Directory.Exists(p);
            Log($"  {(exists ? "[exists]" : "[absent]")} {p}");
            await Task.Delay(500);
        }
    }

    static async Task Inc_SingleNetwork()
    {
        Log("Making a single HTTP request...");
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
            _ = await http.GetStringAsync("https://www.google.com");
            Log("  Connected to www.google.com");
        }
        catch { Log("  (no route)"); }
        await Task.Delay(500);
    }

    static async Task Inc_TempWrites()
    {
        Log("Writing 3 temp files...");
        for (int i = 0; i < 3; i++)
        {
            string p = Path.Combine(Drop, $"cache_{i}.dat");
            await File.WriteAllTextAsync(p, $"cached value {i}");
            Log($"  Wrote {p}");
            await Task.Delay(400);
        }
    }

    static async Task Inc_DirectoryChecks()
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
            bool exists = Directory.Exists(dir);
            Log($"  {(exists ? "[exists]" : "[absent]")} {dir}");
            await Task.Delay(400);
        }
    }

    private static readonly List<string> _extraDirs = [];

    static async Task Phase(string name, Func<Task> action)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"  ── Phase {name}");
        Console.ResetColor();
        await action();
    }

    static void Log(string msg)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"     {msg}");
        Console.ResetColor();
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
        catch (Exception ex) { Log($"  [spawn failed] {exe}: {ex.Message}"); }
    }

    static async Task Cleanup()
    {
        Console.WriteLine();
        Log("Cleaning up...");
        foreach (var dir in _extraDirs)
            try { Directory.Delete(dir, recursive: true); } catch { }
        try { Directory.Delete(Drop, recursive: true); } catch { }
        await Task.CompletedTask;
    }
}
