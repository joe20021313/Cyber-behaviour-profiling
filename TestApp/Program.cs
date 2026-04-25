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

    private static TaskCompletionSource<bool>? _spaceWaiter;

    public static async Task Main()
    {
        Console.WriteLine("===========================================");
        Console.WriteLine("  CYBER BEHAVIOUR PROFILING — TEST APP");
        Console.WriteLine("===========================================");
        Console.WriteLine();
        Console.WriteLine("  [1] MALICIOUS   — Simulates a real attack step by step");
        Console.WriteLine("  [2] SAFE        — Normal everyday software behaviour");
        Console.WriteLine("  [3] SUSPICIOUS  — Unusual but not clearly harmful activity");
        Console.WriteLine("  [4] KNN DEMO    — Demonstrates the pattern-learning detector");
        Console.WriteLine();
        Console.WriteLine("  [Q] QUIT");
        Console.WriteLine();
        Console.WriteLine("  Press a key at any time to switch modes.");
        Console.WriteLine();

        Directory.CreateDirectory(Drop);

        while (true)
        {
            var keyInfo = Console.ReadKey(true);
            char key = keyInfo.KeyChar;

            if (keyInfo.Key == ConsoleKey.Spacebar && _spaceWaiter != null)
            {
                _spaceWaiter.TrySetResult(true);
                continue;
            }

            if (key == 'q' || key == 'Q')
                break;

            if (key >= '1' && key <= '4')
            {
                if (_currentSequence != null && !_currentSequence.IsCompleted)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("\n  Stopping current mode...");
                    Console.ResetColor();
                    _cts.Cancel();
                    try { await _currentSequence; } catch { }
                }

                _cts = new CancellationTokenSource();
                int mode = key - '0';

                string modeName = mode switch {
                    1 => "MALICIOUS",
                    2 => "SAFE",
                    3 => "SUSPICIOUS",
                    4 => "KNN DEMO",
                    _ => "UNKNOWN"
                };

                Console.WriteLine();
                Console.ForegroundColor = mode == 1 ? ConsoleColor.Red
                                        : mode == 2 ? ConsoleColor.Green
                                        : mode == 3 ? ConsoleColor.Yellow
                                        : ConsoleColor.Cyan;
                Console.WriteLine($"  ── STARTING: {modeName} ──");
                Console.ResetColor();
                Console.WriteLine();

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
                case 1: await RunMalicious(ct);   break;
                case 2: await RunSafe(ct);        break;
                case 3: await RunSuspicious(ct);  break;
                case 4: await RunKnnDemo(ct);     break;
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\n  Done.");
            Console.ResetColor();
        }
        catch (OperationCanceledException) { }
    }

    static async Task RunMalicious(CancellationToken ct)
    {
        Step("Gathering information about the machine — who is logged in, what is running");
        await Mal_Reconnaissance(ct);

        Step("Downloading a file and hiding it in a system folder");
        await Mal_DownloadAndDrop(ct);

        Step("Opening hidden command-line windows to run system tools");
        await Mal_LolbinExecution(ct);

        Step("Requesting extra permissions to access protected areas");
        await Mal_EnableDebugPrivilege(ct);

        Step("Adding itself to the list of programs that start with Windows");
        await Mal_RegistryPersistence(ct);

        Step("Disabling security tools by changing system settings");
        await Mal_DefenseEvasion(ct);

        Step("Searching for saved passwords and login files");
        await Mal_CredentialHarvest(ct);

        Step("Extracting stored credentials using Windows built-in decryption");
        await Mal_DpapiExtract(ct);

        Step("Trying to access the Windows password storage process (LSASS)");
        await Mal_LsassAccess(ct);

        Step("Packaging stolen data and sending it out");
        await Mal_DataStagingAndExfil(ct);

        Step("Locking files — simulating ransomware encryption");
        await Mal_RansomwareSim(ct);

        Step("Deleting backups so the files cannot be recovered");
        await Mal_AntiRecovery(ct);

        Step("Covering tracks — rapid file creation and deletion");
        await Mal_FileChurn(ct);

        Step("Attempting to remove itself");
        await Mal_SelfDeletion(ct);
    }

    static async Task RunSafe(CancellationToken ct)
    {
        Step("Reading files in your documents and pictures folders");
        await Safe_BrowseUserFolders(ct);

        Step("Connecting to the internet — one normal web request");
        await Safe_SingleWebRequest(ct);

        Step("Writing a few temporary files");
        await Safe_WriteTempFiles(ct);

        Step("Checking a few common system folders");
        await Safe_CheckCommonDirs(ct);
    }

    static async Task Safe_BrowseUserFolders(CancellationToken ct)
    {
        string[] paths =
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };
        foreach (var p in paths)
        {
            ct.ThrowIfCancellationRequested();
            await ProbeDirectoryAsync(p, ct, sampleRead: true);
            await Task.Delay(600, ct);
        }
    }

    static async Task Safe_SingleWebRequest(CancellationToken ct)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
            _ = await http.GetStringAsync("https://www.google.com", ct);
        }
        catch { }
        await Task.Delay(500, ct);
    }

    static async Task Safe_WriteTempFiles(CancellationToken ct)
    {
        for (int i = 0; i < 3; i++)
        {
            ct.ThrowIfCancellationRequested();
            string p = Path.Combine(Drop, $"cache_{i}.dat");
            await File.WriteAllTextAsync(p, $"cached value {i}", ct);
            await Task.Delay(500, ct);
        }
    }

    static async Task Safe_CheckCommonDirs(CancellationToken ct)
    {
        string[] dirs =
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Common Files"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Fonts"),
        };
        foreach (var dir in dirs)
        {
            ct.ThrowIfCancellationRequested();
            await ProbeDirectoryAsync(dir, ct, sampleRead: false);
            await Task.Delay(400, ct);
        }
    }

    static async Task RunSuspicious(CancellationToken ct)
    {
        Step("Scanning through system and application folders");
        await Sus_DirectoryEnum(ct);

        Step("Running tools to gather information about this computer");
        await Sus_DiscoveryTools(ct);

        Step("Opening command windows and running scripts");
        await Sus_ProcessSpawns(ct);

        Step("Connecting to several websites to probe external access");
        await Sus_NetworkProbe(ct);

        Step("Writing files at an unusually fast rate");
        await Sus_RapidWrites(ct);
    }

    static async Task RunKnnDemo(CancellationToken ct)
    {
        string workDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            $"cbp_knn_demo_{Environment.ProcessId}");
        Directory.CreateDirectory(workDir);
        _extraDirs.Add(workDir);

        int tick = 0;

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  [PHASE 1 — NORMAL]");
        Console.ResetColor();
        Console.WriteLine("  The app is running quietly — writing files at a slow, steady pace.");
        Console.WriteLine("  The profiler is watching and learning what normal looks like.");
        Console.WriteLine();
        Console.WriteLine("  → NOW is the time to record a baseline in the profiler.");
        Console.WriteLine();

        var normalEnd = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < normalEnd)
        {
            ct.ThrowIfCancellationRequested();
            string p = Path.Combine(workDir, $"normal_{tick++}.dat");
            await File.WriteAllTextAsync(p, $"normal data {tick}", ct);
            await Task.Delay(1800, ct);
        }

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine();
        Console.WriteLine("  [WAITING]");
        Console.WriteLine("  Normal phase finished. Press SPACE when ready to trigger the attack spike.");
        Console.ResetColor();

        _spaceWaiter = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        try   { await _spaceWaiter.Task.WaitAsync(ct); }
        finally { _spaceWaiter = null; }

        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine();
        Console.WriteLine("  [PHASE 2 — ATTACK SPIKE]");
        Console.ResetColor();
        Console.WriteLine("  The app is now writing files extremely fast — far above its normal pace.");
        Console.WriteLine("  If a baseline was recorded, the profiler should flag this as unusual.");
        Console.WriteLine();

        var spikeEnd = DateTime.UtcNow.AddSeconds(15);
        int spikeTick = 0;
        while (DateTime.UtcNow < spikeEnd)
        {
            ct.ThrowIfCancellationRequested();
            string p = Path.Combine(workDir, $"spike_{spikeTick++}.dat");
            await File.WriteAllBytesAsync(p, Encoding.UTF8.GetBytes(new string('A', 512)), ct);
            await Task.Delay(15, ct);
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  Spike done — {spikeTick} files written in 15 seconds.");
        Console.WriteLine("  Check the profiler report to see whether the spike was caught.");
        Console.ResetColor();
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
        }

        string exePath = Path.Combine(staging, "svcupdate.exe");
        string batPath = Path.Combine(staging, "install.bat");
        string ps1Path = Path.Combine(staging, "stage.ps1");
        string dllPath = Path.Combine(staging, "helper.dll");

        await File.WriteAllBytesAsync(exePath, bytes, ct);
        await File.WriteAllTextAsync(batPath, "@echo off\r\necho installing...", ct);
        await File.WriteAllTextAsync(ps1Path, "# stage loader", ct);
        await File.WriteAllTextAsync(dllPath, "MZ", ct);

        _extraDirs.Add(staging);
        await Task.Delay(1000, ct);
    }

    static async Task Mal_LolbinExecution(CancellationToken ct)
    {
        await Spawn("powershell.exe",
            "-ExecutionPolicy Bypass -NoProfile -Command \"Write-Host 'payload executed'; Start-Sleep 2\"",
            showWindow: true);
        await Task.Delay(1500, ct);

        string cmd     = "Write-Host 'payload'";
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(cmd));
        await Spawn("powershell.exe", $"-EncodedCommand {encoded}", showWindow: true);
        await Task.Delay(1500, ct);

        await Spawn("wmic.exe", "process call create \"cmd.exe /c echo WMI Spawned\"");
        await Task.Delay(1000, ct);

        await Spawn("certutil.exe",
            "-hashfile \"" + Environment.GetCommandLineArgs()[0] + "\" MD5");
        await Task.Delay(1000, ct);
    }

    static async Task Mal_RegistryPersistence(CancellationToken ct)
    {
        const string runKey  = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        const string valName = "SimUpdate";

        using (var key = Registry.CurrentUser.OpenSubKey(runKey, writable: true))
            key?.SetValue(valName, @"C:\Windows\Temp\svcupdate.exe");
        await Task.Delay(2000, ct);

        using (var key = Registry.CurrentUser.OpenSubKey(runKey, writable: true))
            key?.DeleteValue(valName, throwOnMissingValue: false);

        using var wl = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
        _ = wl?.GetValue("Userinit");
        await Task.Delay(500, ct);
    }

    static async Task Mal_CredentialHarvest(CancellationToken ct)
    {
        string appdata  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localapp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string home     = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string[] probeTargets =
        {
            Path.Combine(localapp, "Google", "Chrome", "User Data", "Default", "Login Data"),
            Path.Combine(localapp, "Google", "Chrome", "User Data", "Default", "Cookies"),
            Path.Combine(home, ".ssh", "id_rsa"),
            Path.Combine(home, ".ssh", "known_hosts"),
            Path.Combine(appdata, "Mozilla", "Firefox", "Profiles"),
        };

        foreach (var target in probeTargets)
        {
            ct.ThrowIfCancellationRequested();
            try   { _ = File.Exists(target) || Directory.Exists(target); }
            catch { }
            await Task.Delay(200, ct);
        }

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
                }
                catch { }
                await Task.Delay(150, ct);
            }
        }
        catch { }

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
                }
                catch { }
                await Task.Delay(150, ct);
            }
        }
        catch { }

        string dumpPath = Path.Combine(credDir, "sim_credentials.dump");
        try
        {
            await File.WriteAllTextAsync(dumpPath, "SIM:CREDENTIAL_DUMP:PLACEHOLDER", ct);
            await Task.Delay(800, ct);
            File.Delete(dumpPath);
        }
        catch { }
    }

    static async Task Mal_DataStagingAndExfil(CancellationToken ct)
    {
        string stageDir = Path.Combine(Drop, "staging");
        Directory.CreateDirectory(stageDir);
        string zipPath = Path.Combine(stageDir, "loot.zip");

        byte[] fakeZip = { 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00 };
        await File.WriteAllBytesAsync(zipPath, fakeZip, ct);
        await Task.Delay(800, ct);

        for (int i = 0; i < 4; i++)
        {
            ct.ThrowIfCancellationRequested();
            string path = Path.Combine(stageDir, $"chunk_{i}.bin");
            await File.WriteAllBytesAsync(path, Encoding.UTF8.GetBytes(new string('A', 512)), ct);
            await Task.Delay(50, ct);
        }

        foreach (var host in new[] { "pastebin.com", "api.telegram.org" })
        {
            ct.ThrowIfCancellationRequested();
            try { System.Net.Dns.GetHostEntry(host); } catch { }
            await Task.Delay(100, ct);
        }

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        foreach (var host in new[] { "https://api.github.com", "https://pastebin.com/raw/example" })
        {
            ct.ThrowIfCancellationRequested();
            try   { _ = await http.GetStringAsync(host, ct); }
            catch { }
            await Task.Delay(300, ct);
        }
    }

    static async Task Mal_RansomwareSim(CancellationToken ct)
    {
        string rnsmDir = Path.Combine(Drop, "locked_files");
        Directory.CreateDirectory(rnsmDir);

        for (int i = 0; i < 20; i++)
        {
            ct.ThrowIfCancellationRequested();
            string original  = Path.Combine(rnsmDir, $"financial_record_{i}.pdf");
            string encrypted = Path.Combine(rnsmDir, $"financial_record_{i}.pdf.locked");
            await File.WriteAllTextAsync(original, "dummy data", ct);
            await File.WriteAllBytesAsync(encrypted, new byte[] { 0x55, 0xAA, 0xFF }, ct);
            try { File.Delete(original); } catch { }
            await Task.Delay(20, ct);
        }

        string rnote = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "README_RECOVER_FILES.txt");
        try { await File.WriteAllTextAsync(rnote, "All your files are encrypted.", ct); _extraDirs.Add(rnote); } catch { }
        await Task.Delay(1000, ct);
    }

    static async Task Mal_AntiRecovery(CancellationToken ct)
    {
        await Spawn("vssadmin.exe", "delete shadows /all /quiet", showWindow: false);
        await Task.Delay(1500, ct);

        await Spawn("bcdedit.exe", "/set {default} recoveryenabled No", showWindow: false);
        await Task.Delay(1500, ct);
    }

    static async Task Mal_FileChurn(CancellationToken ct)
    {
        string churnDir = Path.Combine(Drop, "churn");
        Directory.CreateDirectory(churnDir);
        var written = new List<string>();

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
    }

    static async Task Mal_SelfDeletion(CancellationToken ct)
    {
        string marker = Path.Combine(Drop, "marker.exe");
        await File.WriteAllTextAsync(marker, "marker", ct);
        await Spawn("cmd.exe", $"/c ping -n 3 127.0.0.1 > nul && del /f /q \"{marker}\"");
        await Task.Delay(4000, ct);
    }

    static async Task Mal_Reconnaissance(CancellationToken ct)
    {
        (string exe, string args)[] tools =
        {
            ("whoami.exe",     "/all"),
            ("ipconfig.exe",   "/all"),
            ("systeminfo.exe", ""),
            ("netstat.exe",    "-an"),
            ("tasklist.exe",   ""),
            ("net.exe",        "user"),
        };
        foreach (var (exe, args) in tools)
        {
            ct.ThrowIfCancellationRequested();
            await Spawn(exe, args);
            await Task.Delay(500, ct);
        }
    }

    static async Task Mal_EnableDebugPrivilege(CancellationToken ct)
    {
        NativeMethods.EnableSeDebugPrivilege();
        await Task.Delay(800, ct);
    }

    static async Task Mal_DefenseEvasion(CancellationToken ct)
    {
        const string ifeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sim_target.exe";
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(ifeoKey);
            key?.SetValue("Debugger", @"C:\Windows\Temp\injector.exe");
            await Task.Delay(800, ct);
            Registry.CurrentUser.DeleteSubKey(ifeoKey, throwOnMissingSubKey: false);
        }
        catch { }

        await Spawn("powershell.exe", "-w hidden -ep bypass -nop -c \"Start-Sleep 2\"", showWindow: false);
        await Task.Delay(1000, ct);
    }

    static async Task Mal_DpapiExtract(CancellationToken ct)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("SIM:extracted_credential_data");
        byte[]? encrypted = NativeMethods.DpapiProtect(plaintext);
        if (encrypted != null)
            NativeMethods.DpapiUnprotect(encrypted);
        await Task.Delay(500, ct);
    }

    static async Task Mal_LsassAccess(CancellationToken ct)
    {
        var lsass = Process.GetProcessesByName("lsass").FirstOrDefault();
        if (lsass == null)
        {
            await Task.Delay(300, ct);
            return;
        }

        IntPtr handle = NativeMethods.OpenProcess(0x0010, false, lsass.Id);
        if (handle != IntPtr.Zero)
            NativeMethods.CloseHandle(handle);
        await Task.Delay(500, ct);
    }

    static async Task Sus_DirectoryEnum(CancellationToken ct)
    {
        string win      = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string localapp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string temp     = Path.GetTempPath();

        string[] dirs =
        {
            Path.Combine(win, "System32", "drivers"),
            Path.Combine(win, "System32", "Tasks"),
            Path.Combine(win, "Prefetch"),
            Path.Combine(win, "SysWOW64"),
            Path.Combine(progFiles, "Common Files"),
            @"C:\ProgramData",
            Path.Combine(localapp, "Temp"),
            Path.Combine(localapp, "Microsoft", "Windows", "INetCache"),
            temp,
        };

        foreach (var dir in dirs)
        {
            ct.ThrowIfCancellationRequested();
            await ProbeDirectoryAsync(dir, ct, sampleRead: false);
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

        foreach (var (exe, args) in commands)
        {
            ct.ThrowIfCancellationRequested();
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

        await Spawn("certutil.exe",
            "-hashfile \"" + Environment.GetCommandLineArgs()[0] + "\" SHA256");
        await Task.Delay(1000, ct);
    }

    static async Task Sus_NetworkProbe(CancellationToken ct)
    {
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
            try   { _ = await http.GetStringAsync(url, ct); }
            catch { }
            await Task.Delay(500, ct);
        }
    }

    static async Task Sus_RapidWrites(CancellationToken ct)
    {
        string dir = Path.Combine(Drop, "scratch");
        Directory.CreateDirectory(dir);

        for (int i = 0; i < 20; i++)
        {
            ct.ThrowIfCancellationRequested();
            string p = Path.Combine(dir, $"note_{i}.txt");
            await File.WriteAllTextAsync(p, $"scratch data {i}", ct);
            await Task.Delay(60, ct);
        }
    }

    private static readonly List<string> _extraDirs = [];

    static void Step(string description)
    {
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine($"\n  → {description}");
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
        catch { }
    }

    static async Task ProbeDirectoryAsync(string dir, CancellationToken ct, bool sampleRead)
    {
        ct.ThrowIfCancellationRequested();

        if (!Directory.Exists(dir))
            return;

        try
        {
            int shown = 0;
            foreach (var entry in Directory.EnumerateFileSystemEntries(dir))
            {
                shown++;
                if (shown >= 3) break;
            }
        }
        catch { }

        if (!sampleRead) return;

        string? sampleFile = FindFirstFile(dir, maxDepth: 2);
        if (string.IsNullOrEmpty(sampleFile)) return;

        try
        {
            using var fs = File.Open(sampleFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            int len = fs.Length > 0 ? (int)Math.Min(fs.Length, 32) : 1;
            byte[] buffer = new byte[len];
            _ = await fs.ReadAsync(buffer, ct);
        }
        catch { }
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

                if (depth >= maxDepth) continue;

                int queued = 0;
                foreach (var subDir in Directory.EnumerateDirectories(dir))
                {
                    pending.Enqueue((subDir, depth + 1));
                    if (++queued >= 3) break;
                }
            }
            catch { }
        }

        return null;
    }

    static async Task Cleanup()
    {
        foreach (var dir in _extraDirs)
            try { Directory.Delete(dir, recursive: true); } catch { }
        try { Directory.Delete(Drop, recursive: true); } catch { }
        await Task.CompletedTask;
    }
}

[SupportedOSPlatform("windows")]
internal static class NativeMethods
{

    [StructLayout(LayoutKind.Sequential)]
    private struct DATA_BLOB
    {
        public uint  cbData;
        public IntPtr pbData;
    }

    [DllImport("Crypt32.dll", SetLastError = true)]
    private static extern bool CryptProtectData(
        ref DATA_BLOB dataIn, string? description, IntPtr entropy,
        IntPtr reserved, IntPtr prompt, uint flags, out DATA_BLOB dataOut);

    [DllImport("Crypt32.dll", SetLastError = true)]
    private static extern bool CryptUnprotectData(
        ref DATA_BLOB dataIn, out IntPtr description, IntPtr entropy,
        IntPtr reserved, IntPtr prompt, uint flags, out DATA_BLOB dataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr mem);

    public static byte[]? DpapiProtect(byte[] data)
    {
        var blob = new DATA_BLOB { cbData = (uint)data.Length };
        blob.pbData = Marshal.AllocHGlobal(data.Length);
        try
        {
            Marshal.Copy(data, 0, blob.pbData, data.Length);
            if (!CryptProtectData(ref blob, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out var output))
                return null;
            byte[] result = new byte[output.cbData];
            Marshal.Copy(output.pbData, result, 0, result.Length);
            LocalFree(output.pbData);
            return result;
        }
        finally { Marshal.FreeHGlobal(blob.pbData); }
    }

    public static byte[]? DpapiUnprotect(byte[] data)
    {
        var blob = new DATA_BLOB { cbData = (uint)data.Length };
        blob.pbData = Marshal.AllocHGlobal(data.Length);
        try
        {
            Marshal.Copy(data, 0, blob.pbData, data.Length);
            if (!CryptUnprotectData(ref blob, out var desc, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out var output))
                return null;
            if (desc != IntPtr.Zero) LocalFree(desc);
            byte[] result = new byte[output.cbData];
            Marshal.Copy(output.pbData, result, 0, result.Length);
            LocalFree(output.pbData);
            return result;
        }
        finally { Marshal.FreeHGlobal(blob.pbData); }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inheritHandle, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? system, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES newState,
        uint bufLen, IntPtr prevState, IntPtr returnLen);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_QUERY             = 0x0008;
    private const uint SE_PRIVILEGE_ENABLED    = 0x0002;

    public static bool EnableSeDebugPrivilege()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr token))
            return false;
        try
        {
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out LUID luid))
                return false;
            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges     = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }
            };
            return AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally { CloseHandle(token); }
    }
}
