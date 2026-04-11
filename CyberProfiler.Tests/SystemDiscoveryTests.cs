using System;
using System.IO;
using System.Linq;
using Cyber_behaviour_profiling;

public class SystemDiscoveryTests
{
    [Fact]
    public void ExpandSensitiveDirectoryCandidates_ResolvesSpecialMarkers()
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        var sshCandidates = SystemDiscovery.ExpandSensitiveDirectoryCandidates(@"\.ssh\");
        Assert.Contains(sshCandidates, path =>
            path.Equals(Path.Combine(userProfile, ".ssh"), StringComparison.OrdinalIgnoreCase));

        var localPackagesCandidates = SystemDiscovery.ExpandSensitiveDirectoryCandidates(@"\appdata\local\packages\");
        Assert.Contains(localPackagesCandidates, path =>
            path.Equals(Path.Combine(userProfile, "AppData", "Local", "Packages"), StringComparison.OrdinalIgnoreCase));

        var startupCandidates = SystemDiscovery.ExpandSensitiveDirectoryCandidates(
            @"\roaming\microsoft\windows\start menu\programs\startup\");
        Assert.Contains(startupCandidates, path =>
            path.Equals(
                Path.Combine(userProfile, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
                StringComparison.OrdinalIgnoreCase));

        var driversCandidates = SystemDiscovery.ExpandSensitiveDirectoryCandidates(@"\drivers\etc\");
        Assert.Contains(driversCandidates, path =>
            path.Equals(Path.Combine(windowsDir, "System32", "drivers", "etc"), StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void TakeDirectorySnapshot_CapturesNestedFilesWithinDepthLimit()
    {
        string root = Path.Combine(Path.GetTempPath(), $"systemdiscovery-snapshot-{Guid.NewGuid():N}");
        string nestedDir = Path.Combine(root, "level1", "level2", "level3", "level4");
        string nestedFile = Path.Combine(nestedDir, "payload.exe");

        Directory.CreateDirectory(nestedDir);
        try
        {
            File.WriteAllText(nestedFile, "MZ");

            var snapshot = SystemDiscovery.TakeDirectorySnapshot(new[] { root });

            Assert.True(snapshot.Files.ContainsKey(nestedFile), $"Expected snapshot to capture {nestedFile}");
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }

    [Fact]
    public void Analyze_DnsQueryWithAppDataExecutableDrop_ProducesNetworkInvestigation()
    {
        TestScope.WithFreshSession(() =>
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string uniqueDir = Path.Combine(appData, "WindowsUpdate", "cache", $"sd-test-{Guid.NewGuid():N}");
            string payloadPath = Path.Combine(uniqueDir, "payload.exe");

            Directory.CreateDirectory(uniqueDir);
            try
            {
                var monitoredDirs = SystemDiscovery.GetMonitoredDirectories(MapToData.SensitiveDirs as IReadOnlyList<string>);
                var profile = ProfileFactory.Empty("TestApp.exe", 2_000_002_001);
                profile.DirectorySnapshotBefore = SystemDiscovery.TakeDirectorySnapshot(monitoredDirs);

                File.WriteAllText(payloadPath, "MZ");
                DateTime observedAt = DateTime.Now;
                ProfileFactory.AddEvent(
                    profile,
                    "DNS_Query",
                    "pastebin.com",
                    "pastebin.com",
                    "dns_c2",
                    timestamp: observedAt,
                    lastSeen: observedAt);

                var report = BehaviorAnalyzer.Analyze(profile);

                Assert.NotNull(report.NetworkInvestigation);
                Assert.Contains(report.NetworkInvestigation!.Findings, finding =>
                    finding.Description.Contains("payload.exe", StringComparison.OrdinalIgnoreCase));
            }
            finally
            {
                try { Directory.Delete(uniqueDir, recursive: true); } catch { }
            }
        }, loadData: true);
    }

    [Fact]
    public void Analyze_MultipleNetworkEvents_DoNotDuplicateSameDroppedExecutable()
    {
        TestScope.WithFreshSession(() =>
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string uniqueDir = Path.Combine(appData, "WindowsUpdate", "cache", $"sd-dedupe-{Guid.NewGuid():N}");
            string payloadPath = Path.Combine(uniqueDir, "payload.exe");

            Directory.CreateDirectory(uniqueDir);
            try
            {
                var monitoredDirs = SystemDiscovery.GetMonitoredDirectories(MapToData.SensitiveDirs as IReadOnlyList<string>);
                var profile = ProfileFactory.Empty("TestApp.exe", 2_000_002_002);
                profile.DirectorySnapshotBefore = SystemDiscovery.TakeDirectorySnapshot(monitoredDirs);

                File.WriteAllText(payloadPath, "MZ");
                DateTime observedAt = DateTime.Now;

                ProfileFactory.AddEvent(
                    profile,
                    "DNS_Query",
                    "pastebin.com",
                    "pastebin.com",
                    "dns_c2",
                    timestamp: observedAt,
                    lastSeen: observedAt);
                ProfileFactory.AddEvent(
                    profile,
                    "NetworkConnect",
                    "pastebin.com",
                    "pastebin.com (93.184.216.34)",
                    "network_c2",
                    timestamp: observedAt.AddMilliseconds(500),
                    lastSeen: observedAt.AddMilliseconds(500));

                var report = BehaviorAnalyzer.Analyze(profile);

                Assert.NotNull(report.NetworkInvestigation);
                Assert.Single(report.NetworkInvestigation!.Findings,
                    f => f.ArtifactPath.Equals(payloadPath, StringComparison.OrdinalIgnoreCase));
            }
            finally
            {
                try { Directory.Delete(uniqueDir, recursive: true); } catch { }
            }
        }, loadData: true);
    }

    [Fact]
    public void InvestigateNetworkEvent_GroupsManyNonExecutableArtifactsIntoOneFinding()
    {
        string root = Path.Combine(Path.GetTempPath(), $"systemdiscovery-network-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);

        try
        {
            var before = SystemDiscovery.TakeDirectorySnapshot(new[] { root });
            string[] files =
            {
                Path.Combine(root, "financial_record_0.pdf.locked"),
                Path.Combine(root, "financial_record_1.pdf.locked"),
                Path.Combine(root, "chunk_0.bin"),
                Path.Combine(root, "loot.zip")
            };

            foreach (string file in files)
                File.WriteAllText(file, "demo");

            var after = SystemDiscovery.TakeDirectorySnapshot(new[] { root });
            DateTime observedAt = DateTime.Now;
            var networkEvent = ProfileFactory.Event(
                "NetworkConnect",
                "api.telegram.org",
                "api.telegram.org",
                "network_c2",
                timestamp: observedAt,
                lastSeen: observedAt);

            var result = SystemDiscovery.InvestigateNetworkEvent(
                networkEvent,
                ProfileFactory.Empty("testapp.exe", 2_000_002_100),
                before,
                after);

            Assert.Single(result.Findings);
            Assert.Contains("4 files appeared within 10s of connecting to api.telegram.org", result.Findings[0].Description, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { }
        }
    }

    [Fact]
    public void InvestigateDirectoryChanges_ScriptArtifacts_DoNotReportBinaryTrustFailures()
    {
        TestScope.WithFreshSession(() =>
        {
            string root = Path.Combine(Path.GetTempPath(), $"systemdiscovery-script-{Guid.NewGuid():N}");
            Directory.CreateDirectory(root);

            try
            {
                var before = SystemDiscovery.TakeDirectorySnapshot(new[] { root });
                string scriptPath = Path.Combine(root, "stage.ps1");
                File.WriteAllText(scriptPath, "Write-Host demo");
                var after = SystemDiscovery.TakeDirectorySnapshot(new[] { root });

                SignatureTestScope.WithSignatureResult(new SignatureVerificationResult
                {
                    HasSignature = true,
                    IsCryptographicallyValid = false,
                    IsTrustedPublisher = false,
                    TrustState = SignatureTrustState.InvalidSignature,
                    Summary = "A digital signature is present, but trust validation failed."
                }, () =>
                {
                    var result = SystemDiscovery.InvestigateDirectoryChanges(before, after);

                    var finding = Assert.Single(result.Findings,
                        f => f.ArtifactPath.Equals(scriptPath, StringComparison.OrdinalIgnoreCase));
                    Assert.DoesNotContain("trust:", finding.Description, StringComparison.OrdinalIgnoreCase);
                    Assert.Empty(finding.Children);
                });
            }
            finally
            {
                try { Directory.Delete(root, recursive: true); } catch { }
            }
        }, loadData: true);
    }

    [Fact]
    public void CommandLineMatchesRule_NormalizesExecutableSuffix()
    {
        Assert.True(MapToData.CommandLineMatchesRule(
            "wmic.exe process call create \"cmd.exe /c echo WMI Spawned\"",
            "wmic process call create"));

        Assert.True(MapToData.CommandLineMatchesRule(
            "cmd.exe /c del payload.exe",
            "cmd /c del"));
    }
}