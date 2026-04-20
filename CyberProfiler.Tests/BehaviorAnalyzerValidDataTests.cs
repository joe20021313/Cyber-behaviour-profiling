using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Cyber_behaviour_profiling;

public class BehaviorAnalyzerValidDataTests
{
    [Fact]
    public void HardMaliciousIndicator_LsassAccess_ReturnsMalicious()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.WithEvent(
                "LsassAccess",
                "lsass.exe",
                "lsass.exe",
                "lsass_access",
                "unknown.exe",
                2_100_000_001);

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.Equal(ThreatImpact.Malicious, report.FinalVerdict);
            Assert.True(report.ChainResult.HasHardIndicator);
            Assert.Contains(report.FiredCheckNames, n =>
                n.Equals("LSASS Memory Access", StringComparison.OrdinalIgnoreCase));
        });
    }

    [Fact]
    public void EncodedBypassCommand_ReturnsSuspicious()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.Empty("powershell.exe", 2_100_000_003);
            profile.SpawnedCommandLines.Add(new SpawnedProcess
            {
                Pid = 2_100_000_004,
                Name = "powershell.exe",
                CommandLine = "powershell.exe -exec bypass -enc AAAA",
                StartTime = DateTime.Now
            });

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.Equal(ThreatImpact.Suspicious, report.FinalVerdict);
            Assert.Contains(report.FiredCheckNames, n =>
                n.Equals("Encoded or Obfuscated Command", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(report.FiredCheckNames, n =>
                n.Equals("Execution Policy or Profile Bypass", StringComparison.OrdinalIgnoreCase));
        }, loadData: true);
    }

    [Fact]
    public void NetworkAndCredentialSignals_FlagUnexpectedOutboundConnections()
    {
        var ctx = new ProcessContext
        {
            HasNetworkConns = true,
            NetworkConnCount = 2,
            FilePath = @"C:\Users\User\AppData\Local\SomeApp\app.exe",
            ParentProcess = "explorer"
        };

        var profile = ProfileFactory.Empty("app.exe", 2_100_000_005);
        ProfileFactory.AddEvent(
            profile,
            "NetworkConnect",
            "example.org",
            "example.org (93.184.216.34)",
            "network_outbound");
        ProfileFactory.AddEvent(
            profile,
            "FileRead",
            "login data",
            @"C:\Users\VM\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            "credential_file_access");

        bool flagged = BehaviorAnalyzer.ShouldFlagUnexpectedNetworkConnections(
            ctx,
            profile.EventTimeline.ToList(),
            profile);

        Assert.True(flagged);
    }

    [Fact]
    public void BrowserProcess_AccessingBrowserCredentialPath_DoesNotTriggerNonBrowserCredentialTheft()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.Empty("msedge.exe", 2_100_000_051);

            ProfileFactory.AddEvent(
                profile,
                "FileRead",
                "Login Data",
                @"C:\Users\user\AppData\Local\Microsoft\Edge\User Data\Default\Login Data",
                "credential_file_access");

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.DoesNotContain(report.FiredCheckNames, n =>
                n.Equals("Browser Credential Access", StringComparison.OrdinalIgnoreCase));
            Assert.NotEqual(ThreatImpact.Malicious, report.FinalVerdict);
        }, loadData: true);
    }

    [Fact]
    public void BrowserUserLaunch_HighChurnAndScriptCleanup_CanRemainSafe()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.Empty("msedge.exe", 2_100_000_052);
            profile.ParentProcessNameAtSpawn = "explorer.exe";
            profile.TotalFileWrites = 640;
            profile.TotalFileDeletes = 90;
            profile.DeletedPaths.Add(@"C:\Users\user\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache\js1.js");
            profile.DeletedPaths.Add(@"C:\Users\user\AppData\Local\Microsoft\Edge\User Data\Default\Code Cache\js2.js");

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.Equal(ThreatImpact.Safe, report.FinalVerdict);
            Assert.DoesNotContain(report.FiredCheckNames, n =>
                n.Equals("Executable File Deleted", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(report.FiredCheckNames, n =>
                n.Equals("High File Create-Delete Churn", StringComparison.OrdinalIgnoreCase));
        }, loadData: true);
    }

    [Fact]
    public void BrowserLaunchedByProgram_IsNeverAutoSafe()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.Empty("msedge.exe", 2_100_000_053);
            profile.ParentProcessNameAtSpawn = "notepad.exe";

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.NotEqual(ThreatImpact.Safe, report.FinalVerdict);
            Assert.Contains(report.FiredCheckNames, n =>
                n.Equals("Browser Spawned by Non-Shell Parent", StringComparison.OrdinalIgnoreCase));
        }, loadData: true);
    }

    [Fact]
    public void NonBrowserHighChurnAndScriptCleanup_DoesNotUseBrowserSafePath()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.Empty("testapp.exe", 2_100_000_054);
            profile.ParentProcessNameAtSpawn = "explorer.exe";
            profile.TotalFileWrites = 640;
            profile.TotalFileDeletes = 90;
            profile.DeletedPaths.Add(@"C:\Users\user\AppData\Local\Temp\run1.js");
            profile.DeletedPaths.Add(@"C:\Users\user\AppData\Local\Temp\run2.js");

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.NotEqual(ThreatImpact.Safe, report.FinalVerdict);
            Assert.Contains(report.FiredCheckNames, n =>
                n.Equals("Executable File Deleted", StringComparison.OrdinalIgnoreCase));
        }, loadData: true);
    }

    [Fact]
    public void BaselineNearMatch_RemainsSafeAndUsesBaseline()
    {
        AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>
        {
            ["writer"] = new ProcessBaseline
            {
                Source = "user",
                Snapshots = Enumerable.Range(0, 8)
                    .Select(_ => new[] { 10.0, 0.0, 1.0, 0.5 })
                    .ToArray()
            }
        });

        try
        {
            var profile = ProfileFactory.Empty("writer.exe", 2_100_000_006);
            for (int i = 0; i < 8; i++)
                profile.AnomalyHistory.Add(new[] { 10.03, 0.01, 1.01, 0.52 });

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.NotNull(report.Anomaly);
            Assert.True(report.Anomaly!.BaselineUsed);
            Assert.Equal(ThreatImpact.Safe, report.FinalVerdict);
        }
        finally
        {
            AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());
        }
    }

    [Fact]
    public void NoBaselineSensitiveShortLivedBurst_DefaultsToSuspicious()
    {
        AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());

        try
        {
            var profile = ProfileFactory.Empty("lazagne.exe", 2_100_000_007);
            profile.AnomalyHistory.Add(new[] { 0.0, 0.0, 0.0, 10.0 });
            profile.AnomalyHistory.Add(new[] { 0.0, 0.0, 0.0, 0.0 });
            profile.AnomalyHistory.Add(new[] { 0.0, 0.0, 0.0, 0.0 });

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.NotNull(report.Anomaly);
            Assert.True(report.Anomaly!.ShortLivedBurstFired);
            Assert.Equal(ThreatImpact.Suspicious, report.FinalVerdict);
            Assert.Contains(report.DecisionReasons, reason =>
                reason.Contains("ShortLivedBurst", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());
        }
    }

    [Fact]
    public void NoBaselineShortLivedBurstWithHardHighRiskEvents_EscalatesToMalicious()
    {
        var anomaly = new AnomalyResult
        {
            AnomalyDetected = true,
            BaselineUsed = false,
            ShortLivedBurstFired = true,
            ShortLivedBurstReason = "Sensitive Access Rate 10.0/sec exceeded ShortLivedBurst 4.0/sec",
            Score = 36
        };

        var events = new List<SuspiciousEvent>
        {
            ProfileFactory.Event(
                "DPAPI_Decrypt",
                "dpapi",
                "CryptUnprotectData",
                "credential_file_access")
        };

        var impact = BehaviorAnalyzer.DetermineAnomalyImpact(
            anomaly,
            events,
            ProfileFactory.Empty("lazagne.exe", 2_100_000_008));

        Assert.Equal(ThreatImpact.Malicious, impact);
    }
}
