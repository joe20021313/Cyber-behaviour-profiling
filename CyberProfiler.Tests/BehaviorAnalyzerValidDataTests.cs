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
    public void ExecutableDropWithContextSignal_ReturnsMalicious()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.Empty("loader.exe", 2_100_000_002);
            string dropPath = @"C:\Users\User\AppData\Local\Temp\payload.exe";

            ProfileFactory.AddEvent(
                profile,
                "ContextSignal",
                "payload.exe",
                dropPath,
                "context_signal");
            profile.ExeDropPaths.TryAdd(dropPath, 0);

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.Equal(ThreatImpact.Malicious, report.FinalVerdict);
            Assert.Contains(report.FiredCheckNames, n =>
                n.Equals("Executable Binary Dropped", StringComparison.OrdinalIgnoreCase));
        }, loadData: true);
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
    public void NoBaselineSensitiveTripwire_DefaultsToSuspicious()
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
            Assert.True(report.Anomaly!.TripwireFired);
            Assert.Equal(ThreatImpact.Suspicious, report.FinalVerdict);
            Assert.Contains(report.DecisionReasons, reason =>
                reason.Contains("tripwire", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            AnomalyDetector.LoadBaselines(new Dictionary<string, ProcessBaseline>());
        }
    }

    [Fact]
    public void NoBaselineTripwireWithHardHighRiskEvents_EscalatesToMalicious()
    {
        var anomaly = new AnomalyResult
        {
            AnomalyDetected = true,
            BaselineUsed = false,
            TripwireFired = true,
            TripwireReason = "Sensitive Access Rate 10.0/sec exceeded tripwire 4.0/sec",
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