using System;
using System.Collections.Generic;
using System.Linq;
using Cyber_behaviour_profiling;

public class BehaviorAnalyzerInvalidDataTests
{
    [Fact]
    public void EmptyProfile_NoEvents_ReturnsSafeWithoutChecks()
    {
        var profile = ProfileFactory.Empty("idle.exe", 2_110_000_001);

        var report = BehaviorAnalyzer.Analyze(profile);

        Assert.Equal(ThreatImpact.Safe, report.FinalVerdict);
        Assert.Empty(report.FiredCheckNames);
    }

    [Fact]
    public void InsufficientVectors_NoBaseline_ReturnsNotEnoughDataNotice()
    {
        var profile = ProfileFactory.Empty("writer.exe", 2_110_000_002);
        profile.AnomalyHistory.Add(new[] { 1.0, 0.0, 0.0, 0.0 });
        profile.AnomalyHistory.Add(new[] { 1.1, 0.0, 0.0, 0.0 });
        profile.AnomalyHistory.Add(new[] { 0.9, 0.0, 0.0, 0.0 });

        var report = BehaviorAnalyzer.Analyze(profile);

        Assert.Equal(ThreatImpact.Safe, report.FinalVerdict);
        Assert.Contains(report.DecisionReasons, reason =>
            reason.Contains("Not enough data yet", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void GenericOutboundWithoutCorroboration_DoesNotFlagUnexpectedNetwork()
    {
        var ctx = new ProcessContext
        {
            HasNetworkConns = true,
            NetworkConnCount = 4,
            FilePath = @"C:\Users\User\AppData\Local\SomeApp\app.exe",
            ParentProcess = "explorer"
        };

        var profile = ProfileFactory.Empty("app.exe", 2_110_000_003);
        ProfileFactory.AddEvent(
            profile,
            "NetworkConnect",
            "example.org",
            "example.org (93.184.216.34)",
            "network_outbound");

        bool flagged = BehaviorAnalyzer.ShouldFlagUnexpectedNetworkConnections(
            ctx,
            profile.EventTimeline.ToList(),
            profile);

        Assert.False(flagged);
    }

    [Fact]
    public void ElevatedUnsignedWithoutCorroboration_DoesNotFlagUnexpectedElevation()
    {
        var ctx = new ProcessContext
        {
            IsElevated = true,
            IsSigned = false,
            FilePath = @"C:\Users\User\AppData\Local\SomeApp\app.exe",
            ParentProcess = "explorer",
            IsSuspiciousPath = false,
            ParentIsSuspicious = false
        };

        bool flagged = BehaviorAnalyzer.ShouldFlagUnexpectedElevation(
            ctx,
            new List<SuspiciousEvent>(),
            ProfileFactory.Empty("app.exe", 2_110_000_004));

        Assert.False(flagged);
    }

    [Fact]
    public void CommandLineMatchesRule_EmptyOrMissingInputs_ReturnsFalse()
    {
        Assert.False(MapToData.CommandLineMatchesRule(string.Empty, "cmd /c del"));
        Assert.False(MapToData.CommandLineMatchesRule("cmd /c del file.txt", string.Empty));
        Assert.False(MapToData.CommandLineMatchesRule("   ", "   "));
    }

    [Fact]
    public void EvaluateFileOperation_EmptyPath_DoesNotCreateProfile()
    {
        TestScope.WithFreshSession(() =>
        {
            Exception? ex = Record.Exception(() =>
                MapToData.EvaluateFileOperation(2_110_000_005, "tool.exe", string.Empty, "FileWrite"));

            Assert.Null(ex);
            Assert.False(MapToData.ActiveProfiles.ContainsKey(2_110_000_005));
        });
    }
}