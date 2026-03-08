using System;
using System.Collections.Concurrent;
using Xunit;

public class BehaviorAnalyzerTests
{
    private static ProcessProfile MakeProfile(string eventType, string indicator)
    {
        var profile = new ProcessProfile
        {
            ProcessId = 1234,
            ProcessName = "testprocess.exe",
            FirstSeen = DateTime.Now
        };
        profile.EventTimeline.Add(new SuspiciousEvent
        {
            Timestamp = DateTime.Now,
            EventType = eventType,
            MatchedIndicator = indicator,
            RawData = "unit-test"
        });
        return profile;
    }

    [Fact]
    public void EmptyTimeline_ShouldProduceZeroScore()
    {
        var profile = new ProcessProfile
        {
            ProcessId = 999,
            ProcessName = "clean.exe",
            FirstSeen = DateTime.Now
        };

        var report = BehaviorAnalyzer.Analyze(profile);

        Assert.Equal(0, report.ThreatScore);
    }

    [Fact]
    public void DNS_Query_ShouldRaiseScore()
    {
        var profile = MakeProfile("DNS_Query", "api.telegram.org");

        var report = BehaviorAnalyzer.Analyze(profile);

        Assert.True(report.ThreatScore > 0, $"Expected score > 0 for DNS_Query, got {report.ThreatScore}");
    }

    [Fact]
    public void RegistryPersistence_ShouldRaiseScore()
    {
        var profile = MakeProfile("Registry Persistence", "currentversion\\run");

        var report = BehaviorAnalyzer.Analyze(profile);

        Assert.True(report.ThreatScore > 0, $"Expected score > 0 for Registry Persistence, got {report.ThreatScore}");
        Assert.NotEmpty(report.Reasons);
    }

    [Fact]
    public void MultipleEvents_ShouldAccumulateScore()
    {
        var profile = new ProcessProfile
        {
            ProcessId = 5678,
            ProcessName = "malware.exe",
            FirstSeen = DateTime.Now
        };

        profile.EventTimeline.Add(new SuspiciousEvent { Timestamp = DateTime.Now, EventType = "DNS_Query",           MatchedIndicator = "pastebin.com",        RawData = "" });
        profile.EventTimeline.Add(new SuspiciousEvent { Timestamp = DateTime.Now, EventType = "Sensitive File Read", MatchedIndicator = "login data",           RawData = "" });
        profile.EventTimeline.Add(new SuspiciousEvent { Timestamp = DateTime.Now, EventType = "Registry Persistence",MatchedIndicator = "currentversion\\run",  RawData = "" });

        var single = BehaviorAnalyzer.Analyze(MakeProfile("DNS_Query", "pastebin.com"));
        var multi  = BehaviorAnalyzer.Analyze(profile);

        Assert.True(multi.ThreatScore > single.ThreatScore,
            $"Score with 3 events ({multi.ThreatScore}) should exceed score with 1 event ({single.ThreatScore})");
    }

    [Fact]
    public void ThreatRating_ShouldMatchScore()
    {
        var clean = new ProcessProfile { ProcessId = 1, ProcessName = "clean.exe", FirstSeen = DateTime.Now };
        var reportClean = BehaviorAnalyzer.Analyze(clean);

        Assert.Equal("Low", reportClean.Rating);
    }

    [Fact]
    public void SuspiciousCommand_ShouldRaiseScore()
    {
        var profile = MakeProfile("SuspiciousCommand", "-encodedcommand");

        var report = BehaviorAnalyzer.Analyze(profile);

        Assert.True(report.ThreatScore > 0, $"Expected score > 0 for SuspiciousCommand, got {report.ThreatScore}");
    }
}
