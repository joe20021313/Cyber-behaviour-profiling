using Cyber_behaviour_profiling;

static class TestSetup
{
    static TestSetup()
    {
        MapToData._scoring = new ScoringConfig
        {
            low_threshold      = 15,
            medium_threshold   = 35,
            review_threshold   = 40,
            high_threshold     = 60,
            critical_threshold = 85
        };
    }

    public static void Init() { }
}

static class ProfileFactory
{
    public static ProcessProfile Empty(string name = "testprocess", int pid = 1) =>
        new() { ProcessId = pid, ProcessName = name, FirstSeen = DateTime.Now };

    public static ProcessProfile WithEvent(string eventType, string indicator,
        string rawData, string category, string name = "testprocess", int pid = 1)
    {
        var p = Empty(name, pid);
        AddEvent(p, eventType, indicator, rawData, category);
        return p;
    }

    public static void AddEvent(ProcessProfile p, string eventType, string indicator,
        string rawData, string category)
    {
        p.EventTimeline.Add(new SuspiciousEvent
        {
            Timestamp        = DateTime.Now,
            LastSeen         = DateTime.Now,
            EventType        = eventType,
            MatchedIndicator = indicator,
            RawData          = rawData,
            Category         = category,
            AttemptCount     = 1
        });
    }
}

public class CategoryMappingTests
{
    static CategoryMappingTests() => TestSetup.Init();
    [Fact]
    public void CredentialFileAccess_MapsToCredentialAccess()
    {
        var (tactic, id, _) = AttackNarrator.ResolveCategory("credential_file_access");
        Assert.Equal("CredentialAccess", tactic);
        Assert.Equal("T1555", id);
    }

    [Fact]
    public void RegistryPersistence_MapsToPersistence()
    {
        var (tactic, id, _) = AttackNarrator.ResolveCategory("registry_persistence");
        Assert.Equal("Persistence", tactic);
        Assert.Equal("T1547", id);
    }

    [Fact]
    public void NetworkC2_MapsToCommandAndControl()
    {
        var (tactic, id, _) = AttackNarrator.ResolveCategory("network_c2");
        Assert.Equal("CommandAndControl", tactic);
        Assert.Equal("T1071", id);
    }

    [Fact]
    public void ExeDrop_MapsToExecution()
    {
        var (tactic, id, _) = AttackNarrator.ResolveCategory("file_exe_drop");
        Assert.Equal("Execution", tactic);
        Assert.Equal("T1105", id);
    }

    [Fact]
    public void UnknownCategory_ReturnsEmpty()
    {
        var (tactic, id, name) = AttackNarrator.ResolveCategory("does_not_exist");
        Assert.Equal("", tactic);
        Assert.Equal("", id);
        Assert.Equal("", name);
    }

    [Fact]
    public void ContextSignal_IsNotHighValue()
    {
        Assert.False(AttackNarrator.IsHighValueCategory("context_signal"));
    }

    [Fact]
    public void CredentialAccess_IsHighValue()
    {
        Assert.True(AttackNarrator.IsHighValueCategory("credential_file_access"));
    }

    [Fact]
    public void NetworkC2_IsHighValue()
    {
        Assert.True(AttackNarrator.IsHighValueCategory("network_c2"));
    }
}

public class ToGradeTests
{
    static ToGradeTests() => TestSetup.Init();

    // ── New ThreatImpact-based tests ──

    [Fact]
    public void Safe_Impact_ReturnsSafe()
    {
        Assert.Equal("SAFE", AttackNarrator.ToGrade(ThreatImpact.Safe));
    }

    [Fact]
    public void Inconclusive_Impact_ReturnsInconclusive()
    {
        Assert.Equal("INCONCLUSIVE", AttackNarrator.ToGrade(ThreatImpact.Inconclusive));
    }

    [Fact]
    public void Suspicious_Impact_ReturnsSuspicious()
    {
        Assert.Equal("SUSPICIOUS", AttackNarrator.ToGrade(ThreatImpact.Suspicious));
    }

    [Fact]
    public void Malicious_Impact_ReturnsMalicious()
    {
        Assert.Equal("MALICIOUS", AttackNarrator.ToGrade(ThreatImpact.Malicious));
    }

    // ── Legacy int-based tests (backward compat) ──

    [Fact]
    public void ZeroScore_ReturnsSafe()
    {
        Assert.Equal("SAFE", AttackNarrator.ToGrade(0));
    }

    [Fact]
    public void LowScore_ReturnsInconclusive()
    {
        Assert.Equal("INCONCLUSIVE", AttackNarrator.ToGrade(20));
    }

    [Fact]
    public void HighScore_ReturnsSuspicious()
    {
        Assert.Equal("SUSPICIOUS", AttackNarrator.ToGrade(50));
    }

    [Fact]
    public void CriticalScore_ReturnsMalicious()
    {
        Assert.Equal("MALICIOUS", AttackNarrator.ToGrade(100));
    }
}

public class NarrativeTests
{
    static NarrativeTests() => TestSetup.Init();
    private static BehaviorReport SafeReport() => new()
    {
        FinalScore = 0, FiredChecks = 0, ObservedTacticCount = 0,
        ChainResult = new ChainConfirmationResult()
    };

    private static BehaviorReport MaliciousReport() => new()
    {
        FinalVerdict = ThreatImpact.Malicious,
        FinalScore = 90, FiredChecks = 5, ObservedTacticCount = 3,
        ChainResult = new ChainConfirmationResult { HasHardIndicator = true }
    };

    [Fact]
    public void EmptyProfile_BuildsNarrative_WithSafeGrade()
    {
        var profile = ProfileFactory.Empty();
        var narrative = AttackNarrator.BuildNarrative(profile, SafeReport());
        Assert.Equal("SAFE", narrative.Grade);
        Assert.Empty(narrative.Timeline);
    }

    [Fact]
    public void MaliciousReport_BuildsNarrative_WithMaliciousGrade()
    {
        var profile = ProfileFactory.WithEvent(
            "FileRead", "login data",
            @"C:\Users\VM\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            "credential_file_access");

        var narrative = AttackNarrator.BuildNarrative(profile, MaliciousReport());
        Assert.Equal("MALICIOUS", narrative.Grade);
        Assert.NotEmpty(narrative.Timeline);
    }

    [Fact]
    public void CredentialEvent_Headline_MentionsBrowserPasswords()
    {
        var profile = ProfileFactory.WithEvent(
            "FileRead", "login data",
            @"C:\Users\VM\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            "credential_file_access");

        var narrative = AttackNarrator.BuildNarrative(profile, MaliciousReport());
        var headline = narrative.Timeline[0].Headline;
        Assert.Contains("browser", headline, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RegistryEvent_Headline_MentionsWinlogon()
    {
        var profile = ProfileFactory.WithEvent(
            "Registry", "winlogon",
            @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "registry_persistence");

        var narrative = AttackNarrator.BuildNarrative(profile, MaliciousReport());
        var headline = narrative.Timeline[0].Headline;
        Assert.Contains("Winlogon", headline, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ProcessName_SetCorrectly_InNarrative()
    {
        var profile = ProfileFactory.Empty("powershell", 1234);
        var narrative = AttackNarrator.BuildNarrative(profile, SafeReport());
        Assert.Equal("powershell", narrative.ProcessName);
        Assert.Equal(1234, narrative.ProcessId);
    }

    [Fact]
    public void Timeline_OrderedByTimestamp()
    {
        var profile = ProfileFactory.Empty();
        ProfileFactory.AddEvent(profile, "Registry", "winlogon", "key1", "registry_persistence");
        System.Threading.Thread.Sleep(5);
        ProfileFactory.AddEvent(profile, "FileRead", "login data", "file1", "credential_file_access");

        var narrative = AttackNarrator.BuildNarrative(profile, MaliciousReport());
        Assert.True(narrative.Timeline[0].Timestamp <= narrative.Timeline[1].Timestamp);
    }

    [Fact]
    public void TotalSeconds_CalculatedFromFirstAndLastEvent()
    {
        var profile = ProfileFactory.Empty();
        ProfileFactory.AddEvent(profile, "Registry", "winlogon", "key1", "registry_persistence");
        System.Threading.Thread.Sleep(50);
        ProfileFactory.AddEvent(profile, "FileRead", "login data", "file1", "credential_file_access");

        var narrative = AttackNarrator.BuildNarrative(profile, MaliciousReport());
        Assert.True(narrative.TotalSeconds >= 0.05);
    }
}

public class ProcessProfileTests
{
    static ProcessProfileTests() => TestSetup.Init();
    [Fact]
    public void NewProfile_HasEmptyTimeline()
    {
        var p = ProfileFactory.Empty();
        Assert.Empty(p.EventTimeline);
    }

    [Fact]
    public void AddingEvents_IncreasesTimeline()
    {
        var p = ProfileFactory.Empty();
        ProfileFactory.AddEvent(p, "Registry", "winlogon", "key", "registry_persistence");
        ProfileFactory.AddEvent(p, "FileRead", "login data", "file", "credential_file_access");
        Assert.Equal(2, p.EventTimeline.Count);
    }

    [Fact]
    public void SuspiciousEvent_CategoryStoredCorrectly()
    {
        var p = ProfileFactory.WithEvent("FileRead", "login data", "path", "credential_file_access");
        var ev = Assert.Single(p.EventTimeline);
        Assert.Equal("credential_file_access", ev.Category);
        Assert.Equal("", ev.Tactic);
    }
}

public class AnomalyDetectorTests
{
    static AnomalyDetectorTests() => TestSetup.Init();

    private static ProcessProfile BuildProfileWithBaseline(double steadyWriteRate, int samples)
    {
        var p = ProfileFactory.Empty();

        for (int i = 0; i < samples; i++)
            p.AnomalyHistory.Add(new[] { steadyWriteRate, 0.0, 0.0, 0.0 });

        for (int i = 0; i < samples; i++)
            p.KnnScores.Add(0.01);

        p.TotalFileWrites = (int)(steadyWriteRate * samples);
        p.PrevFileWrites = p.TotalFileWrites;
        p.PrevFileDeletes = 0;
        p.PrevEventCount = 0;
        p.PrevSnapshotTime = DateTime.Now.AddSeconds(-1);

        return p;
    }

    [Fact]
    public void NotEnoughSamples_NoAnomaly()
    {
        var p = ProfileFactory.Empty();
        p.PrevSnapshotTime = DateTime.Now.AddSeconds(-2);
        p.TotalFileWrites = 10;
        var ctx = new ProcessContext { NetworkConnCount = 0 };

        var result = AnomalyDetector.Evaluate(p, ctx);
        Assert.False(result.AnomalyDetected);
    }

    [Fact]
    public void SteadyBaseline_NoAnomaly()
    {
        var p = BuildProfileWithBaseline(steadyWriteRate: 5, samples: 8);
        var ctx = new ProcessContext { NetworkConnCount = 0 };

        p.TotalFileWrites += 5;
        var result = AnomalyDetector.Evaluate(p, ctx);
        Assert.False(result.AnomalyDetected);
    }

    [Fact]
    public void SpikeAfterBaseline_DetectsAnomaly()
    {
        var p = BuildProfileWithBaseline(steadyWriteRate: 5, samples: 8);
        var ctx = new ProcessContext { NetworkConnCount = 0 };

        p.TotalFileWrites += 500;
        var result = AnomalyDetector.Evaluate(p, ctx);
        Assert.True(result.AnomalyDetected,
            $"Score={result.Score}, KnnDist={result.KnnDistance:F4}, Threshold={result.Threshold:F4}, " +
            $"History={p.AnomalyHistory.Count}, KnnScores={p.KnnScores.Count}");
    }

    [Fact]
    public void AnomalyScore_ClampedInRange()
    {
        var p = BuildProfileWithBaseline(steadyWriteRate: 5, samples: 8);
        var ctx = new ProcessContext { NetworkConnCount = 0 };

        p.TotalFileWrites += 500;
        var result = AnomalyDetector.Evaluate(p, ctx);
        Assert.True(result.Score >= 15 && result.Score <= 45,
            $"Score={result.Score}, Detected={result.AnomalyDetected}, KnnDist={result.KnnDistance:F4}");
    }

    [Fact]
    public void AnomalyResult_FeedsIntoBehaviorReport()
    {
        var report = new BehaviorReport();
        var anomaly = new AnomalyResult
        {
            AnomalyDetected = true,
            Score = 30,
            SpikedMetrics = new List<string> { "File Write Rate: 50.0/sec (baseline: 5.0/sec)" }
        };
        report.Anomaly = anomaly;

        Assert.NotNull(report.Anomaly);
        Assert.True(report.Anomaly.AnomalyDetected);
        Assert.Equal(30, report.Anomaly.Score);
    }
}
