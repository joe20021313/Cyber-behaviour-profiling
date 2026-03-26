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
        var (tactic, techId, techName) = AttackNarrator.ResolveCategory(category);
        p.EventTimeline.Add(new SuspiciousEvent
        {
            Timestamp        = DateTime.Now,
            LastSeen         = DateTime.Now,
            EventType        = eventType,
            MatchedIndicator = indicator,
            RawData          = rawData,
            Tactic           = tactic,
            TechniqueId      = techId,
            TechniqueName    = techName,
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
    private static ChainConfirmationResult NoChain() => new();
    private static ChainConfirmationResult HardIndicator() =>
        new() { HasHardIndicator = true };
    private static ChainConfirmationResult ConfirmedChain() =>
        new() { HasConfirmedChain = true, HasHardIndicator = true };

    [Fact]
    public void ZeroScore_ReturnsSafe()
    {
        Assert.Equal("SAFE", AttackNarrator.ToGrade(0, NoChain()));
    }

    [Fact]
    public void LowScore_ReturnsSafe()
    {
        Assert.Equal("SAFE", AttackNarrator.ToGrade(5, NoChain()));
    }

    [Fact]
    public void HighScoreWithChain_ReturnsMalicious()
    {
        Assert.Equal("MALICIOUS", AttackNarrator.ToGrade(200, ConfirmedChain()));
    }

    [Fact]
    public void HighScoreNoChain_ReturnsSuspicious()
    {
        Assert.Equal("SUSPICIOUS", AttackNarrator.ToGrade(200, NoChain()));
    }

    [Fact]
    public void ReviewScoreWithHardIndicator_ReturnsSuspicious()
    {
        Assert.Equal("SUSPICIOUS", AttackNarrator.ToGrade(60, HardIndicator()));
    }

    [Fact]
    public void ReviewScoreNoSignals_ReturnsInconclusive()
    {
        Assert.Equal("INCONCLUSIVE", AttackNarrator.ToGrade(60, NoChain(), firedChecks: 0, observedTacticCount: 0));
    }

    [Fact]
    public void ReviewScoreWithTactics_ReturnsSuspicious()
    {
        Assert.Equal("SUSPICIOUS", AttackNarrator.ToGrade(60, NoChain(), firedChecks: 0, observedTacticCount: 2));
    }

    [Fact]
    public void ReviewScoreWithManyChecks_ReturnsSuspicious()
    {
        Assert.Equal("SUSPICIOUS", AttackNarrator.ToGrade(60, NoChain(), firedChecks: 4, observedTacticCount: 0));
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
        FinalScore = 200, FiredChecks = 5, ObservedTacticCount = 3,
        ChainResult = new ChainConfirmationResult { HasConfirmedChain = true, HasHardIndicator = true }
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
    public void SuspiciousEvent_TacticResolvedCorrectly()
    {
        var p = ProfileFactory.WithEvent("FileRead", "login data", "path", "credential_file_access");
        var ev = Assert.Single(p.EventTimeline);
        Assert.Equal("CredentialAccess", ev.Tactic);
        Assert.Equal("T1555", ev.TechniqueId);
    }
}
