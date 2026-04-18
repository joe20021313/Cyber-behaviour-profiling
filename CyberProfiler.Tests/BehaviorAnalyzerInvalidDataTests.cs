using Cyber_behaviour_profiling;

public class BehaviorAnalyzerInvalidDataTests
{
    [Fact]
    public void EmptyProfile_NoEvents_ReturnsSafe()
    {
        var profile = ProfileFactory.Empty("idle.exe", 2_110_000_001);

        var report = BehaviorAnalyzer.Analyze(profile);

        Assert.Equal(ThreatImpact.Safe, report.FinalVerdict);
        Assert.Empty(report.FiredCheckNames);
    }

    [Fact]
    public void InsufficientVectors_NoBaseline_ReturnsSafeWithNotice()
    {
        var profile = ProfileFactory.Empty("writer.exe", 2_110_000_002);
        profile.AnomalyHistory.Add(new[] { 1.0, 0.0, 0.0, 0.0 });
        profile.AnomalyHistory.Add(new[] { 1.1, 0.0, 0.0, 0.0 });
        profile.AnomalyHistory.Add(new[] { 0.9, 0.0, 0.0, 0.0 });

        var report = BehaviorAnalyzer.Analyze(profile);

        Assert.Equal(ThreatImpact.Safe, report.FinalVerdict);
        Assert.Contains(report.DecisionReasons, r =>
            r.Contains("Not enough data yet", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CommandLineMatchesRule_EmptyInputs_ReturnsFalse()
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
            var ex = Record.Exception(() =>
                MapToData.EvaluateFileOperation(2_110_000_005, "tool.exe", string.Empty, "FileWrite"));

            Assert.Null(ex);
            Assert.False(MapToData.ActiveProfiles.ContainsKey(2_110_000_005));
        });
    }
}
