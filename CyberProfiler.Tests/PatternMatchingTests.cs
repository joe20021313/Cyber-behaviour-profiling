using System;
using System.Linq;
using Cyber_behaviour_profiling;

public class PatternMatchingTests
{
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

    [Fact]
    public void CommandLineMatchesRule_NormalizesCaseQuotesAndWhitespace()
    {
        Assert.True(MapToData.CommandLineMatchesRule(
            "  POWERSHELL.EXE   -ENC   AAAA  ",
            "powershell -enc"));
    }

    [Fact]
    public void EvaluateFileOperation_RuntimeArtifact_IsTrackedSeparately()
    {
        TestScope.WithFreshSession(() =>
        {
            MapToData.EvaluateFileOperation(
                2_130_000_001,
                "tool.exe",
                @"C:\Users\Wolf\AppData\Local\Temp\_MEI123\python310.dll",
                "FileWrite");
            MapToData.EvaluateFileOperation(
                2_130_000_001,
                "tool.exe",
                @"C:\Users\Wolf\AppData\Local\Temp\_MEI123\python310.dll",
                "FileDelete");

            var profile = MapToData.ActiveProfiles[2_130_000_001];

            Assert.Empty(profile.ExeDropPaths);
            Assert.Single(profile.RuntimeArtifactPaths);
            Assert.Empty(profile.DeletedPaths);
            Assert.Single(profile.DeletedRuntimeArtifacts);
        }, loadData: true);
    }

    [Fact]
    public void EvaluateProcessSpawn_SuspiciousCommand_RecordsEvent()
    {
        TestScope.WithFreshSession(() =>
        {
            MapToData.EvaluateProcessSpawn(
                2_130_000_002,
                "testapp.exe",
                2_130_000_003,
                "cmd.exe",
                @"C:\Windows\System32\cmd.exe",
                "cmd.exe /c del file.txt");

            var parentProfile = MapToData.ActiveProfiles[2_130_000_002];

            Assert.Contains(parentProfile.EventTimeline, ev =>
                ev.EventType == "SuspiciousCommand" &&
                ev.MatchedIndicator.Contains("cmd /c del", StringComparison.OrdinalIgnoreCase));
        }, loadData: true);
    }

    [Fact]
    public void EvaluateRegistryAccess_RunKeyWrite_RecordsPersistenceEvent()
    {
        TestScope.WithFreshSession(() =>
        {
            MapToData.EvaluateRegistryAccess(
                2_130_000_004,
                "tool.exe",
                @"\Registry\Machine\Software\Microsoft\Windows\CurrentVersion\Run",
                "SetValue");

            var profile = MapToData.ActiveProfiles[2_130_000_004];
            Assert.Contains(profile.EventTimeline, ev =>
                ev.EventType == "Registry" &&
                ev.Category == "registry_persistence");
        }, loadData: true);
    }

    [Fact]
    public void EvaluateNetworkConnection_SuspiciousDomain_RecordsNetworkC2()
    {
        TestScope.WithFreshSession(() =>
        {
            MapToData.EvaluateNetworkConnection(2_130_000_005, "tool.exe", "pastebin.com");

            var profile = MapToData.ActiveProfiles[2_130_000_005];
            Assert.Contains(profile.EventTimeline, ev =>
                ev.EventType == "NetworkConnect" &&
                ev.Category == "network_c2");
        }, loadData: true);
    }

    [Fact]
    public void EvaluateNetworkConnection_GenericHost_RecordsNetworkOutbound()
    {
        TestScope.WithFreshSession(() =>
        {
            MapToData.EvaluateNetworkConnection(2_130_000_006, "tool.exe", "example.org");

            var profile = MapToData.ActiveProfiles[2_130_000_006];
            Assert.Contains(profile.EventTimeline, ev =>
                ev.EventType == "NetworkConnect" &&
                ev.Category == "network_outbound");
        }, loadData: true);
    }

    [Fact]
    public void EvaluateFileRead_SensitiveCredentialFile_RecordsCredentialAccess()
    {
        TestScope.WithFreshSession(() =>
        {
            MapToData.EvaluateFileOperation(
                2_130_000_007,
                "stealer.exe",
                @"C:\Users\VM\AppData\Local\Google\Chrome\User Data\Default\Login Data",
                "FileRead");

            var profile = MapToData.ActiveProfiles[2_130_000_007];

            Assert.True(profile.TotalSensitiveAccessEvents > 0);
            Assert.Contains(profile.EventTimeline, ev =>
                ev.Category == "credential_file_access" &&
                ev.MatchedIndicator.Contains("login data", StringComparison.OrdinalIgnoreCase));
        }, loadData: true);
    }
}