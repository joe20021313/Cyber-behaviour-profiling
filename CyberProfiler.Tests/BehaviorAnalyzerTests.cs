using System.IO;
using Cyber_behaviour_profiling;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

static class ProfileFactory
{
    public static ProcessProfile Empty(string name = "testprocess.exe", int pid = 2_000_000_000) =>
        new() { ProcessId = pid, ProcessName = name, FirstSeen = DateTime.Now };

    public static SuspiciousEvent Event(
        string eventType,
        string indicator,
        string rawData,
        string category,
        DateTime? timestamp = null,
        DateTime? lastSeen = null,
        int attemptCount = 1) =>
        new()
        {
            Timestamp = timestamp ?? DateTime.Now,
            LastSeen = lastSeen ?? timestamp ?? DateTime.Now,
            EventType = eventType,
            MatchedIndicator = indicator,
            RawData = rawData,
            Category = category,
            AttemptCount = attemptCount
        };

    public static ProcessProfile WithEvent(
        string eventType,
        string indicator,
        string rawData,
        string category,
        string name = "testprocess.exe",
        int pid = 2_000_000_000)
    {
        var profile = Empty(name, pid);
        AddEvent(profile, eventType, indicator, rawData, category);
        return profile;
    }

    public static void AddEvent(
        ProcessProfile profile,
        string eventType,
        string indicator,
        string rawData,
        string category,
        DateTime? timestamp = null,
        DateTime? lastSeen = null,
        int attemptCount = 1)
    {
        profile.EventTimeline.Add(Event(
            eventType,
            indicator,
            rawData,
            category,
            timestamp,
            lastSeen,
            attemptCount));
    }
}

static class TestDataLoader
{
    private static readonly object Gate = new();

    public static void EnsureLoaded()
    {
        lock (Gate)
        {
            string dataPath = Path.GetFullPath(
                Path.Combine(AppContext.BaseDirectory, "../../../../data.json"));
            MapToData.LoadData(dataPath);
        }
    }
}

static class TestScope
{
    public static void WithFreshSession(Action action, bool loadData = false)
    {
        MapToData.ResetSession();
        try
        {
            if (loadData)
                TestDataLoader.EnsureLoaded();

            action();
        }
        finally
        {
            MapToData.ResetSession();
        }
    }
}

static class SignatureTestScope
{
    public static void WithSignatureResult(SignatureVerificationResult result, Action action)
    {
        using var _ = SignatureVerifier.PushTestOverride(_ => result);
        action();
    }
}

static class TemporaryFileScope
{
    public static void WithExecutableFile(Action<string> action)
    {
        string path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.exe");
        File.WriteAllText(path, "placeholder");

        try
        {
            action(path);
        }
        finally
        {
            try
            {
                if (File.Exists(path))
                    File.Delete(path);
            }
            catch
            {
            }
        }
    }
}

public class AttackNarratorSmokeTests
{
    [Fact]
    public void BuildNarrative_UsesObservedWindowFromLastSeen()
    {
        var profile = ProfileFactory.Empty("collector.exe", 2_000_000_101);
        DateTime start = DateTime.Now;

        profile.EventTimeline.Add(ProfileFactory.Event(
            "Registry",
            "winlogon",
            "key1",
            "registry_persistence",
            start,
            start.AddSeconds(1.5)));
        profile.EventTimeline.Add(ProfileFactory.Event(
            "FileRead",
            "login data",
            "file1",
            "credential_file_access",
            start.AddMilliseconds(200),
            start.AddMilliseconds(300)));

        var report = new BehaviorReport
        {
            FinalVerdict = ThreatImpact.Malicious,
            ChainResult = new ChainConfirmationResult { HasHardIndicator = true }
        };

        var narrative = AttackNarrator.BuildNarrative(profile, report);

        Assert.True(narrative.HasObservedTimeline);
        Assert.True(narrative.TotalSeconds >= 1.4,
            $"Expected >= 1.4s but got {narrative.TotalSeconds:F2}s");
    }

    [Fact]
    public void DescribeSpawnedCommand_WithConcreteRule_UsesSpecificDescription()
    {
        TestScope.WithFreshSession(() =>
        {
            string label = AttackNarrator.DescribeSpawnedCommand("cmd.exe", "cmd.exe /c del file.txt");

            Assert.Contains("file deletion command", label, StringComparison.OrdinalIgnoreCase);
        }, loadData: true);
    }

    [Fact]
    public void BuildNarrative_WithoutTimeline_PreservesLaunchContext()
    {
        var profile = ProfileFactory.Empty("powershell.exe", 2_000_000_102);
        profile.SpawnedAt = DateTime.Now;
        profile.ParentProcessIdAtSpawn = 4242;
        profile.ParentProcessNameAtSpawn = "testapp.exe";
        profile.LaunchCommandLineAtSpawn = "powershell.exe -w hidden -ep bypass -nop -c whoami";

        var narrative = AttackNarrator.BuildNarrative(profile, new BehaviorReport
        {
            FinalVerdict = ThreatImpact.Safe,
            IsSigned = false,
            SignerName = ""
        });

        Assert.False(narrative.HasObservedTimeline);
        Assert.NotEmpty(narrative.LaunchContext);
        Assert.Contains("testapp.exe", narrative.LaunchContext[0], StringComparison.OrdinalIgnoreCase);
    }
}

public class MapToDataMechanismTests
{
    [Fact]
    public void TakeAnomalySnapshot_UsesFileCentricDeltas()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.Empty("testprocess.exe", 42);
            profile.PrevSnapshotTime = DateTime.Now.AddSeconds(-2);
            profile.TotalFilteredWrites = 6;
            profile.TotalFilteredDeletes = 2;
            profile.TotalPayloadLikeWrites = 1;
            profile.TotalSensitiveAccessEvents = 2;
            profile.PrevFilteredWrites = 0;
            profile.PrevFilteredDeletes = 0;
            profile.PrevPayloadLikeWrites = 0;
            profile.PrevSensitiveAccessEvents = 0;

            MapToData.ActiveProfiles[profile.ProcessId] = profile;

            MapToData.TakeAnomalySnapshot();

            List<double[]> history;
            lock (profile.KnnStateLock)
                history = profile.AnomalyHistory.ToList();

            Assert.NotEmpty(history);
            double[] latest = history[^1];
            Assert.Equal(4, latest.Length);
            Assert.True(latest[0] > 2.0, $"Filtered write rate too low: {latest[0]:F2}");
            Assert.True(latest[1] > 0.5, $"Filtered delete rate too low: {latest[1]:F2}");
            Assert.True(latest[2] > 0.3, $"Payload write rate too low: {latest[2]:F2}");
            Assert.True(latest[3] > 0.5, $"Sensitive access rate too low: {latest[3]:F2}");
        });
    }

    [Fact]
    public void TakeAnomalySnapshot_TrimsHistoryToRecentWindow()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.Empty("writer.exe", 43);
            for (int i = 0; i < 60; i++)
                profile.AnomalyHistory.Add(new double[4]);

            profile.PrevSnapshotTime = DateTime.Now.AddSeconds(-1);
            profile.TotalFilteredWrites = 5;

            MapToData.ActiveProfiles[profile.ProcessId] = profile;
            MapToData.TakeAnomalySnapshot();

            List<double[]> history;
            lock (profile.KnnStateLock)
                history = profile.AnomalyHistory.ToList();

            Assert.Equal(60, history.Count);
            Assert.True(history[^1][0] > 0.0, $"Expected latest filtered write rate to be recorded but got {history[^1][0]:F2}");
        });
    }

    [Fact]
    public void EvaluateFileOperation_RuntimeArtifact_IsTrackedSeparately()
    {
        TestScope.WithFreshSession(() =>
        {
            MapToData.EvaluateFileOperation(
                501,
                "tool.exe",
                @"C:\Users\Wolf\AppData\Local\Temp\_MEI123\python310.dll",
                "FileWrite");
            MapToData.EvaluateFileOperation(
                501,
                "tool.exe",
                @"C:\Users\Wolf\AppData\Local\Temp\_MEI123\python310.dll",
                "FileDelete");

            var profile = MapToData.ActiveProfiles[501];

            Assert.Empty(profile.ExeDropPaths);
            Assert.Single(profile.RuntimeArtifactPaths);
            Assert.Empty(profile.DeletedPaths);
            Assert.Single(profile.DeletedRuntimeArtifacts);
        }, loadData: true);
    }

    [Fact]
    public void EvaluateProcessSpawn_PreservesChildProvenance_WithoutSuspiciousCommandMatch()
    {
        TestScope.WithFreshSession(() =>
        {
            MapToData.EvaluateProcessSpawn(
                9001,
                "testapp.exe",
                9002,
                "whoami.exe",
                @"C:\Windows\System32\whoami.exe",
                "whoami.exe /all");

            var childProfile = MapToData.ActiveProfiles[9002];

            Assert.Equal(9001, childProfile.ParentProcessIdAtSpawn);
            Assert.Equal("testapp.exe", childProfile.ParentProcessNameAtSpawn);
            Assert.Equal("whoami.exe /all", childProfile.LaunchCommandLineAtSpawn);
            Assert.Single(childProfile.InheritedCommandContexts);
        });
    }

    [Fact]
    public void TakeAnomalySnapshot_DoesNotSeedSyntheticBootstrapSamples()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.Empty("writer.exe", 44);
            profile.PrevSnapshotTime = DateTime.Now.AddSeconds(-1);
            profile.TotalFileWrites = 4;
            profile.TotalPayloadLikeWrites = 1;

            MapToData.ActiveProfiles[profile.ProcessId] = profile;
            MapToData.TakeAnomalySnapshot();

            List<double[]> history;
            lock (profile.KnnStateLock)
                history = profile.AnomalyHistory.ToList();

            Assert.Single(history);
            Assert.True(history[0].Any(value => value > 0.0), "Expected the first snapshot to be a real measurement.");
        });
    }
}

public class AnomalyDetectorMechanismTests
{
    private static void AddFeatureSnapshot(
        ProcessProfile profile,
        double filteredWriteRate,
        double filteredDeleteRate,
        double payloadRate,
        double sensitiveRate)
    {
        profile.AnomalyHistory.Add(
        [
            filteredWriteRate,
            filteredDeleteRate,
            payloadRate,
            sensitiveRate
        ]);
    }

    private static ProcessProfile BuildProfileWithBaseline(
        double steadyWriteRate,
        int samples,
        double deleteRate = 0.0,
        double payloadLikeRate = 0.0,
        double sensitiveAccessRate = 0.0)
    {
        var profile = ProfileFactory.Empty();

        for (int i = 0; i < samples; i++)
            profile.AnomalyHistory.Add(new[] { steadyWriteRate, deleteRate, payloadLikeRate, sensitiveAccessRate });

        return profile;
    }

    [Fact]
    public void SteadyBaseline_DoesNotDetectAnomaly()
    {
        var profile = BuildProfileWithBaseline(steadyWriteRate: 5, samples: 8);
        var result = AnomalyDetector.Evaluate(profile, new ProcessContext());

        Assert.False(result.AnomalyDetected);
    }

    [Fact]
    public void PayloadBurst_DetectsAnomaly()
    {
        var profile = BuildProfileWithBaseline(steadyWriteRate: 5, samples: 8);

        AddFeatureSnapshot(profile, 20.0, 5.0, 3.0, 2.0);
        var result = AnomalyDetector.Evaluate(profile, new ProcessContext());

        Assert.True(result.AnomalyDetected,
            $"Score={result.Score}, KnnDist={result.KnnDistance:F4}, Threshold={result.Threshold:F4}");
        Assert.Contains(result.SpikedMetrics,
            metric => metric.Contains("Payload Write Rate", StringComparison.OrdinalIgnoreCase) ||
                      metric.Contains("Sensitive Access Rate", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ModerateWriteShift_DoesNotTriggerAnomaly()
    {
        var profile = ProfileFactory.Empty();

        for (int i = 0; i < 10; i++)
            profile.AnomalyHistory.Add(new[] { 0.0, 0.0, 0.0, 0.0 });

        profile.AnomalyHistory.Add(new[] { 3.0, 0.0, 0.0, 0.0 });
        var result = AnomalyDetector.Evaluate(profile, new ProcessContext());

        Assert.False(result.AnomalyDetected,
            $"Score={result.Score}, KnnDist={result.KnnDistance:F4}, Threshold={result.Threshold:F4}");
    }

    [Fact]
    public void EarlierSpike_StillDetectedEvenWithQuietLatestSnapshot()
    {
        var profile = BuildProfileWithBaseline(steadyWriteRate: 1, samples: 8);

        AddFeatureSnapshot(profile, 18.0, 5.0, 3.0, 2.0);
        profile.AnomalyHistory.Add(new[] { 1.0, 0.0, 0.0, 0.0 });

        var result = AnomalyDetector.Evaluate(profile, new ProcessContext());

        Assert.True(result.AnomalyDetected,
            $"Spike in history should still be detected. Score={result.Score}, KnnDist={result.KnnDistance:F4}, Threshold={result.Threshold:F4}");
    }

    [Fact]
    public void SimilarSnapshots_DoNotTriggerAnomaly()
    {
        var profile = ProfileFactory.Empty("msbuild.exe", 2_000_000_499);

        AddFeatureSnapshot(profile, 38.0, 2.0, 0.0, 0.0);
        AddFeatureSnapshot(profile, 44.0, 3.0, 0.0, 0.0);
        AddFeatureSnapshot(profile, 40.0, 2.5, 0.0, 0.0);
        AddFeatureSnapshot(profile, 42.0, 2.0, 0.0, 0.0);
        AddFeatureSnapshot(profile, 39.0, 2.2, 0.0, 0.0);

        var result = AnomalyDetector.Evaluate(profile, new ProcessContext());

        Assert.False(result.AnomalyDetected,
            $"Score={result.Score}, KnnDist={result.KnnDistance:F4}, Threshold={result.Threshold:F4}");
    }
}

public class AnomalyImpactTests
{
    [Fact]
    public void NoAnomaly_ReturnsSafe()
    {
        var impact = BehaviorAnalyzer.DetermineAnomalyImpact(
            new AnomalyResult { AnomalyDetected = false },
            Array.Empty<SuspiciousEvent>(),
            ProfileFactory.Empty(),
            hasBehavioralRedFlag: false,
            hasHardIndicator: false);

        Assert.Equal(ThreatImpact.Safe, impact);
    }

    [Fact]
    public void FocusedBurstWithoutCorroboration_ReturnsSafe()
    {
        var impact = BehaviorAnalyzer.DetermineAnomalyImpact(
            new AnomalyResult
            {
                AnomalyDetected = true,
                KnnDistance = 2.0,
                Threshold = 1.0,
                SpikedMetrics = new List<string> { "File Write Burst: 12.0 writes/sec (baseline: 2.0)" }
            },
            Array.Empty<SuspiciousEvent>(),
            ProfileFactory.Empty(),
            hasBehavioralRedFlag: false,
            hasHardIndicator: false);

        Assert.Equal(ThreatImpact.Safe, impact);
    }

    [Fact]
    public void SustainedAnomalyWithoutCorroboration_ReturnsInconclusive()
    {
        var impact = BehaviorAnalyzer.DetermineAnomalyImpact(
            new AnomalyResult
            {
                AnomalyDetected = true,
                KnnDistance = 2.4,
                Threshold = 1.0,
                ConsecutiveAnomalousWindows = 2,
                SpikedMetrics = new List<string>
                {
                    "Directory Spread: 4 top-level dir(s) (baseline: 1.0)",
                    "Dispersed Write Ratio: 65 % (baseline: 5 %)"
                }
            },
            Array.Empty<SuspiciousEvent>(),
            ProfileFactory.Empty(),
            hasBehavioralRedFlag: false,
            hasHardIndicator: false);

        Assert.Equal(ThreatImpact.Inconclusive, impact);
    }

    [Fact]
    public void AnomalyWithSensitiveDirectoryEvidence_ReturnsSuspicious()
    {
        var profile = ProfileFactory.Empty("testapp.exe", 2_000_000_401);
        profile.WriteDirectories.TryAdd(@"c:\users\user\appdata\local\temp\sim_2401\scratch", 20);

        var anomaly = new AnomalyResult
        {
            AnomalyDetected = true,
            SpikedMetrics = new List<string>
            {
                "File Write Rate: 18.9/sec (baseline: 0.0/sec)",
                "Payload-Like Writes: 1.0/sec (baseline: 0.0/sec)"
            }
        };

        var events = new List<SuspiciousEvent>
        {
            ProfileFactory.Event(
                "SensitiveDirAccess",
                "secure notes",
                @"C:\Users\VM\AppData\Roaming\SecureNotes\notes.db",
                "collection")
        };

        var impact = BehaviorAnalyzer.DetermineAnomalyImpact(
            anomaly,
            events,
            profile,
            hasBehavioralRedFlag: false,
            hasHardIndicator: false);

        Assert.Equal(ThreatImpact.Suspicious, impact);
        Assert.Equal(1, BehaviorAnalyzer.CountTopWriteDirectories(profile));
    }

    [Fact]
    public void AnomalyWithCredentialEvidence_ReturnsMalicious()
    {
        var anomaly = new AnomalyResult
        {
            AnomalyDetected = true,
            SpikedMetrics = new List<string>
            {
                "Sensitive Access: 2.0/sec (baseline: 0.0/sec)",
                "File Write Rate: 6.0/sec (baseline: 0.0/sec)"
            }
        };

        var events = new List<SuspiciousEvent>
        {
            ProfileFactory.Event(
                "FileRead",
                "login data",
                @"C:\Users\VM\AppData\Local\Google\Chrome\User Data\Default\Login Data",
                "credential_file_access")
        };

        var impact = BehaviorAnalyzer.DetermineAnomalyImpact(
            anomaly,
            events,
            ProfileFactory.Empty("stealer.exe", 2_000_000_402),
            hasBehavioralRedFlag: false,
            hasHardIndicator: false);

        Assert.Equal(ThreatImpact.Malicious, impact);
    }
}

public class RuntimeCorroborationTests
{
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

        var profile = ProfileFactory.Empty("app.exe", 2_000_000_501);
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
    public void GenericOutboundWithCredentialAccess_FlagsUnexpectedNetwork()
    {
        var ctx = new ProcessContext
        {
            HasNetworkConns = true,
            NetworkConnCount = 2,
            FilePath = @"C:\Users\User\AppData\Local\SomeApp\app.exe",
            ParentProcess = "explorer"
        };

        var profile = ProfileFactory.Empty("app.exe", 2_000_000_502);
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
            ProfileFactory.Empty("app.exe", 2_000_000_503));

        Assert.False(flagged);
    }

    [Fact]
    public void ElevatedUnsignedWithInheritedSuspiciousCommand_FlagsUnexpectedElevation()
    {
        TestScope.WithFreshSession(() =>
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

            var profile = ProfileFactory.Empty("powershell.exe", 2_000_000_504);
            profile.InheritedCommandContexts.Add(new InheritedCommandContext
            {
                Timestamp = DateTime.Now,
                ParentProcessId = 5000,
                ParentProcessName = "launcher.exe",
                CommandLine = "powershell.exe -exec bypass -enc AAAA"
            });

            bool flagged = BehaviorAnalyzer.ShouldFlagUnexpectedElevation(
                ctx,
                new List<SuspiciousEvent>(),
                profile);

            Assert.True(flagged);
        }, loadData: true);
    }
}

public class BehaviorAnalyzerVerdictTests
{
    [Fact]
    public void WriteAnomalyWithoutCorroboration_RemainsSafe()
    {
        var profile = BuildWriteAnomalyProfile("writer.exe", 2_000_000_600);

        var report = BehaviorAnalyzer.Analyze(profile);

        Assert.NotNull(report.Anomaly);
        Assert.True(report.Anomaly!.AnomalyDetected);
        Assert.Equal(ThreatImpact.Safe, report.FinalVerdict);
        Assert.DoesNotContain(report.DecisionReasons,
            reason => reason.Contains("Anomaly detector (KNN)", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void WriteAnomalyWithSensitiveAccess_ReturnsSuspicious()
    {
        var profile = BuildWriteAnomalyProfile("writer.exe", 2_000_000_608);
        ProfileFactory.AddEvent(
            profile,
            "SensitiveDirAccess",
            "secure notes",
            @"C:\Users\VM\AppData\Roaming\SecureNotes\notes.db",
            "collection");

        var report = BehaviorAnalyzer.Analyze(profile);

        Assert.NotNull(report.Anomaly);
        Assert.True(report.Anomaly!.AnomalyDetected);
        Assert.Equal(ThreatImpact.Suspicious, report.FinalVerdict);
        Assert.Contains(report.DecisionReasons,
            reason => reason.Contains("Anomaly detector (KNN)", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void GenericOutboundOnly_RemainsSafe()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.WithEvent(
                "NetworkConnect",
                "example.org",
                "example.org (93.184.216.34)",
                "network_outbound",
                "app.exe",
                2_000_000_601);

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.Equal(ThreatImpact.Safe, report.FinalVerdict);
            Assert.Empty(report.FiredCheckNames);
        });
    }

    [Fact]
    public void HiddenWindowCommandOnly_ReturnsInconclusive()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.Empty("powershell.exe", 2_000_000_602);
            profile.InheritedCommandContexts.Add(new InheritedCommandContext
            {
                Timestamp = DateTime.Now,
                ParentProcessId = 6001,
                ParentProcessName = "launcher.exe",
                CommandLine = "powershell.exe -windowstyle hidden -command whoami"
            });

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.Equal(ThreatImpact.Inconclusive, report.FinalVerdict);
            Assert.Contains(report.FiredCheckNames,
                name => name == "Hidden or Minimized Command Execution");
        }, loadData: true);
    }

    [Fact]
    public void UnsignedProcess_DoesNotCreateStandaloneUnsignedFinding()
    {
        TestScope.WithFreshSession(() =>
        {
            TemporaryFileScope.WithExecutableFile(imagePath =>
            {
                SignatureTestScope.WithSignatureResult(new SignatureVerificationResult
                {
                    HasSignature = false,
                    IsCryptographicallyValid = false,
                    IsTrustedPublisher = false,
                    TrustState = SignatureTrustState.NoSignature,
                    Summary = "No digital signature present."
                }, () =>
                {
                    var profile = ProfileFactory.Empty("app.exe", 2_100_000_621);
                    profile.ImagePath = imagePath;
                    ProfileFactory.AddEvent(profile, "FileOpen", "readme.txt", @"C:\Work\readme.txt", "");

                    var report = BehaviorAnalyzer.Analyze(profile);

                    Assert.Equal(SignatureTrustState.NoSignature, report.SignatureTrustState);
                    Assert.DoesNotContain(report.FiredCheckNames,
                        name => name == "Unsigned Binary");
                    Assert.DoesNotContain(report.DecisionReasons,
                        reason => reason.Contains("verified digital signature", StringComparison.OrdinalIgnoreCase));
                });
            });
        }, loadData: true);
    }

    [Fact]
    public void ValidButUntrustedSignature_DoesNotClearInconclusiveVerdict()
    {
        TestScope.WithFreshSession(() =>
        {
            TemporaryFileScope.WithExecutableFile(imagePath =>
            {
                SignatureTestScope.WithSignatureResult(new SignatureVerificationResult
                {
                    HasSignature = true,
                    IsCryptographicallyValid = true,
                    IsTrustedPublisher = false,
                    TrustState = SignatureTrustState.ValidSignatureUntrustedPublisher,
                    PublisherName = "Contoso Labs",
                    Summary = "A valid digital signature is present for 'Contoso Labs', but the signer is not on the trusted public-vendor list."
                }, () =>
                {
                    var profile = ProfileFactory.Empty("powershell.exe", 2_100_000_622);
                    profile.ImagePath = imagePath;
                    profile.InheritedCommandContexts.Add(new InheritedCommandContext
                    {
                        Timestamp = DateTime.Now,
                        ParentProcessId = 6201,
                        ParentProcessName = "launcher.exe",
                        CommandLine = "powershell.exe -windowstyle hidden -command whoami"
                    });

                    var report = BehaviorAnalyzer.Analyze(profile);

                    Assert.Equal(ThreatImpact.Inconclusive, report.FinalVerdict);
                    Assert.Equal(SignatureTrustState.ValidSignatureUntrustedPublisher, report.SignatureTrustState);
                    Assert.DoesNotContain(report.DecisionReasons,
                        reason => reason.Contains("trusted publisher identity", StringComparison.OrdinalIgnoreCase));
                });
            });
        }, loadData: true);
    }

    [Fact]
    public void EncodedBypassCommand_ReturnsSuspiciousWithHumanReadableChecks()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.Empty("powershell.exe", 2_000_000_603);
            profile.SpawnedCommandLines.Add(new SpawnedProcess
            {
                Pid = 2_000_000_604,
                Name = "powershell.exe",
                CommandLine = "powershell.exe -exec bypass -enc AAAA",
                StartTime = DateTime.Now
            });

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.Equal(ThreatImpact.Suspicious, report.FinalVerdict);
            Assert.Contains(report.FiredCheckNames,
                name => name == "Encoded or Obfuscated Command");
            Assert.Contains(report.FiredCheckNames,
                name => name == "Execution Policy or Profile Bypass");
        }, loadData: true);
    }

    [Fact]
    public void ElevatedValidButUntrustedSignatureWithSuspiciousCommand_StillFlagsUnexpectedElevation()
    {
        TestScope.WithFreshSession(() =>
        {
            var ctx = new ProcessContext
            {
                IsElevated = true,
                HasSignature = true,
                IsSigned = true,
                IsTrustedPublisher = false,
                SignatureTrustState = SignatureTrustState.ValidSignatureUntrustedPublisher,
                SignerName = "Contoso Labs",
                SignatureSummary = "A valid digital signature is present for 'Contoso Labs', but the signer is not on the trusted public-vendor list.",
                FilePath = @"C:\Users\User\AppData\Local\SomeApp\app.exe",
                ParentProcess = "explorer",
                IsSuspiciousPath = false,
                ParentIsSuspicious = false
            };

            var profile = ProfileFactory.Empty("powershell.exe", 2_100_000_631);
            profile.InheritedCommandContexts.Add(new InheritedCommandContext
            {
                Timestamp = DateTime.Now,
                ParentProcessId = 5000,
                ParentProcessName = "launcher.exe",
                CommandLine = "powershell.exe -exec bypass -enc AAAA"
            });

            bool flagged = BehaviorAnalyzer.ShouldFlagUnexpectedElevation(
                ctx,
                new List<SuspiciousEvent>(),
                profile);

            Assert.True(flagged);
        }, loadData: true);
    }

    [Fact]
    public void RecoveryTamperingCommand_WithExecutableSuffix_IsDetectedForContextOnlyChild()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.Empty("vssadmin.exe", 2_000_000_603);
            profile.SpawnedAt = DateTime.Now;
            profile.ParentProcessIdAtSpawn = 7001;
            profile.ParentProcessNameAtSpawn = "testapp.exe";
            profile.LaunchCommandLineAtSpawn = "vssadmin.exe delete shadows /all /quiet";
            profile.InheritedCommandContexts.Add(new InheritedCommandContext
            {
                Timestamp = DateTime.Now,
                ParentProcessId = 7001,
                ParentProcessName = "testapp.exe",
                CommandLine = "vssadmin.exe delete shadows /all /quiet"
            });

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.Equal(ThreatImpact.Suspicious, report.FinalVerdict);
            Assert.Contains(report.FiredCheckNames,
                name => name == "Recovery Tampering Command");
        }, loadData: true);
    }

    [Fact]
    public void ExecutableDropFromTemp_ReturnsMalicious()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.Empty("loader.exe", 2_000_000_605);
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
            Assert.Contains(report.FiredCheckNames,
                name => name == "Executable Binary Dropped");
        }, loadData: true);
    }

    [Fact]
    public void TrustedSignedExecutableDrop_RemainsMalicious()
    {
        TestScope.WithFreshSession(() =>
        {
            TemporaryFileScope.WithExecutableFile(imagePath =>
            {
                TemporaryFileScope.WithExecutableFile(dropPath =>
                {
                    SignatureTestScope.WithSignatureResult(new SignatureVerificationResult
                    {
                        HasSignature = true,
                        IsCryptographicallyValid = true,
                        IsTrustedPublisher = true,
                        TrustState = SignatureTrustState.TrustedPublisherVerified,
                        PublisherName = "Microsoft Corporation",
                        Summary = "Trusted digital signature verified for publisher 'Microsoft Corporation'."
                    }, () =>
                    {
                        var profile = ProfileFactory.Empty("loader.exe", 2_100_000_651);
                        profile.ImagePath = imagePath;

                        ProfileFactory.AddEvent(
                            profile,
                            "ContextSignal",
                            Path.GetFileName(dropPath),
                            dropPath,
                            "context_signal");
                        profile.ExeDropPaths.TryAdd(dropPath, 0);

                        var report = BehaviorAnalyzer.Analyze(profile);

                        Assert.Equal(ThreatImpact.Malicious, report.FinalVerdict);
                        Assert.Contains(report.FiredCheckNames,
                            name => name == "Executable Binary Dropped");
                    });
                });
            });
        }, loadData: true);
    }

    [Fact]
    public void LsassAccess_ReturnsMalicious()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.WithEvent(
                "LsassAccess",
                "lsass.exe",
                "lsass.exe",
                "lsass_access",
                "unknown.exe",
                2_000_000_606);

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.Equal(ThreatImpact.Malicious, report.FinalVerdict);
            Assert.True(report.ChainResult.HasHardIndicator);
            Assert.Contains(report.FiredCheckNames,
                name => name == "LSASS Memory Access");
        });
    }

    [Fact]
    public void KnownToolNameWithoutStrongBehavior_IsNotForcedMalicious()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.WithEvent(
                "ProcessSpawn",
                "cmd.exe",
                "cmd.exe",
                "process_lolbin",
                "lazagne.exe",
                2_000_000_607);

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.Equal(ThreatImpact.Safe, report.FinalVerdict);
            Assert.DoesNotContain(report.DecisionReasons,
                reason => reason.Contains("known offensive tool", StringComparison.OrdinalIgnoreCase));
        }, loadData: true);
    }

    [Fact]
    public void ContextOnlyChildProfile_UsesStoredLaunchContextInsteadOfReturningBlank()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.Empty("whoami.exe", 2_000_000_609);
            profile.SpawnedAt = DateTime.Now;
            profile.ParentProcessIdAtSpawn = 6001;
            profile.ParentProcessNameAtSpawn = "testapp.exe";
            profile.LaunchCommandLineAtSpawn = "whoami.exe /all";
            profile.InheritedCommandContexts.Add(new InheritedCommandContext
            {
                Timestamp = DateTime.Now,
                ParentProcessId = 6001,
                ParentProcessName = "testapp.exe",
                CommandLine = "whoami.exe /all"
            });

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.Equal(ThreatImpact.Safe, report.FinalVerdict);
            Assert.NotEmpty(report.SafeReasons);
            Assert.Contains(report.SafeReasons,
                reason => reason.Contains("spawn provenance", StringComparison.OrdinalIgnoreCase));
        });
    }

    [Fact]
    public void DecisionReasons_UseThreatImpactLabels()
    {
        TestScope.WithFreshSession(() =>
        {
            var profile = ProfileFactory.Empty("powershell.exe", 2_000_000_610);
            profile.InheritedCommandContexts.Add(new InheritedCommandContext
            {
                Timestamp = DateTime.Now,
                ParentProcessId = 6101,
                ParentProcessName = "launcher.exe",
                CommandLine = "powershell.exe -windowstyle hidden -command whoami"
            });

            var report = BehaviorAnalyzer.Analyze(profile);

            Assert.Contains(report.DecisionReasons,
                reason => reason.Contains("[INCONCLUSIVE]", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(report.DecisionReasons,
                reason => reason.Contains("[Warning]", StringComparison.OrdinalIgnoreCase) ||
                          reason.Contains("[Notice]", StringComparison.OrdinalIgnoreCase) ||
                          reason.Contains("[ALERT]", StringComparison.OrdinalIgnoreCase));
        }, loadData: true);
    }

    private static ProcessProfile BuildWriteAnomalyProfile(string name, int pid)
    {
        var profile = ProfileFactory.Empty(name, pid);
        ProfileFactory.AddEvent(profile, "FileWrite", "note.txt", @"C:\Temp\note.txt", "");

        for (int i = 0; i < 8; i++)
            profile.AnomalyHistory.Add(new[] { 1.0, 0.0, 0.0, 0.0 });

        profile.AnomalyHistory.Add(new[] { 25.0, 8.0, 0.0, 0.0 });
        return profile;
    }
}
