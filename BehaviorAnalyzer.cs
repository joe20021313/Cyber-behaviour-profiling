using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;

namespace Cyber_behaviour_profiling
{
    public enum ThreatImpact
    {
        Safe = 0,
        Inconclusive = 1,
        Suspicious = 2,
        Malicious = 3
    }

    public enum SemanticCheckId
    {
        SuspiciousExecutionPath,
        MissingProgramOnDisk,
        ProcessExitedBeforeAnalysis,
        SystemProcessNotInSystem32,
        SpawnedBySuspiciousParent,
        OfficeAppSpawnedShellOrTool,
        BrowserSpawnedByNonShellParent,
        DeepAncestryChain,
        EncodedOrObfuscatedCommand,
        ExecutionPolicyOrProfileBypass,
        HiddenOrMinimizedCommandExecution,
        DestructiveCleanupCommand,
        RecoveryTamperingCommand,
        PersistenceOrientedCommand,
        WmiProcessCreationCommand,
        ExcessiveHandleCount,
        DisproportionateMemoryUse,
        UnexpectedNetworkConnections,
        SeDebugPrivilegeSelfEnabled,
        SeDebugPrivilegeWithCredentialActivity,
        InheritedSeDebugPrivilege,
        UnexpectedElevation,
        HeadlessConsoleApp,
        ImmediateHighActivityOnSpawn,
        HighOverallEventRate,
        ModerateAutomatedRate,
        SingleRuleHighVelocity,
        BroadSystemScanning,
        ModerateSystemScanning,
        CredentialsStoreAccess,
        BrowserCredentialAccess,
        ThirdPartyCredentialStores,
        ModifyingPersistenceMechanisms,
        DefenseToolTampering,
        DpapiDecryptionActivity,
        HighCrossSystemAreaCoverage,
        AllActivityInTwoSecondBurst,
        MultiTacticActivityInFiveSecondWindow,
        MassiveAttemptCountForShortRuntime,
        ExecutableDroppedToStagingFolder,
        CredentialHarvestFileStaged,
        ExfiltrationChainCollectStageExfil,
        ExfiltrationChainCollectStageNoExfilYet,
        UnsignedWriteToUnrelatedProgramDataFolder,
        MultipleStagingLocationsUsed,
        ExecutableProgramDropped,
        ScriptFileDropped,
        MultipleExecutablesDropped,
        HighFileCreateDeleteChurn,
        ExcessiveFileDeletion,
        WriteDirectoryScatter,
        WideWriteDirectoryScatter,
        ProcessSelfDeletion,
        OwnProgramDeleted,
        ExecutableFileDeleted,
        ExecutableFileDeletedAfterExecution,
        LsassMemoryAccess,
        RemoteThreadInjection,
        ProcessTamperingDetected,
        ReconnaissanceToolSpawning,
        PotentialCredentialStaging
    }

    public class ChainConfirmationResult
    {
        public bool HasHardIndicator { get; set; } = false;
    }

    public class BehaviorReport
    {
        public ThreatImpact FinalVerdict { get; set; } = ThreatImpact.Safe;
        public List<string> DecisionReasons { get; set; } = new();
        public List<string> SafeReasons { get; set; } = new();
        public ChainConfirmationResult ChainResult { get; set; } = new();
        public int FiredChecks { get; set; } = 0;
        public int TotalChecks { get; set; } = 0;
        public List<string> FiredCheckNames { get; set; } = new();
        public AnomalyResult? Anomaly { get; set; }
        public bool HasSignature { get; set; }
        public bool IsSigned { get; set; }
        public string SignerName { get; set; } = "";
        public SignatureTrustState SignatureTrustState { get; set; } = SignatureTrustState.NoSignature;
        public string SignatureSummary { get; set; } = "";
        public InvestigationResult? DirectoryInvestigation { get; set; }
        public InvestigationResult? NetworkInvestigation { get; set; }
    }

    public class ProcessContext
    {
        public string FilePath { get; set; } = "UNKNOWN";
        public bool HasSignature { get; set; } = false;
        public bool IsSigned { get; set; } = false;
        public bool IsTrustedPublisher { get; set; } = false;
        public bool IsSuspiciousPath { get; set; } = false;
        public string SignerName { get; set; } = "";
        public SignatureTrustState SignatureTrustState { get; set; } = SignatureTrustState.NoSignature;
        public string SignatureSummary { get; set; } = "";
        public string ParentProcess { get; set; } = "UNKNOWN";
        public bool ParentIsSuspicious { get; set; } = false;
        public bool ParentIsTrustedPublisher { get; set; } = false;
        public string ParentFilePath { get; set; } = "UNKNOWN";
        public List<string> AncestorChain { get; set; } = new();
        public int HandleCount { get; set; } = 0;
        public long WorkingSetMB { get; set; } = 0;
        public int ThreadCount { get; set; } = 0;
        public bool HasDebugPriv { get; set; } = false;
        public bool HasNetworkConns { get; set; } = false;
        public int NetworkConnCount { get; set; } = 0;
        public bool IsElevated { get; set; } = false;
        public bool IsConsoleApp { get; set; } = false;
        public double UptimeSeconds { get; set; } = 0;
        public bool ProcessExited { get; set; } = false;
    }

    public class SemanticCheck
    {
        public SemanticCheckId Id { get; set; }
        public string Name { get; set; }
        public ThreatImpact Impact { get; set; }
        public string Reason { get; set; }
        public bool IsFired { get; set; }
        public bool IsHardIndicator { get; set; }
    }

    public static class BehaviorAnalyzer
    {
        private sealed class SuspiciousCommandEvidence
        {
            public string CommandLine { get; set; } = "";
            public string Pattern { get; set; } = "";
            public string Description { get; set; } = "";
            public string Source { get; set; } = "";
        }

        internal enum AnomalyConfidenceTier
        {
            Low = 0,
            Moderate = 1,
            High = 2,
            Extreme = 3
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInfoClass,
            IntPtr tokenInfo, int tokenInfoLength, out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        private const uint TOKEN_QUERY = 0x0008;

        public static BehaviorReport Analyze(ProcessProfile profile)
        {
            var report = new BehaviorReport();
            if (profile == null)
                return report;

            bool hasDirectEvents = profile.EventTimeline != null && profile.EventTimeline.Any();
            bool hasSuspiciousCommandContext = HasSuspiciousCommandContext(profile);
            bool hasRetainedAnalysisContext = HasRetainedAnalysisContext(profile, hasSuspiciousCommandContext);
            if (!hasDirectEvents && !hasRetainedAnalysisContext)
                return report;

            var events = hasDirectEvents ? profile.EventTimeline.ToList() : new List<SuspiciousEvent>();
            string name = profile.ProcessName?.ToLowerInvariant() ?? "";
            string nameNoExt = Path.GetFileNameWithoutExtension(name);

            ProcessContext ctx = GatherSystemContext(profile);
            bool isKnownBrowserProcess = IsKnownBrowserProcess(profile, ctx);
            bool browserLaunchedByOtherProgram = IsBrowserLaunchedByOtherProgram(profile, ctx, isKnownBrowserProcess);
               bool browserSafeMode = isKnownBrowserProcess && !browserLaunchedByOtherProgram;
            bool installerSafeMode = IsKnownInstallerProcess(nameNoExt, ctx);

            bool hasBehavioralRedFlag = HasBehavioralRedFlag(profile, ctx, browserSafeMode);

            bool claimsTrustedName = nameNoExt.Length >= 3 &&
                (MapToData._trustedSystem.Any(t =>
                    Path.GetFileNameWithoutExtension(t).Equals(nameNoExt, StringComparison.OrdinalIgnoreCase)) ||
                 MapToData._trustedUserApps.Any(t =>
                    Path.GetFileNameWithoutExtension(t).Equals(nameNoExt, StringComparison.OrdinalIgnoreCase)));

            if (claimsTrustedName && ctx.FilePath != "UNKNOWN" && !ctx.IsTrustedPublisher && ctx.IsSuspiciousPath)
            {
                report.FinalVerdict = ThreatImpact.Malicious;
                report.DecisionReasons.Add(
                    $"The program '{profile.ProcessName}' uses a trusted name but operates from a strange folder ({ctx.FilePath}) and has no valid signature.");
                return report;
            }

            var netInvestigation = RunNetworkInvestigation(events, profile);

            var checks = new List<SemanticCheck>();
            checks.AddRange(CheckProgramProvenance(ctx, profile));
            checks.AddRange(CheckSysmonEvents(events));
            checks.AddRange(CheckParent(ctx, profile, browserLaunchedByOtherProgram));
            checks.AddRange(CheckSuspiciousCommandSemantics(profile));
            checks.AddRange(CheckRuntimeAnomalies(ctx, events, profile, netInvestigation));
            checks.AddRange(CheckVelocityAndDensity(events, installerSafeMode));
            checks.AddRange(CheckSystemAreaFootprint(events, profile, isKnownBrowserProcess));
            checks.AddRange(CheckTemporalAnomalies(events, ctx));
            checks.AddRange(CheckContextFolderBehavior(ctx, events, profile, installerSafeMode));
            checks.AddRange(CheckFileChurnBehavior(ctx, profile, browserSafeMode, installerSafeMode));
            checks.AddRange(CheckDirectoryScatter(ctx, profile));
            checks.AddRange(CheckSelfDeletion(ctx, profile, browserSafeMode));

            var anomaly = AnomalyDetector.Evaluate(profile, ctx);

            report.Anomaly = anomaly;
            report.HasSignature = ctx.HasSignature;
            report.IsSigned = ctx.IsSigned;
            report.SignerName = ctx.SignerName;
            report.SignatureTrustState = ctx.SignatureTrustState;
            report.SignatureSummary = ctx.SignatureSummary;

            var chainResult = new ChainConfirmationResult
            {
                HasHardIndicator = events.Any(ev => IsHardIndicatorEvent(ev, !isKnownBrowserProcess))
            };
            if (!chainResult.HasHardIndicator)
                chainResult.HasHardIndicator = checks.Any(c => c.IsFired && c.IsHardIndicator);
            report.ChainResult = chainResult;

            bool grantsTrustedLeeway =
                ctx.IsTrustedPublisher &&
                !ctx.IsSuspiciousPath &&
                !chainResult.HasHardIndicator &&
                !hasBehavioralRedFlag;

            double trustMult = GetTrustMultiplier(name, nameNoExt, ctx);
            bool isLolBin = trustMult > 1.0;
            
            bool isLolBinFromNonShell = isLolBin && !IsShellOrSystemLauncher(profile, ctx);

            if (!hasBehavioralRedFlag && !isLolBinFromNonShell)
            {
                if (ctx.IsTrustedPublisher && !ctx.IsSuspiciousPath)
                {
                    trustMult *= 0.5;
                }
            }
            ThreatImpact highestImpact = ThreatImpact.Safe;
            int firedCount = 0;
            foreach (var check in checks.Where(c => c.IsFired))
            {
                if (!chainResult.HasHardIndicator && _softDrivenChecks.Contains(check.Id))
                    continue;

                if (check.Impact > highestImpact) highestImpact = check.Impact;
                firedCount++;
                report.FiredCheckNames.Add(check.Name);
                string impactLabel = ToImpactLabel(check.Impact);
                report.DecisionReasons.Add($"  [{impactLabel}] {check.Reason}");
            }

            if (anomaly.AnomalyDetected)
            {
                string metrics  = anomaly.SpikedMetrics.Count > 0
                    ? string.Join(", ", anomaly.SpikedMetrics)
                    : (!string.IsNullOrWhiteSpace(anomaly.ShortLivedBurstReason)
                        ? anomaly.ShortLivedBurstReason
                        : "file activity deviated from the session baseline");
                string burstTag = anomaly.IsBurstDetection ? " [burst-mode]" : "";
                string ShortLivedBurstTag = anomaly.ShortLivedBurstFired ? " [ShortLivedBurst]" : "";
                AnomalyConfidenceTier anomalyTier = GetAnomalyConfidenceTier(anomaly);
                ThreatImpact knnImpact = ComputeIndependentKnnImpact(anomaly, anomalyTier);

                if (!anomaly.BaselineUsed &&
                    knnImpact == ThreatImpact.Inconclusive &&
                    (firedCount > 0 || HasAnomalyCorroboration(events)))
                {
                    knnImpact = ThreatImpact.Suspicious;
                }

                if (knnImpact != ThreatImpact.Safe)
                {
                    string focusNote = knnImpact == ThreatImpact.Suspicious &&
                                       CountTopWriteDirectories(profile) == 1
                        ? " Activity was concentrated in one location."
                        : "";
                    string statsText = anomaly.Threshold > 0
                        ? $" KNN distance {anomaly.KnnDistance:F2} vs threshold {anomaly.Threshold:F2}."
                        : "";

                    string labelText;
                    string baselineTag;
                    string messageBody;

                    if (!anomaly.BaselineUsed)
                    {
                        labelText   = knnImpact == ThreatImpact.Suspicious
                            ? ToImpactLabel(ThreatImpact.Suspicious)
                            : "NOTICE";
                        baselineTag = " [no baseline — self-referential]";
                        messageBody = $"self-referential behavioural deviation — {metrics}";
                    }
                    else
                    {
                        labelText   = ToImpactLabel(knnImpact);
                        baselineTag = " [baseline]";
                        messageBody = $"baseline deviation — {metrics}";
                    }

                    report.DecisionReasons.Add(
                        $"  [{labelText}] Anomaly detector (KNN){burstTag}{ShortLivedBurstTag}{baselineTag}: {messageBody}.{statsText}{focusNote}");

                    if (knnImpact > highestImpact) highestImpact = knnImpact;
                    firedCount++;
                }
            }
            else
            {
                string metricsDisplay = "No activity recorded";
                int snapshotCount = 0;
                lock (profile.KnnStateLock)
                {
                    snapshotCount = profile.AnomalyHistory.Count;
                    if (profile.AnomalyHistory.Count > 0)
                    {
                        var snapshots = profile.AnomalyHistory.ToList();
                        double peakWrite  = snapshots.Max(s => s.Length > 0 ? s[0] : 0);
                        double peakDelete = snapshots.Max(s => s.Length > 1 ? s[1] : 0);
                        double peakPayload = snapshots.Max(s => s.Length > 2 ? s[2] : 0);
                        double peakSensitive = snapshots.Max(s => s.Length > 3 ? s[3] : 0);
                        double avgWrite   = snapshots.Average(s => s.Length > 0 ? s[0] : 0);

                        if (peakWrite > 0 || peakDelete > 0 || peakPayload > 0 || peakSensitive > 0)
                        {
                            if (peakWrite > 0 || peakDelete > 0)
                            {
                                metricsDisplay =
                                    $"Peak Writes: {peakWrite:F1}/s, Avg: {avgWrite:F1}/s, Peak Deletes: {peakDelete:F1}/s, Peak Payload Writes: {peakPayload:F1}/s, Peak Sensitive Access: {peakSensitive:F1}/s ({snapshots.Count} samples)";
                            }
                            else
                            {
                                metricsDisplay =
                                    $"No write/delete bursts in {snapshots.Count} samples; peak payload writes {peakPayload:F1}/s, peak sensitive access {peakSensitive:F1}/s";
                            }
                        }
                        else
                            metricsDisplay = $"No file writes in {snapshots.Count} samples (read-only activity)";
                    }
                }

                if (!anomaly.BaselineUsed && snapshotCount < AnomalyDetector.MinVectorsRequired)
                {
                    report.DecisionReasons.Add(
                        $"  [NOTICE] Anomaly detector (KNN) [no baseline]: Not enough data yet ({snapshotCount}/{AnomalyDetector.MinVectorsRequired} vectors).");
                }
                else
                {
                    string baselineTag = anomaly.BaselineUsed ? " [baseline used]" : " [no baseline — self-referential]";
                    report.DecisionReasons.Add($"  [SAFE] Anomaly detector (KNN){baselineTag}: Safe — {metricsDisplay}");
                }
            }

            if (firedCount >= 6)
            {
                if (ThreatImpact.Suspicious > highestImpact) highestImpact = ThreatImpact.Suspicious;
                report.DecisionReasons.Add($"  [{ToImpactLabel(ThreatImpact.Suspicious)}] Found {firedCount} different warning signs");
            }
            else if (firedCount >= 3)
            {
                if (ThreatImpact.Inconclusive > highestImpact) highestImpact = ThreatImpact.Inconclusive;
                report.DecisionReasons.Add($"  [{ToImpactLabel(ThreatImpact.Inconclusive)}] Found {firedCount} different warning signs");
            }

            var dirInvestigation = HasFileOrArtifactFootprint(profile, events)
                ? RunDirectoryInvestigation(profile)
                : null;
            if (dirInvestigation != null && dirInvestigation.Findings.Count > 0)
            {
                report.DirectoryInvestigation = dirInvestigation;
                ThreatImpact dirImpact = dirInvestigation.OverallSuspicion switch
                {
                    SuspicionLevel.High   => ThreatImpact.Malicious,
                    SuspicionLevel.Medium => ThreatImpact.Suspicious,
                    SuspicionLevel.Low    => ThreatImpact.Inconclusive,
                    _                     => ThreatImpact.Safe
                };
                if (dirImpact > highestImpact) highestImpact = dirImpact;
                firedCount += dirInvestigation.Findings.Count(f => f.Severity == FindingSeverity.Alert);
                foreach (var f in dirInvestigation.Findings)
                {
                    ThreatImpact findingImpact = ToThreatImpact(f.Severity);
                    report.DecisionReasons.Add($"  [{ToFindingLabel(f.Severity, findingImpact)}] {f.Description}");
                    foreach (var child in f.Children)
                        report.DecisionReasons.Add($"    ↳ [{ToFindingLabel(child.Severity, ToThreatImpact(child.Severity))}] {child.Description}");
                }

                if (dirInvestigation.OverallSuspicion >= SuspicionLevel.High && !chainResult.HasHardIndicator)
                    chainResult.HasHardIndicator = true;
            }

            if (netInvestigation != null && netInvestigation.Findings.Count > 0)
            {
                report.NetworkInvestigation = netInvestigation;
                ThreatImpact netImpact = netInvestigation.OverallSuspicion switch
                {
                    SuspicionLevel.High   => ThreatImpact.Malicious,
                    SuspicionLevel.Medium => ThreatImpact.Suspicious,
                    SuspicionLevel.Low    => ThreatImpact.Inconclusive,
                    _                     => ThreatImpact.Safe
                };
                if (netImpact > highestImpact) highestImpact = netImpact;
                firedCount += netInvestigation.Findings.Count(f => f.Severity == FindingSeverity.Alert);
                foreach (var f in netInvestigation.Findings)
                {
                    ThreatImpact findingImpact = ToThreatImpact(f.Severity);
                    report.DecisionReasons.Add($"  [{ToFindingLabel(f.Severity, findingImpact)}] {f.Description}");
                    foreach (var child in f.Children)
                        report.DecisionReasons.Add($"    ↳ [{ToFindingLabel(child.Severity, ToThreatImpact(child.Severity))}] {child.Description}");
                }

                if (netInvestigation.OverallSuspicion >= SuspicionLevel.High &&
                    !chainResult.HasHardIndicator &&
                    HasHardHighRiskEvents(events, treatCredentialFileAccessAsHard: !isKnownBrowserProcess))
                    chainResult.HasHardIndicator = true;
            }

            if (!anomaly.ShortLivedBurstFired && !chainResult.HasHardIndicator && !hasBehavioralRedFlag && trustMult <= 0.6)
            {
                if (highestImpact == ThreatImpact.Malicious)
                {
                    highestImpact = ThreatImpact.Suspicious;
                }
                else if (highestImpact == ThreatImpact.Suspicious)
                {
                    highestImpact = ThreatImpact.Inconclusive;
                }
            }

            if (chainResult.HasHardIndicator && highestImpact < ThreatImpact.Malicious)
            {
                highestImpact = ThreatImpact.Malicious;
                report.DecisionReasons.Add($"  [{ToImpactLabel(ThreatImpact.Malicious)}] Found multiple strong signs of malware.");
            }
            else if (!chainResult.HasHardIndicator && hasBehavioralRedFlag && highestImpact < ThreatImpact.Suspicious)
            {
                highestImpact = ThreatImpact.Suspicious;
                report.DecisionReasons.Add($"  [{ToImpactLabel(ThreatImpact.Suspicious)}] Noticed bad program behavior (like hiding files or deleting itself).");
            }

            if (grantsTrustedLeeway &&
                !browserLaunchedByOtherProgram &&
                !isLolBinFromNonShell)
            {
                highestImpact = ThreatImpact.Safe;
                report.DecisionReasons.Add($"  [{ToImpactLabel(ThreatImpact.Safe)}] Process verified as safe: trusted publisher identity '{ctx.SignerName}' passed signature and revocation validation.");
            }

            if (browserLaunchedByOtherProgram && highestImpact == ThreatImpact.Safe)
            {
                highestImpact = ThreatImpact.Inconclusive;
                report.DecisionReasons.Add($"  [{ToImpactLabel(ThreatImpact.Inconclusive)}] Browser-safe suppression disabled because this browser instance was launched by another program.");
            }

            report.FinalVerdict = highestImpact;
            report.FiredChecks = firedCount;
            report.TotalChecks = checks.Count;
            string grade = highestImpact switch
            {
                ThreatImpact.Malicious    => "MALICIOUS",
                ThreatImpact.Suspicious   => "SUSPICIOUS",
                ThreatImpact.Inconclusive => "INCONCLUSIVE",
                _                         => "SAFE"
            };
            string verdictDetail = grade switch
            {
                "MALICIOUS"    => "Found malware activity.",
                "SUSPICIOUS"   => "Saw suspicious activity.",
                "INCONCLUSIVE" => "Activity seems strange, but more proof is needed.",
                _              => "No dangerous or strange activity found."
            };
            report.DecisionReasons.Insert(0, verdictDetail);

            if (grade == "SAFE")
                report.SafeReasons = BuildSafeReasons(ctx, profile, events, checks,
                    report.Anomaly, firedCount, checks.Count);

            return report;
        }

        private static InvestigationResult? RunDirectoryInvestigation(ProcessProfile profile)
        {
            try
            {
                if (profile.DirectorySnapshotBefore == null) return null;

                var monitoredDirs = SystemDiscovery.GetMonitoredDirectories(MapToData.SensitiveDirs as IReadOnlyList<string>);
                var afterSnapshot = SystemDiscovery.TakeDirectorySnapshot(monitoredDirs);

                return SystemDiscovery.InvestigateDirectoryChanges(
                    profile.DirectorySnapshotBefore,
                    afterSnapshot,
                    MapToData.SensitiveDirs as IReadOnlyList<string>);
            }
            catch
            {
                return null;
            }
        }

        internal static ThreatImpact DetermineAnomalyImpact(
            AnomalyResult anomaly,
            IReadOnlyCollection<SuspiciousEvent> events,
            ProcessProfile profile)
        {
            if (!anomaly.AnomalyDetected)
                return ThreatImpact.Safe;

            AnomalyConfidenceTier confidenceTier = GetAnomalyConfidenceTier(anomaly);
            ThreatImpact impact = ComputeIndependentKnnImpact(anomaly, confidenceTier);

            if (!anomaly.BaselineUsed &&
                impact == ThreatImpact.Inconclusive &&
                HasAnomalyCorroboration(events))
            {
                impact = ThreatImpact.Suspicious;
            }

            if (ShouldEscalateAnomalyToMalicious(anomaly, events, profile))
                return ThreatImpact.Malicious;

            return impact;
        }

        internal static ThreatImpact ComputeIndependentKnnImpact(
            AnomalyResult anomaly,
            AnomalyConfidenceTier tier)
        {
            if (!anomaly.AnomalyDetected)
                return ThreatImpact.Safe;

            if (anomaly.ShortLivedBurstFired)
                return ThreatImpact.Suspicious;

            if (!anomaly.BaselineUsed)
            {
                return tier switch
                {
                    AnomalyConfidenceTier.Extreme  => ThreatImpact.Suspicious,
                    AnomalyConfidenceTier.High     => ThreatImpact.Suspicious,
                    AnomalyConfidenceTier.Moderate => ThreatImpact.Inconclusive,
                    _                              => ThreatImpact.Safe
                };
            }

            return tier == AnomalyConfidenceTier.Extreme
                ? ThreatImpact.Malicious
                : ThreatImpact.Suspicious;
        }

        internal static bool ShouldEscalateAnomalyToMalicious(
            AnomalyResult anomaly,
            IReadOnlyCollection<SuspiciousEvent> events,
            ProcessProfile profile)
        {
            bool treatCredentialFileAccessAsHard = !MapToData.IsKnownBrowserProcessName(profile.ProcessName);

            if (HasHardHighRiskEvents(events, treatCredentialFileAccessAsHard) &&
                (anomaly.BaselineUsed || anomaly.ShortLivedBurstFired))
                return true;

            return false;
        }

        private static AnomalyConfidenceTier GetAnomalyConfidenceTier(AnomalyResult anomaly)
        {
            if (!anomaly.AnomalyDetected)
                return AnomalyConfidenceTier.Low;

            double threshold = Math.Max(0.001, anomaly.Threshold);
            double marginOverThreshold = anomaly.KnnDistance > threshold
                ? (anomaly.KnnDistance - threshold) / threshold
                : 0.0;

            bool hasHighSignalMetric = anomaly.SpikedMetrics.Any(metric =>
                metric.Contains("Payload Write Rate", StringComparison.OrdinalIgnoreCase) ||
                metric.Contains("Sensitive Access Rate", StringComparison.OrdinalIgnoreCase));
            bool hasHighSignal = anomaly.HasHighSignalFeatureSpike || hasHighSignalMetric;

            bool extremeMargin = marginOverThreshold >= 3.0;
            if ((marginOverThreshold >= 2.0 && anomaly.IsSustained || extremeMargin) && hasHighSignal)
                return AnomalyConfidenceTier.Extreme;

            if (marginOverThreshold >= 1.2 || anomaly.Score >= 38)
                return AnomalyConfidenceTier.High;

            if (marginOverThreshold >= 0.55 || anomaly.Score >= 28 || anomaly.SpikedMetrics.Count >= 2)
                return AnomalyConfidenceTier.Moderate;

            return AnomalyConfidenceTier.Low;
        }

        private static bool HasAnomalyCorroboration(IReadOnlyCollection<SuspiciousEvent> events) =>
            events.Any(IsCredentialCollectionEvent) ||
            events.Any(e => e.EventType is "SensitiveDirAccess" or "ContextSignal" or "UncommonWrite");

        internal static int CountTopWriteDirectories(ProcessProfile profile)
        {
            if (profile.WriteDirectories == null || !profile.WriteDirectories.Any())
                return 0;

            return profile.WriteDirectories.Keys
                .Select(NormalizeToTopDir)
                .Where(d => d != null)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
        }

        internal static List<SemanticCheck> GetSeDebugPrivilegeChecksForTesting(
            ProcessContext ctx,
            IReadOnlyCollection<SuspiciousEvent> events,
            ProcessProfile profile) =>
            CheckSeDebugPrivilegeSignals(ctx, events, profile).ToList();

        private static InvestigationResult? RunNetworkInvestigation(
            List<SuspiciousEvent> events, ProcessProfile profile)
        {
            try
            {
                var networkEvents = events
                    .Where(e => e.EventType is "NetworkConnect" or "DNS_Query")
                    .ToList();

                if (networkEvents.Count == 0 || profile.DirectorySnapshotBefore == null)
                    return null;

                var monitoredDirs = SystemDiscovery.GetMonitoredDirectories(
                    MapToData.SensitiveDirs as IReadOnlyList<string>);
                var afterSnapshot = SystemDiscovery.TakeDirectorySnapshot(monitoredDirs);

                var combined = new InvestigationResult();
                var reportedFilePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var netEvent in networkEvents)
                {
                    var r = SystemDiscovery.InvestigateNetworkEvent(
                        netEvent, profile,
                        profile.DirectorySnapshotBefore, afterSnapshot);

                    foreach (var finding in r.Findings)
                    {
                        string correlationKey = !string.IsNullOrWhiteSpace(finding.CorrelationKey)
                            ? finding.CorrelationKey
                            : finding.ArtifactPath;

                        if (!string.IsNullOrWhiteSpace(correlationKey) &&
                            !reportedFilePaths.Add(correlationKey))
                            continue;

                        combined.Findings.Add(finding);
                    }

                    if (r.OverallSuspicion > combined.OverallSuspicion)
                        combined.OverallSuspicion = r.OverallSuspicion;
                }

                return combined.Findings.Count > 0 ? combined : null;
            }
            catch
            {
                return null;
            }
        }

        private static List<string> BuildSafeReasons(
            ProcessContext ctx, ProcessProfile profile, List<SuspiciousEvent> events,
            List<SemanticCheck>? checks = null, AnomalyResult? anomaly = null,
            int firedCount = 0, int totalChecks = 0)
        {
            var reasons = new List<string>();

            if (!string.IsNullOrWhiteSpace(ctx.SignatureSummary))
                reasons.Add(ctx.SignatureSummary);

            if (ctx.FilePath != "UNKNOWN" && !ctx.IsSuspiciousPath)
                reasons.Add($"Running from a standard install location ({ctx.FilePath}).");

            if (ctx.ParentIsSuspicious)
            {
                reasons.Add($"Parent process '{ctx.ParentProcess}' is flagged as suspicious — this does not confirm the child is dangerous, but warrants attention.");
            }
            else if (MapToData.GenericShells.Contains(ctx.ParentProcess))
            {
                reasons.Add($"Parent process is '{ctx.ParentProcess}' (the Windows shell). Most user-launched applications start from explorer.");
            }
            else if (ctx.ParentIsTrustedPublisher)
            {
                reasons.Add($"Launched by verified parent process '{ctx.ParentProcess}' ({ctx.ParentFilePath}).");
            }
            else
            {
                reasons.Add($"Parent process '{ctx.ParentProcess}' is not flagged as suspicious.");
            }

            int fileEvents = events.Count(e => e.EventType is "FileWrite" or "FileRead" or "FileOpen" or "FileDelete" or "FileRename");
            int netEvents = events.Count(e => e.EventType is "NetworkConnect" or "DNS_Query");
            int procEvents = events.Count(e => e.EventType is "ProcessSpawn" or "DiscoverySpawn" or "SuspiciousCommand");
            int regEvents = events.Count(e => e.EventType == "Registry");
            if (procEvents == 0 && profile.SpawnedCommandLines != null)
                procEvents = profile.SpawnedCommandLines.Count;

            var activityParts = new List<string>();
            if (fileEvents > 0) activityParts.Add($"{fileEvents} file operation(s)");
            if (netEvents > 0) activityParts.Add($"{netEvents} network connection(s)");
            if (procEvents > 0) activityParts.Add($"{procEvents} child process(es)");
            if (regEvents > 0) activityParts.Add($"{regEvents} registry access(es)");

            if (activityParts.Count > 0)
                reasons.Add($"Observed activity: {string.Join(", ", activityParts)} — none matched threat patterns in the rule database.");
            else if (HasRetainedLaunchContext(profile))
                reasons.Add("No direct ETW events were captured after launch, but spawn provenance was preserved for analysis.");
            else
                reasons.Add("No ETW events were captured for this process during the monitoring window.");

            if (checks != null && totalChecks > 0)
            {
                reasons.Add($"{totalChecks} behavioral checks evaluated, {firedCount} triggered.");
                if (firedCount == 0)
                    reasons.Add("No checks fired — file operations, network behaviour, process spawning, registry access, and persistence patterns all within normal bounds.");
            }

            var absent = new List<string>();
            if (profile.ExeDropPaths.Count == 0)
                absent.Add("no executable files dropped");
            if (!events.Any(e => e.EventType is "NetworkConnect" or "DNS_Query"))
                absent.Add("no outbound network activity");

            if (absent.Count > 0)
                reasons.Add($"Absent threat indicators: {string.Join(", ", absent)}.");

            if (anomaly != null)
            {
                if (!anomaly.AnomalyDetected)
                    reasons.Add("Anomaly detector (KNN): behaviour is within the normal statistical range.");
                else
                    reasons.Add($"Anomaly detector (KNN) flagged deviation — {string.Join(", ", anomaly.SpikedMetrics)}.");
            }

            reasons.Add("ETW event data is available for manual review if further investigation is needed.");

            return reasons;
        }

        private static bool IsHardIndicatorEvent(SuspiciousEvent ev, bool treatCredentialFileAccessAsHard)
        {
            if (ev.EventType is "DPAPI_Decrypt" or "AccessibilityProgramOverwrite"
                    or "LsassAccess" or "RemoteThreadInjection" or "ProcessTampering")
                return true;
            if (ev.EventType is "NetworkConnect" or "DNS_Query")
                return ev.Category is "network_c2" or "dns_c2";
            if (IsHardCredentialCollectionEvent(ev, treatCredentialFileAccessAsHard))
                return true;
            return false;
        }

        private static bool IsSensitiveVaultAccessEvent(SuspiciousEvent ev)
        {
            if (ev.EventType != "SensitiveDirAccess")
                return false;

            string raw = (ev.RawData ?? "").ToLowerInvariant();
            return raw.Contains("\\protect\\") || raw.Contains("\\credentials\\") || raw.Contains("\\vault\\");
        }

        private static bool IsHardCredentialCollectionEvent(SuspiciousEvent ev, bool treatCredentialFileAccessAsHard = true) =>
            ev.Category is "registry_credential_access" or "lsass_access" ||
            (treatCredentialFileAccessAsHard && ev.Category == "credential_file_access");

        private static bool IsCredentialCollectionEvent(SuspiciousEvent ev) =>
            IsHardCredentialCollectionEvent(ev) ||
            IsSensitiveVaultAccessEvent(ev);

        private static bool HasCredentialRuntimeActivity(IReadOnlyCollection<SuspiciousEvent> events) =>
            events.Any(e => e.EventType is "LsassAccess" or "DPAPI_Decrypt") ||
            events.Any(IsCredentialCollectionEvent);

        private static bool HasHighRiskEventEvidence(
            IReadOnlyCollection<SuspiciousEvent> events,
            bool treatCredentialFileAccessAsHard = true) =>
            events.Any(e => e.EventType is "DPAPI_Decrypt" or "LsassAccess" or "RemoteThreadInjection" or
                "ProcessTampering" or "AccessibilityProgramOverwrite") ||
            events.Any(e =>
                ((treatCredentialFileAccessAsHard && e.Category == "credential_file_access") ||
                 e.Category is "registry_credential_access" or "lsass_access" or
                    "registry_persistence" or "registry_defense_evasion" or "registry_privilege_escalation" or
                    "process_injection" or "process_tampering" or "network_c2" or "dns_c2")) ||
            events.Any(IsSensitiveVaultAccessEvent);

        private static bool HasHardHighRiskEvents(
            IReadOnlyCollection<SuspiciousEvent> events,
            bool treatCredentialFileAccessAsHard = true) =>
            events.Any(e => e.EventType is "DPAPI_Decrypt" or "LsassAccess" or "RemoteThreadInjection" or
                "ProcessTampering" or "AccessibilityProgramOverwrite") ||
            events.Any(e =>
                ((treatCredentialFileAccessAsHard && e.Category == "credential_file_access") ||
                 e.Category is "registry_credential_access" or "lsass_access" or
                    "registry_persistence" or "registry_defense_evasion" or "registry_privilege_escalation" or
                    "process_injection" or "process_tampering" or "network_c2" or "dns_c2"));

        private static bool IsKnownBrowserProcess(ProcessProfile profile, ProcessContext? ctx)
        {
            if (MapToData.IsKnownBrowserProcessName(profile.ProcessName))
                return true;

            if (ctx != null)
            {
                string fileName = Path.GetFileName(ctx.FilePath);
                if (MapToData.IsKnownBrowserProcessName(fileName))
                    return true;
            }

            return false;
        }

        private static readonly HashSet<string> _installerProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "msiexec", "setup", "install", "dotnet", "msbuild", "cl", "link", "cmake",
            "node", "npm", "cargo", "go", "7z", "7za", "winrar", "winzip", "unzip"
        };

        private static bool IsKnownInstallerProcess(string nameNoExt, ProcessContext? ctx)
        {
            if (!_installerProcessNames.Contains(nameNoExt))
                return false;

            
            
            return ctx?.IsTrustedPublisher == true;
        }

        private static string ResolveParentProcessName(ProcessProfile profile, ProcessContext ctx)
        {
            if (!string.IsNullOrWhiteSpace(profile.ParentProcessNameAtSpawn))
                return profile.ParentProcessNameAtSpawn;

            return ctx.ParentProcess ?? "UNKNOWN";
        }

        private static string NormalizeProcessNameNoExtension(string? processName)
        {
            if (string.IsNullOrWhiteSpace(processName))
                return "";

            string candidate = processName.Trim().Trim('"');
            int firstSpace = candidate.IndexOf(' ');
            if (firstSpace > 0)
                candidate = candidate[..firstSpace];

            candidate = Path.GetFileName(candidate);
            candidate = Path.GetFileNameWithoutExtension(candidate);
            return candidate.ToLowerInvariant();
        }

        private static bool IsGenericShellProcess(string? processName)
        {
            if (string.IsNullOrWhiteSpace(processName))
                return false;

            if (MapToData.GenericShells.Contains(processName))
                return true;

            string normalized = NormalizeProcessNameNoExtension(processName);
            return !string.IsNullOrWhiteSpace(normalized) &&
                   (MapToData.GenericShells.Contains(normalized) ||
                    MapToData.GenericShells.Contains(normalized + ".exe"));
        }

        private static bool IsTrustedSystemProcessName(string? processName)
        {
            string normalized = NormalizeProcessNameNoExtension(processName);
            if (string.IsNullOrWhiteSpace(normalized))
                return false;

            return MapToData._trustedSystem.Any(t =>
                Path.GetFileNameWithoutExtension(t)
                    .Equals(normalized, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsShellOrSystemLauncher(ProcessProfile profile, ProcessContext ctx)
        {
            string parentName = ResolveParentProcessName(profile, ctx);
            if (string.IsNullOrWhiteSpace(parentName) ||
                parentName.Equals("UNKNOWN", StringComparison.OrdinalIgnoreCase) ||
                ctx.ParentIsSuspicious)
            {
                return false;
            }

            if (IsGenericShellProcess(parentName))
                return true;

            if (!IsTrustedSystemProcessName(parentName))
                return false;

            if (string.IsNullOrWhiteSpace(ctx.ParentFilePath) ||
                ctx.ParentFilePath.Equals("UNKNOWN", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return ctx.ParentFilePath.StartsWith(@"c:\windows\", StringComparison.OrdinalIgnoreCase) ||
                   ctx.ParentIsTrustedPublisher;
        }

        private static bool IsBrowserLaunchedByOtherProgram(
            ProcessProfile profile,
            ProcessContext ctx,
            bool isKnownBrowserProcess)
        {
            if (!isKnownBrowserProcess)
                return false;

            string parentName = ResolveParentProcessName(profile, ctx);
            if (string.IsNullOrWhiteSpace(parentName) ||
                parentName.Equals("UNKNOWN", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return !IsShellOrSystemLauncher(profile, ctx);
        }

        private static bool HasSuspiciousExecutionEvidence(IReadOnlyCollection<SuspiciousEvent> events) =>
            events.Any(e => e.EventType is "SuspiciousCommand" or "DiscoverySpawn" or "DPAPI_Decrypt" or
                "LsassAccess" or "RemoteThreadInjection" or "ProcessTampering");

        private static bool HasPayloadLikeProfileEvidence(ProcessProfile profile) =>
            profile.ExeDropPaths.Any() ||
            profile.DeletedPaths.Any(path =>
                MapToData._executableExtensions.Contains(Path.GetExtension(path)) &&
                !MapToData.IsRuntimeArtifactPath(path));

        private static bool IsCommandInterpreter(string? processName)
        {
            if (string.IsNullOrWhiteSpace(processName))
                return false;

            string lower = processName.ToLowerInvariant();
            return lower.Contains("cmd") || lower.Contains("powershell") || lower.Contains("pwsh");
        }

        private static bool ContainsDeleteVerb(string commandLine) =>
            commandLine.Contains("del ") ||
            commandLine.Contains("del \"") ||
            commandLine.Contains("erase ") ||
            commandLine.Contains("remove-item") ||
            commandLine.Contains("rm ") ||
            commandLine.Contains("rmdir") ||
            commandLine.Contains("rd /s");

        private static bool ContainsDelayPrimitive(string commandLine) =>
            commandLine.Contains("ping") ||
            commandLine.Contains("timeout") ||
            commandLine.Contains("choice");

        private static bool ReferencesOwnProgram(string commandLine, string ownPath, string processNameNoExt) =>
            (ownPath != "unknown" && commandLine.Contains(ownPath)) ||
            (processNameNoExt.Length > 3 && commandLine.Contains(processNameNoExt));

        private static bool ReferencesStagingPath(string value) =>
            value.Contains(@"\appdata\") ||
            value.Contains(@"\temp\") ||
            value.Contains(@"\programdata\") ||
            value.Contains(@"\users\public\");

        private static bool HasSuspiciousCommandContext(ProcessProfile profile) =>
            CollectSuspiciousCommandEvidence(profile).Count > 0;

        private static bool HasRetainedAnalysisContext(
            ProcessProfile profile,
            bool hasSuspiciousCommandContext)
        {
            if (profile == null)
                return false;

            if (hasSuspiciousCommandContext || HasRetainedLaunchContext(profile))
                return true;

            if (profile.SpawnedCommandLines != null && profile.SpawnedCommandLines.Any())
                return true;

            if (profile.ExeDropPaths.Any() ||
                profile.RuntimeArtifactPaths.Any() ||
                profile.DeletedPaths.Any() ||
                profile.DeletedRuntimeArtifacts.Any())
            {
                return true;
            }

            if (profile.TotalFileWrites > 0 ||
                profile.TotalFileDeletes > 0 ||
                profile.TotalPayloadLikeWrites > 0 ||
                profile.TotalSensitiveAccessEvents > 0)
            {
                return true;
            }

            if (profile.AnomalyHistory != null && profile.AnomalyHistory.Count > 0)
                return true;

            return profile.SnapshotObservations != null && profile.SnapshotObservations.Any();
        }

        private static bool HasRetainedLaunchContext(ProcessProfile profile)
        {
            if (profile == null)
                return false;

            return profile.SpawnedAt != DateTime.MinValue ||
                   profile.ParentProcessIdAtSpawn > 0 ||
                   !string.IsNullOrWhiteSpace(profile.ParentProcessNameAtSpawn) ||
                   !string.IsNullOrWhiteSpace(profile.ParentImagePathAtSpawn) ||
                   !string.IsNullOrWhiteSpace(profile.LaunchCommandLineAtSpawn) ||
                   (profile.InheritedCommandContexts != null && profile.InheritedCommandContexts.Any());
        }

        private static bool HasFileOrArtifactFootprint(
            ProcessProfile profile,
            IReadOnlyCollection<SuspiciousEvent> events)
        {
            if (profile.TotalFileWrites > 0 ||
                profile.TotalFileDeletes > 0 ||
                profile.TotalPayloadLikeWrites > 0 ||
                profile.TotalSensitiveAccessEvents > 0)
            {
                return true;
            }

            if (profile.ExeDropPaths.Any() ||
                profile.RuntimeArtifactPaths.Any() ||
                profile.DeletedPaths.Any() ||
                profile.DeletedRuntimeArtifacts.Any())
            {
                return true;
            }

            return events.Any(e => e.EventType is "FileWrite" or "FileRead" or "FileOpen" or "FileDelete" or
                "FileRename" or "SensitiveDirAccess" or "UncommonWrite" or "AccessibilityProgramOverwrite" or
                "Executable Drop" or "ContextSignal");
        }

        private static List<SuspiciousCommandEvidence> CollectSuspiciousCommandEvidence(ProcessProfile profile)
        {
            var evidence = new List<SuspiciousCommandEvidence>();
            if (profile == null)
                return evidence;

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            void AddMatches(string? commandLine, string source)
            {
                if (string.IsNullOrWhiteSpace(commandLine))
                    return;

                foreach (var rule in MapToData.CommandRules)
                {
                    if (!MapToData.CommandLineMatchesRule(commandLine, rule.Pattern))
                        continue;

                    string fingerprint = $"{source}|{rule.Pattern}|{commandLine}";
                    if (!seen.Add(fingerprint))
                        continue;

                    evidence.Add(new SuspiciousCommandEvidence
                    {
                        CommandLine = commandLine,
                        Pattern = rule.Pattern,
                        Description = rule.Description ?? "",
                        Source = source
                    });
                }
            }

            if (profile.EventTimeline != null)
            {
                foreach (var ev in profile.EventTimeline.Where(e => e.EventType == "SuspiciousCommand"))
                    AddMatches(ev.RawData, "recorded suspicious command");
            }

            if (profile.SpawnedCommandLines != null)
            {
                foreach (var spawn in profile.SpawnedCommandLines)
                {
                    string childName = string.IsNullOrWhiteSpace(spawn.Name) ? "child process" : spawn.Name;
                    AddMatches(spawn.CommandLine, $"spawned '{childName}'");
                }
            }

            if (profile.InheritedCommandContexts != null)
            {
                foreach (var context in profile.InheritedCommandContexts)
                {
                    string parentName = string.IsNullOrWhiteSpace(context.ParentProcessName)
                        ? "parent process"
                        : context.ParentProcessName;
                    AddMatches(context.CommandLine, $"inherited launch from '{parentName}'");
                }
            }

            return evidence;
        }

        private static bool MatchesCommandDescription(SuspiciousCommandEvidence evidence, string phrase) =>
            evidence.Description.Contains(phrase, StringComparison.OrdinalIgnoreCase);

        private static string ToImpactLabel(ThreatImpact impact) => impact switch
        {
            ThreatImpact.Malicious => "MALICIOUS",
            ThreatImpact.Suspicious => "SUSPICIOUS",
            ThreatImpact.Inconclusive => "INCONCLUSIVE",
            _ => "SAFE"
        };

        private static string ToFindingLabel(FindingSeverity severity, ThreatImpact impact) =>
            severity == FindingSeverity.Info
                ? "NOTICE"
                : ToImpactLabel(impact);

        private static ThreatImpact ToThreatImpact(FindingSeverity severity) => severity switch
        {
            FindingSeverity.Alert => ThreatImpact.Malicious,
            FindingSeverity.Warning => ThreatImpact.Suspicious,
            _ => ThreatImpact.Inconclusive
        };

        private static string DescribeSuspiciousCommandEvidence(
            IReadOnlyCollection<SuspiciousCommandEvidence> evidence,
            string prefix)
        {
            if (evidence.Count == 0)
                return prefix;

            var sample = evidence.First();
            string preview = sample.CommandLine.Length > 120
                ? sample.CommandLine.Substring(0, 120) + "..."
                : sample.CommandLine;
            int commandCount = evidence
                .Select(e => e.CommandLine)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();

            return $"{prefix} across {commandCount} command line(s); sample via {sample.Source}: '{preview}'.";
        }

        private static readonly HashSet<SemanticCheckId> _softDrivenChecks = new()
        {
            SemanticCheckId.SuspiciousExecutionPath,
            SemanticCheckId.DeepAncestryChain,
            SemanticCheckId.AllActivityInTwoSecondBurst,
            SemanticCheckId.MultiTacticActivityInFiveSecondWindow,
            SemanticCheckId.MassiveAttemptCountForShortRuntime,
            SemanticCheckId.ExcessiveHandleCount,
            SemanticCheckId.DisproportionateMemoryUse,
            SemanticCheckId.HeadlessConsoleApp,
            SemanticCheckId.ImmediateHighActivityOnSpawn,
            SemanticCheckId.HighOverallEventRate,
            SemanticCheckId.ModerateAutomatedRate,
            SemanticCheckId.SingleRuleHighVelocity,
            SemanticCheckId.BroadSystemScanning,
            SemanticCheckId.ModerateSystemScanning,
            SemanticCheckId.ModifyingPersistenceMechanisms,
            SemanticCheckId.HighCrossSystemAreaCoverage,
            SemanticCheckId.ExecutableDroppedToStagingFolder,
            SemanticCheckId.UnsignedWriteToUnrelatedProgramDataFolder,
            SemanticCheckId.MultipleStagingLocationsUsed,
            SemanticCheckId.HighFileCreateDeleteChurn,
            SemanticCheckId.ExcessiveFileDeletion,
            SemanticCheckId.WriteDirectoryScatter,
            SemanticCheckId.WideWriteDirectoryScatter,
            SemanticCheckId.ProcessExitedBeforeAnalysis,
        };

        private static IEnumerable<SemanticCheck> CheckProgramProvenance(ProcessContext ctx, ProcessProfile profile)
        {
            yield return Check(SemanticCheckId.SuspiciousExecutionPath,
                ctx.IsSuspiciousPath,
                ThreatImpact.Suspicious, $"This process is running from '{ctx.FilePath}', which is a temporary or user-writable location. Legitimate software is rarely installed here.");

            bool isRootedPath = Path.IsPathRooted(ctx.FilePath);
            bool programMissing = ctx.FilePath == "UNKNOWN";

            bool programDeletedFromDisk = ctx.FilePath != "UNKNOWN" && ctx.ProcessExited && isRootedPath && !File.Exists(ctx.FilePath);

            string name = profile.ProcessName.ToLowerInvariant();
            string nameNoExt = Path.GetFileNameWithoutExtension(name);

            bool claimsKnownName = MapToData._processTrustMultipliers.ContainsKey(name) ||
                                   MapToData._processTrustMultipliers.ContainsKey(name + ".exe");

            bool claimsWindowsSystemName = MapToData._trustedSystem.Any(t =>
                Path.GetFileNameWithoutExtension(t).Equals(nameNoExt, StringComparison.OrdinalIgnoreCase));

            bool inSystemDir = ctx.FilePath.StartsWith(@"c:\windows\", StringComparison.OrdinalIgnoreCase);

            if (claimsKnownName)
                programDeletedFromDisk = false;

            yield return Check(SemanticCheckId.MissingProgramOnDisk,
                programDeletedFromDisk,
                ThreatImpact.Malicious, $"Program no longer on disk: {Path.GetFileName(ctx.FilePath)}");

            yield return Check(SemanticCheckId.ProcessExitedBeforeAnalysis,
                programMissing,
                ThreatImpact.Inconclusive, "Process exited before file path could be confirmed");

            yield return Check(SemanticCheckId.SystemProcessNotInSystem32,
                claimsWindowsSystemName && !inSystemDir && isRootedPath,
                ThreatImpact.Malicious, $"'{profile.ProcessName}' running from non-system location: {ctx.FilePath}");
        }

        private static IEnumerable<SemanticCheck> CheckParent(
            ProcessContext ctx,
            ProcessProfile profile,
            bool browserLaunchedByOtherProgram)
        {
            yield return Check(SemanticCheckId.SpawnedBySuspiciousParent,
                ctx.ParentIsSuspicious,
                ThreatImpact.Suspicious, $"Launched by '{ctx.ParentProcess}' from an untrusted location");

            string procName = profile.ProcessName.ToLower();
            yield return Check(SemanticCheckId.OfficeAppSpawnedShellOrTool,
                MapToData._officeApps.Contains(ctx.ParentProcess) &&
                (procName.Contains("cmd") || procName.Contains("powershell") ||
                 procName.Contains("wscript") || procName.Contains("cscript")),
                ThreatImpact.Malicious, $"Office app '{ctx.ParentProcess}' spawned scripting tool '{profile.ProcessName}'");

            yield return Check(SemanticCheckId.BrowserSpawnedByNonShellParent,
                browserLaunchedByOtherProgram,
                ThreatImpact.Suspicious,
                $"Browser process '{profile.ProcessName}' was launched by '{ResolveParentProcessName(profile, ctx)}'. Browser-specific safe mode is disabled in this launch context.");

            bool deepChain = ctx.AncestorChain.Count >= 4;

            yield return Check(SemanticCheckId.DeepAncestryChain,
                deepChain,
                ThreatImpact.Inconclusive, $"Deep process chain ({ctx.AncestorChain.Count} levels): {string.Join(" → ", ctx.AncestorChain)}");
        }

        private static IEnumerable<SemanticCheck> CheckSuspiciousCommandSemantics(ProcessProfile profile)
        {
            var evidence = CollectSuspiciousCommandEvidence(profile);
            if (evidence.Count == 0)
                yield break;

            var encoded = evidence
                .Where(e => MatchesCommandDescription(e, "encoded/hidden command"))
                .ToList();
            yield return Check(SemanticCheckId.EncodedOrObfuscatedCommand,
                encoded.Count > 0,
                ThreatImpact.Suspicious,
                DescribeSuspiciousCommandEvidence(encoded, "Encoded or obfuscated command-line in content observed"));

            var bypass = evidence
                .Where(e => MatchesCommandDescription(e, "security policy bypass") ||
                            MatchesCommandDescription(e, "profile bypass execution"))
                .ToList();
            yield return Check(SemanticCheckId.ExecutionPolicyOrProfileBypass,
                bypass.Count > 0,
                ThreatImpact.Suspicious,
                DescribeSuspiciousCommandEvidence(bypass, "Execution-policy or profile-bypass flags observed"));

            var hidden = evidence
                .Where(e => MatchesCommandDescription(e, "hidden window execution") ||
                            MatchesCommandDescription(e, "hidden/minimised process launch"))
                .ToList();
            yield return Check(SemanticCheckId.HiddenOrMinimizedCommandExecution,
                hidden.Count > 0,
                ThreatImpact.Inconclusive,
                DescribeSuspiciousCommandEvidence(hidden, "Hidden or minimised command execution observed"));

            var cleanup = evidence
                .Where(e => MatchesCommandDescription(e, "file deletion command") ||
                            MatchesCommandDescription(e, "forced file deletion") ||
                            MatchesCommandDescription(e, "chained file deletion") ||
                            MatchesCommandDescription(e, "directory deletion") ||
                            MatchesCommandDescription(e, "recursive directory deletion") ||
                            MatchesCommandDescription(e, "delay-and-execute pattern"))
                .ToList();
            yield return Check(SemanticCheckId.DestructiveCleanupCommand,
                cleanup.Count > 0,
                ThreatImpact.Suspicious,
                DescribeSuspiciousCommandEvidence(cleanup, "Cleanup or delete-after-execute command observed"));

            var recovery = evidence
                .Where(e => MatchesCommandDescription(e, "shadow copy deletion") ||
                            MatchesCommandDescription(e, "backup catalog deletion") ||
                            MatchesCommandDescription(e, "boot recovery modification"))
                .ToList();
            yield return Check(SemanticCheckId.RecoveryTamperingCommand,
                recovery.Count > 0,
                ThreatImpact.Suspicious,
                DescribeSuspiciousCommandEvidence(recovery, "Backup, recovery, or shadow-copy tampering command observed"));

            var persistence = evidence
                .Where(e => MatchesCommandDescription(e, "scheduled task") ||
                            MatchesCommandDescription(e, "remote task scheduling") ||
                            MatchesCommandDescription(e, "accessibility hijack"))
                .ToList();
            yield return Check(SemanticCheckId.PersistenceOrientedCommand,
                persistence.Count > 0,
                ThreatImpact.Suspicious,
                DescribeSuspiciousCommandEvidence(persistence, "Persistence-oriented command invocation observed"));

            var wmiLaunch = evidence
                .Where(e => e.Pattern.Contains("wmic process call create", StringComparison.OrdinalIgnoreCase))
                .ToList();
            yield return Check(SemanticCheckId.WmiProcessCreationCommand,
                wmiLaunch.Count > 0,
                ThreatImpact.Suspicious,
                DescribeSuspiciousCommandEvidence(wmiLaunch, "WMI-based process creation command observed"));
        }

        private static IEnumerable<SemanticCheck> CheckRuntimeAnomalies(
            ProcessContext ctx, List<SuspiciousEvent> events, ProcessProfile profile,
            InvestigationResult? netInvestigation)
        {
            yield return Check(SemanticCheckId.ExcessiveHandleCount,
                ctx.HandleCount > 500,
                ThreatImpact.Inconclusive, $"{ctx.HandleCount} open handles (above normal)");

            yield return Check(SemanticCheckId.DisproportionateMemoryUse,
                ctx.WorkingSetMB > 200 && events.Count < 5,
                ThreatImpact.Inconclusive, $"High memory use ({ctx.WorkingSetMB}MB) with minimal observable activity");

            yield return Check(SemanticCheckId.UnexpectedNetworkConnections,
                ShouldFlagUnexpectedNetworkConnections(ctx, events, profile, netInvestigation),
                ThreatImpact.Suspicious,
                $"{ctx.NetworkConnCount} outbound connection(s) alongside other suspicious activity");

            foreach (var check in CheckSeDebugPrivilegeSignals(ctx, events, profile))
                yield return check;

            yield return Check(SemanticCheckId.UnexpectedElevation,
                ShouldFlagUnexpectedElevation(ctx, events, profile),
                ThreatImpact.Inconclusive,
                "Running with administrator privileges alongside other suspicious activity");

            yield return Check(SemanticCheckId.HeadlessConsoleApp,
                ctx.IsConsoleApp && ctx.ThreadCount <= 4,
                ThreatImpact.Inconclusive, "Background process with no visible window");

            bool immediatelyActive = ctx.UptimeSeconds > 0 && ctx.UptimeSeconds < 2.0 && events.Count > 10;
            yield return Check(SemanticCheckId.ImmediateHighActivityOnSpawn,
                immediatelyActive,
                ThreatImpact.Inconclusive, $"{events.Count} events in {ctx.UptimeSeconds:F1}s of startup");
        }

        private static IEnumerable<SemanticCheck> CheckSeDebugPrivilegeSignals(
            ProcessContext ctx,
            IReadOnlyCollection<SuspiciousEvent> events,
            ProcessProfile profile)
        {
            bool hasCredentialActivity = HasCredentialRuntimeActivity(events);
            bool hasInjectionOrTamperingActivity = events.Any(e =>
                e.EventType is "RemoteThreadInjection" or "ProcessTampering" ||
                e.Category is "process_injection" or "process_tampering");

            bool hasSuspiciousCompanionActivity =
                HasSuspiciousCommandContext(profile) ||
                profile.ExeDropPaths.Any() ||
                events.Any(e => e.Category is "registry_persistence" or "registry_defense_evasion" or "registry_privilege_escalation");

            bool debugPrivActivelyUsed = ctx.HasDebugPriv &&
                (hasCredentialActivity || hasInjectionOrTamperingActivity);
            bool debugPrivSetWithSuspicion = ctx.HasDebugPriv &&
                !debugPrivActivelyUsed &&
                hasSuspiciousCompanionActivity;
            bool debugPrivSetOnly = ctx.HasDebugPriv &&
                !debugPrivActivelyUsed &&
                !debugPrivSetWithSuspicion;

            yield return Check(SemanticCheckId.SeDebugPrivilegeSelfEnabled,
                debugPrivActivelyUsed,
                ThreatImpact.Malicious,
                "SeDebugPrivilege was enabled and then exercised during credential access, injection, or process tampering.",
                isHardIndicator: true);

            yield return Check(SemanticCheckId.SeDebugPrivilegeWithCredentialActivity,
                debugPrivSetWithSuspicion,
                ThreatImpact.Suspicious,
                "SeDebugPrivilege is enabled alongside suspicious command, staging, or persistence activity.");

            yield return Check(SemanticCheckId.InheritedSeDebugPrivilege,
                debugPrivSetOnly,
                ThreatImpact.Inconclusive,
                "SeDebugPrivilege is enabled, but no misuse was observed.");
        }

        internal static bool ShouldFlagUnexpectedElevation(
            ProcessContext ctx,
            IReadOnlyCollection<SuspiciousEvent> events,
            ProcessProfile profile)
        {
            if (!ctx.IsElevated)
                return false;

            string lowerNameNoExt = Path.GetFileNameWithoutExtension(
                profile.ProcessName?.ToLowerInvariant() ?? "");
            bool isKnownSystemProgram = MapToData._trustedSystem.Any(t =>
                Path.GetFileNameWithoutExtension(t) == lowerNameNoExt);
            if (isKnownSystemProgram)
                return false;

            bool treatCredentialFileAccessAsHard = !MapToData.IsKnownBrowserProcessName(profile.ProcessName);
            bool hasHardOrCredentialSignals = HasHighRiskEventEvidence(events, treatCredentialFileAccessAsHard);

            bool hasSuspiciousExecution = HasSuspiciousExecutionEvidence(events) ||
                HasSuspiciousCommandContext(profile) ||
                HasBehavioralRedFlag(profile, ctx, browserSafeMode: false);

            return ctx.IsSuspiciousPath ||
                   ctx.ParentIsSuspicious ||
                   hasHardOrCredentialSignals ||
                   hasSuspiciousExecution;
        }

        internal static bool ShouldFlagUnexpectedNetworkConnections(
            ProcessContext ctx,
            IReadOnlyCollection<SuspiciousEvent> events,
            ProcessProfile profile,
            InvestigationResult? netInvestigation = null)
        {
            if (!ctx.HasNetworkConns)
                return false;

            bool hasGenericOutbound = events.Any(e =>
                e.EventType is "NetworkConnect" or "DNS_Query" &&
                e.Category is not "network_c2" and not "dns_c2");
            if (!hasGenericOutbound)
                return false;

            bool treatCredentialFileAccessAsHard = !MapToData.IsKnownBrowserProcessName(profile.ProcessName);
            bool hasHardOrCredentialSignals = HasHighRiskEventEvidence(events, treatCredentialFileAccessAsHard);

            bool hasSuspiciousExecution = HasSuspiciousExecutionEvidence(events) ||
                HasSuspiciousCommandContext(profile) ||
                profile.ExeDropPaths.Any();

            bool hasSuspiciousContext = ctx.IsSuspiciousPath ||
                ctx.ParentIsSuspicious;

            bool networkInvestigationRaisedRisk =
                (netInvestigation?.OverallSuspicion ?? SuspicionLevel.None) >= SuspicionLevel.Low;

            return hasHardOrCredentialSignals ||
                   hasSuspiciousExecution ||
                   hasSuspiciousContext ||
                   networkInvestigationRaisedRisk;
        }

        private static IEnumerable<SemanticCheck> CheckVelocityAndDensity(List<SuspiciousEvent> events, bool installerSafeMode = false)
        {
            if (!ObservedTimelineWindow.TryCompute(events, out var sessionStart, out _, out var sessionSecs))
                yield break;

            sessionSecs = Math.Max(sessionSecs, 1.0);
            int totalAttempts = events.Sum(e => e.AttemptCount);
            double overallRate = totalAttempts / sessionSecs;

            double highRateThreshold = installerSafeMode ? 200 : 50;
            yield return Check(SemanticCheckId.HighOverallEventRate,
                overallRate > highRateThreshold,
                ThreatImpact.Inconclusive, $"{totalAttempts:N0} events in {sessionSecs:F1}s ({overallRate:F0}/sec)");

            yield return Check(SemanticCheckId.ModerateAutomatedRate,
                overallRate > 10 && overallRate <= highRateThreshold,
                ThreatImpact.Inconclusive, $"Elevated activity rate: {overallRate:F0} events/sec");

            foreach (var ev in events)
            {
                double dur = Math.Max((ev.LastSeen - ev.Timestamp).TotalSeconds, 1.0);
                double rate = ev.AttemptCount / dur;
                if (rate > 15 && ev.AttemptCount >= 30)
                {
                    yield return Check(SemanticCheckId.SingleRuleHighVelocity,
                        true,
                        ThreatImpact.Suspicious, $"Single pattern repeated {ev.AttemptCount}x in {dur:F1}s");
                    yield break;
                }
            }

            int distinctIndicators = events.Select(e => e.MatchedIndicator).Distinct().Count();

            if (distinctIndicators >= 8)
            {
                yield return Check(SemanticCheckId.BroadSystemScanning,
                    true,
                    ThreatImpact.Suspicious, $"Accessed {distinctIndicators} distinct sensitive system areas");
            }
            else if (distinctIndicators >= 4)
            {
                yield return Check(SemanticCheckId.ModerateSystemScanning,
                    true,
                    ThreatImpact.Inconclusive, $"Accessed {distinctIndicators} distinct sensitive system areas");
            }

            var discoveryTools = events
                .Where(e => e.EventType == "DiscoverySpawn")
                .Select(e => e.MatchedIndicator)
                .Where(m => !string.IsNullOrEmpty(m))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            yield return Check(SemanticCheckId.ReconnaissanceToolSpawning,
                discoveryTools.Count >= 4,
                ThreatImpact.Suspicious,
                $"{discoveryTools.Count} reconnaissance tools executed: {string.Join(", ", discoveryTools.Take(8))}");
        }

        private static IEnumerable<SemanticCheck> CheckSystemAreaFootprint(
            List<SuspiciousEvent> events,
            ProcessProfile profile,
            bool isKnownBrowserProcess)
        {
            var areas = new HashSet<string>();

            foreach (var ev in events)
            {
                string raw = (ev.RawData ?? "").ToLower();
                string ind = (ev.MatchedIndicator ?? "").ToLower();

                bool isBrowserPath = MapToData._browserCredentialDirs.Any(d => raw.Contains(d));
                if (raw.Contains("\\credentials\\") || raw.Contains("\\protect\\") ||
                    raw.Contains("\\vault\\") || ind.Contains("credential") ||
                    (ev.Category == "credential_file_access" && !isBrowserPath) ||
                    raw.Contains("\\system32\\config\\sam") ||
                    raw.Contains("\\system32\\config\\security") ||
                    raw.Contains("\\ntds\\ntds.dit") ||
                    ind == "sam" || ind == "security" || ind == "ntds.dit")
                    areas.Add("WindowsCredentialStore");

                if (MapToData._browserCredentialDirs.Any(d => raw.Contains(d)))
                    areas.Add("BrowserCredentials");

                if (ev.EventType == "Registry" && ev.Category == "registry_credential_access")
                    areas.Add("ThirdPartyCredentials");

                if (ev.EventType == "Registry" && ev.Category == "registry_persistence")
                    areas.Add("PersistenceMechanisms");

                if (ev.EventType == "Registry" && ev.Category == "registry_defense_evasion")
                    areas.Add("DefenseTools");

                if (ev.EventType == "NetworkConnect" || ev.EventType == "DNS_Query")
                    areas.Add("NetworkCommunication");

                if (ev.EventType is "ProcessSpawn"
                    or "SuspiciousCommand" or "DiscoverySpawn")
                    areas.Add("ProcessExecution");

                if (ev.EventType == "DPAPI_Decrypt" ||
                    raw.Contains("\\microsoft\\protect\\"))
                    areas.Add("DPAPIDecryption");
            }

            bool hasNetwork = events.Any(e => e.EventType == "NetworkConnect" || e.EventType == "DNS_Query");
            bool contextIsExec = events
                .Where(e => e.EventType == "ContextSignal")
                .Any(e => MapToData._executableExtensions.Contains(
                    Path.GetExtension(e.RawData ?? "").ToLowerInvariant()));
            if (events.Any(e => e.EventType == "ContextSignal") && (hasNetwork || contextIsExec))
                areas.Add("UnusualWriteLocations");

            yield return Check(SemanticCheckId.CredentialsStoreAccess,
                areas.Contains("WindowsCredentialStore"),
                ThreatImpact.Malicious, "Accessed Windows credential vault");

            bool browserCredAccess = areas.Contains("BrowserCredentials");
            bool isOwnBrowser = isKnownBrowserProcess;
            yield return Check(SemanticCheckId.BrowserCredentialAccess,
                browserCredAccess && !isOwnBrowser,
                ThreatImpact.Malicious,
                $"Non-browser process accessed browser credential storage",
                isHardIndicator: true);

            yield return Check(SemanticCheckId.ThirdPartyCredentialStores,
                areas.Contains("ThirdPartyCredentials"),
                ThreatImpact.Malicious, "Accessed third-party credential registry keys (VNC/PuTTY/SSH)");

            yield return Check(SemanticCheckId.ModifyingPersistenceMechanisms,
                areas.Contains("PersistenceMechanisms"),
                ThreatImpact.Suspicious, "Touched registry paths used for persistent execution.");

            yield return Check(SemanticCheckId.DefenseToolTampering,
                areas.Contains("DefenseTools"),
                ThreatImpact.Malicious, "Accessed security control registry keys (AMSI/IFEO)");

            yield return Check(SemanticCheckId.DpapiDecryptionActivity,
                areas.Contains("DPAPIDecryption"),
                ThreatImpact.Malicious, "DPAPI decryption invoked (used to extract stored credentials)");

            int areaCount = areas.Count;

            yield return Check(SemanticCheckId.HighCrossSystemAreaCoverage,
                areaCount >= 4,
                ThreatImpact.Suspicious,
                $"Touched {areaCount} sensitive system areas: {string.Join(", ", areas)}");
        }

        private static IEnumerable<SemanticCheck> CheckTemporalAnomalies(
            List<SuspiciousEvent> events, ProcessContext ctx)
        {
            if (events.Count < 2) yield break;
            if (!ObservedTimelineWindow.TryCompute(events, out var first, out _, out var totalSpan))
                yield break;

            totalSpan = Math.Max(totalSpan, 1.0);
            var ordered = events.OrderBy(e => e.Timestamp).ToList();

            yield return Check(SemanticCheckId.AllActivityInTwoSecondBurst,
                totalSpan < MapToData.BurstSeconds && events.Count > 3,
                ThreatImpact.Suspicious, $"All {events.Count} events in {totalSpan:F2}s burst");

            var recentWindow = ordered.Where(e => (e.Timestamp - first).TotalSeconds <= MapToData.DiversitySeconds).ToList();
            var tacticDiversity = recentWindow
                .Where(e => !string.IsNullOrEmpty(e.Category))
                .Select(e => e.Category)
                .Distinct()
                .Count();

            yield return Check(SemanticCheckId.MultiTacticActivityInFiveSecondWindow,
                tacticDiversity >= MapToData.DiversityMinTactics,
                ThreatImpact.Suspicious, $"{tacticDiversity} different suspicious activity categories within {MapToData.DiversitySeconds:F0} seconds");

            long totalAttempts = events.Sum(e => (long)e.AttemptCount);
            yield return Check(SemanticCheckId.MassiveAttemptCountForShortRuntime,
                ctx.UptimeSeconds < MapToData.MassiveCountWindowSeconds && totalAttempts > MapToData.MassiveCountThreshold,
                ThreatImpact.Suspicious, $"{totalAttempts:N0} events in {ctx.UptimeSeconds:F0}s");
        }

        private static IEnumerable<SemanticCheck> CheckContextFolderBehavior(
            ProcessContext ctx, List<SuspiciousEvent> events, ProcessProfile profile, bool installerSafeMode = false)
        {
            var contextEvents = events.Where(e => e.EventType == "ContextSignal").ToList();
            if (!contextEvents.Any()) yield break;

            var relevantContextEvents = contextEvents
                .Where(e => !MapToData.IsRuntimeArtifactPath(e.RawData))
                .ToList();

            string nameNoExt = Path.GetFileNameWithoutExtension(
                profile.ProcessName?.ToLowerInvariant() ?? "");
            var execWrites = new List<SuspiciousEvent>();
            foreach (var e in relevantContextEvents)
            {
                string file = Path.GetFileName(e.RawData ?? "").ToLowerInvariant();
                bool isExecutable = MapToData._executableExtensions.Contains(Path.GetExtension(file));
                bool isSafe = MapToData._safeDropPrefixes.Any(pfx => file.StartsWith(pfx));
                if (isExecutable && !isSafe)
                    execWrites.Add(e);
            }

            //yield return Check(SemanticCheckId.ExecutableDroppedToStagingFolder,
            //    execWrites.Any(),
            //    ThreatImpact.Inconclusive,
            //    $"{execWrites.Count} executable or script file(s) were written to a temporary or user-accessible location: " +
            //    string.Join(", ", execWrites.Take(3).Select(e => Path.GetFileName(e.RawData ?? "?"))));

            var highConfWrites = relevantContextEvents
                .Where(e => {
                    string fn = Path.GetFileName(e.RawData ?? "").ToLowerInvariant();
                    return MapToData.HarvestHighConfidence.Any(h => fn.Equals(h) || fn.Contains(h));
                }).ToList();

            var suspConfWrites = relevantContextEvents
                .Where(e => {
                    string fn = Path.GetFileNameWithoutExtension(e.RawData ?? "").ToLowerInvariant();
                    return MapToData.HarvestSuspiciousKeywords.Any(k => fn.Contains(k)) && !highConfWrites.Contains(e);
                }).ToList();

            if (highConfWrites.Any())
            {
                yield return Check(SemanticCheckId.CredentialHarvestFileStaged,
                    true,
                    ThreatImpact.Malicious,
                    $"Hard match on high-confidence credential harvest file(s): {string.Join(", ", highConfWrites.Take(3).Select(e => Path.GetFileName(e.RawData ?? "?")))}");
            }

            if (suspConfWrites.Any())
            {
                yield return Check(SemanticCheckId.PotentialCredentialStaging,
                    true,
                    ThreatImpact.Suspicious,
                    $"Suspiciously named file(s) in staging folder: {string.Join(", ", suspConfWrites.Take(3).Select(e => Path.GetFileName(e.RawData ?? "?")))}");
            }

            DateTime earliestCredAccess = DateTime.MaxValue;
            int credEventsCount = 0;

            foreach (var e in events)
            {
                if (!IsCredentialCollectionEvent(e))
                    continue;

                credEventsCount++;
                if (e.Timestamp < earliestCredAccess)
                    earliestCredAccess = e.Timestamp;
            }

            DateTime earliestStaging = DateTime.MaxValue;
            int stagingAfterCredsCount = 0;

            if (credEventsCount > 0)
            {
                foreach (var e in relevantContextEvents)
                {
                    if (e.Timestamp >= earliestCredAccess)
                    {
                        stagingAfterCredsCount++;
                        if (e.Timestamp < earliestStaging)
                            earliestStaging = e.Timestamp;
                    }
                }
            }

            int networkAfterStagingCount = 0;

            if (stagingAfterCredsCount > 0)
            {
                foreach (var e in events)
                {
                    bool isSuspiciousNetwork = e.Category is "network_c2" or "dns_c2";
                    if (isSuspiciousNetwork && e.Timestamp >= earliestStaging)
                        networkAfterStagingCount++;
                }
            }

            bool fullChain = credEventsCount > 0 && stagingAfterCredsCount > 0 && networkAfterStagingCount > 0;
            bool partialChain = credEventsCount > 0 && stagingAfterCredsCount > 0 && networkAfterStagingCount == 0;

            string timeString = earliestCredAccess == DateTime.MaxValue ? "N/A" : earliestCredAccess.ToString("HH:mm:ss");

            yield return Check(SemanticCheckId.ExfiltrationChainCollectStageExfil,
                fullChain,
                ThreatImpact.Malicious,
                $"Full exfil chain: credential access ({credEventsCount}) → staging ({stagingAfterCredsCount} file(s)) → outbound ({networkAfterStagingCount} connection(s))",
                isHardIndicator: true);

            yield return Check(SemanticCheckId.ExfiltrationChainCollectStageNoExfilYet,
                partialChain,
                ThreatImpact.Suspicious,
                $"Credential access ({credEventsCount}) followed by staging ({stagingAfterCredsCount} file(s)) — no outbound transfer yet");

            var programDataWrites = relevantContextEvents
                .Where(e => (e.RawData ?? "").ToLowerInvariant().Contains(@"c:\programdata\"))
                .ToList();

            bool writesToUnrelatedProgramData = programDataWrites.Any(e =>
            {
                string path = (e.RawData ?? "").ToLowerInvariant();
                return !path.Contains(nameNoExt)
                    && !path.Contains("microsoft")
                    && !path.Contains("windows");
            });

            yield return Check(SemanticCheckId.UnsignedWriteToUnrelatedProgramDataFolder,
                writesToUnrelatedProgramData,
                ThreatImpact.Suspicious,
                $"Wrote to unrelated ProgramData folder");

            var touchedContextFolders = relevantContextEvents
                .Select(e => MapToData.GetContextSignalBucket(e.RawData))
                .Where(cp => !string.IsNullOrEmpty(cp))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Cast<string>()
                .ToList();

            int stagingThreshold = installerSafeMode ? 4 : 2;
            yield return Check(SemanticCheckId.MultipleStagingLocationsUsed,
                touchedContextFolders.Count >= stagingThreshold,
                ThreatImpact.Suspicious,
                $"Files written to {touchedContextFolders.Count} separate staging locations: {string.Join(", ", touchedContextFolders)}");
        }

        private static IEnumerable<SemanticCheck> CheckFileChurnBehavior(
            ProcessContext ctx,
            ProcessProfile profile,
            bool browserSafeMode,
            bool installerSafeMode = false)
        {
            int writes = Math.Max(0, profile.TotalFileWrites - profile.TotalRuntimeArtifactWrites);
            int deletes = Math.Max(0, profile.TotalFileDeletes - profile.TotalRuntimeArtifactDeletes);
            int total = writes + deletes;

            double runtime = Math.Max(ctx.UptimeSeconds, 1.0);
            double churnRate = total / runtime;

            bool highActivityMode = browserSafeMode || installerSafeMode;
            int churnDeleteThreshold = highActivityMode ? 40 : 5;
            double churnRateThreshold = highActivityMode ? 80 : 10;
            int excessiveDeleteThreshold = highActivityMode ? 250 : 20;

            yield return Check(SemanticCheckId.HighFileCreateDeleteChurn,
                deletes >= churnDeleteThreshold && churnRate > churnRateThreshold,
                ThreatImpact.Suspicious,
                $"{writes} writes, {deletes} deletes at {churnRate:F0} ops/sec");

            yield return Check(SemanticCheckId.ExcessiveFileDeletion,
                deletes >= excessiveDeleteThreshold,
                ThreatImpact.Suspicious,
                $"{deletes} files deleted");
        }

        private static IEnumerable<SemanticCheck> CheckDirectoryScatter(
            ProcessContext ctx, ProcessProfile profile)
        {
            if (!profile.WriteDirectories.Any()) yield break;

            var topDirs = profile.WriteDirectories.Keys
                .Select(NormalizeToTopDir)
                .Where(d => d != null)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            yield return Check(SemanticCheckId.WriteDirectoryScatter,
                topDirs.Count >= 3 && topDirs.Count < 5,
                ThreatImpact.Inconclusive,
                $"Writes spread across {topDirs.Count} locations: {string.Join(", ", topDirs.Take(5))}");

            yield return Check(SemanticCheckId.WideWriteDirectoryScatter,
                topDirs.Count >= 5,
                ThreatImpact.Suspicious,
                $"Writes spread across {topDirs.Count} locations: {string.Join(", ", topDirs.Take(6))}");
        }

        private static string? NormalizeToTopDir(string path)
        {
            try
            {
                var parts = path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (parts.Length >= 2)
                    return string.Join(Path.DirectorySeparatorChar.ToString(), parts.Take(3)).ToLowerInvariant();
                return null;
            }
            catch { return null; }
        }

        private static string? FindSelfDeleteCommand(IEnumerable<SpawnedProcess> spawns, string ownPath, string ownName)
        {
            foreach (var spawn in spawns)
            {
                if (string.IsNullOrEmpty(spawn.CommandLine)) continue;
                string lowerCmd = spawn.CommandLine.ToLowerInvariant();

                if (!IsCommandInterpreter(spawn.Name))
                    continue;

                bool hasDeleteVerb = ContainsDeleteVerb(lowerCmd);
                bool referencesOwn = ReferencesOwnProgram(lowerCmd, ownPath, ownName);
                bool hasDelayAndDelete = ContainsDelayPrimitive(lowerCmd) && hasDeleteVerb;

                if (hasDeleteVerb && (referencesOwn || hasDelayAndDelete))
                    return spawn.CommandLine;
            }
            return null;
        }

        private static IEnumerable<SemanticCheck> CheckSelfDeletion(
            ProcessContext ctx,
            ProcessProfile profile,
            bool browserSafeMode)
        {
            string ownPath = (ctx.FilePath ?? "UNKNOWN").ToLowerInvariant();
            string ownName = Path.GetFileName(ownPath);

            string? selfDeleteCmd = FindSelfDeleteCommand(profile.SpawnedCommandLines, ownPath, ownName);

            yield return Check(SemanticCheckId.ProcessSelfDeletion,
                selfDeleteCmd != null,
                ThreatImpact.Malicious,
                $"Self-deletion command issued: '{selfDeleteCmd?[..Math.Min(selfDeleteCmd.Length, 80)]}'",
                isHardIndicator: true);

            var deletedExes = profile.DeletedPaths
                .Where(p => MapToData._executableExtensions.Contains(Path.GetExtension(p)))
                .Where(p => !MapToData.IsRuntimeArtifactPath(p))
                .Where(p => !browserSafeMode || IsProgramExecutableExtension(p))
                .Where(p =>
                {
                    var fn = Path.GetFileName(p).ToLowerInvariant();
                    return !MapToData._safeDropPrefixes.Any(pfx => fn.StartsWith(pfx));
                })
                .ToList();

            bool deletedSelf = ownPath != "unknown" && profile.DeletedPaths
                .Any(p => p.ToLowerInvariant() == ownPath);

            yield return Check(SemanticCheckId.OwnProgramDeleted,
                deletedSelf,
                ThreatImpact.Malicious,
                $"Process deleted its own executable from disk");

            if (deletedExes.Any() && !deletedSelf)
            {
                string deletedNames = string.Join(", ", deletedExes.Take(3).Select(p => Path.GetFileName(p)));

                // Check if any deleted exe was previously spawned by this process AND has since exited.
                // Drop-run-wipe is the canonical dropper-cleanup pattern.
                var spawnedPathsLower = new HashSet<string>(
                    profile.SpawnedCommandLines
                        .Select(s => s.ImagePath?.ToLowerInvariant() ?? "")
                        .Where(p => !string.IsNullOrEmpty(p)),
                    StringComparer.OrdinalIgnoreCase);

                var deletedAfterExecution = deletedExes
                    .Where(p => spawnedPathsLower.Contains(p.ToLowerInvariant()))
                    .ToList();

                bool anySpawnedAndExited = deletedAfterExecution.Any() &&
                    profile.SpawnedCommandLines
                        .Where(s => deletedAfterExecution.Any(d =>
                            d.Equals(s.ImagePath, StringComparison.OrdinalIgnoreCase)))
                        .Any(s =>
                        {
                            try { return Process.GetProcessById(s.Pid).HasExited; }
                            catch { return true; }
                        });

                if (anySpawnedAndExited)
                {
                    string executedNames = string.Join(", ", deletedAfterExecution.Take(3).Select(p => Path.GetFileName(p)));
                    yield return Check(SemanticCheckId.ExecutableFileDeletedAfterExecution,
                        true,
                        ThreatImpact.Malicious,
                        $"{deletedAfterExecution.Count} executable(s) deleted after being executed by this process: {executedNames}",
                        isHardIndicator: true);
                }
                else
                {
                    yield return Check(SemanticCheckId.ExecutableFileDeleted,
                        true,
                        ThreatImpact.Suspicious,
                        $"{deletedExes.Count} executable file(s) deleted with no prior execution by this process: {deletedNames}");
                }
            }
        }

        private static bool IsProgramExecutableExtension(string path)
        {
            string ext = Path.GetExtension(path);
            return ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                   ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                   ext.Equals(".scr", StringComparison.OrdinalIgnoreCase) ||
                   ext.Equals(".pif", StringComparison.OrdinalIgnoreCase) ||
                   ext.Equals(".com", StringComparison.OrdinalIgnoreCase) ||
                   ext.Equals(".msi", StringComparison.OrdinalIgnoreCase);
        }

        private static bool HasBehavioralRedFlag(
            ProcessProfile profile,
            ProcessContext ctx,
            bool browserSafeMode)
        {
            string processNameNoExt = Path.GetFileNameWithoutExtension(
                profile.ProcessName?.ToLowerInvariant() ?? "");

            if (profile.ExeDropPaths != null && profile.ExeDropPaths.Keys.Any(p =>
                IsSuspiciousDropPath(p) &&
                !IsSelfUpdate(p, processNameNoExt) &&
                (!browserSafeMode || IsProgramExecutableExtension(p))))
                return true;

            if (profile.DeletedPaths != null)
            {
                foreach (string p in profile.DeletedPaths)
                {
                    string fn = Path.GetFileName(p).ToLowerInvariant();
                    bool isExe = MapToData._executableExtensions.Contains(Path.GetExtension(p));
                    bool isSafe = MapToData._safeDropPrefixes.Any(pfx => fn.StartsWith(pfx));
                    if (browserSafeMode && !IsProgramExecutableExtension(p))
                        continue;

                    if (isExe && !isSafe && !MapToData.IsRuntimeArtifactPath(p) && IsSuspiciousDropPath(p))
                        return true;
                }
            }

            if (profile.SpawnedCommandLines != null)
            {
                string ownPath = ctx.FilePath?.ToLowerInvariant() ?? "unknown";
                foreach (var spawn in profile.SpawnedCommandLines)
                {
                    if (string.IsNullOrEmpty(spawn.CommandLine)) continue;
                    string cl = spawn.CommandLine.ToLowerInvariant();
                    if (!IsCommandInterpreter(spawn.Name))
                        continue;
                    bool hasDelete = ContainsDeleteVerb(cl);
                    bool hasDelay = ContainsDelayPrimitive(cl) && cl.Contains("del");
                    bool referencesOwn = ReferencesOwnProgram(cl, ownPath, processNameNoExt);
                    bool referencesStaging = ReferencesStagingPath(cl);
                    if ((hasDelete || hasDelay) && (referencesOwn || referencesStaging))
                        return true;
                }
            }

            return false;
        }

        private static bool IsSuspiciousDropPath(string path)
        {
            string lp = path.ToLowerInvariant();
            bool staging =
                lp.Contains(@"\appdata\") ||
                lp.Contains(@"\temp\") ||
                lp.Contains(@"\programdata\") ||
                lp.Contains(@"\users\public\") ||
                lp.Contains(@"\windows\temp\") ||
                lp.Contains(@"\$recycle.bin\");
            bool legitimate =
                lp.Contains(@"\program files\") ||
                lp.Contains(@"\program files (x86)\") ||
                lp.Contains(@"\windows\system32\") ||
                lp.Contains(@"\windows\syswow64\");
            return staging && !legitimate;
        }

        private static bool IsSelfUpdate(string droppedPath, string processNameNoExt)
        {
            if (string.IsNullOrEmpty(processNameNoExt) || processNameNoExt.Length < 3)
                return false;
            string droppedName = Path.GetFileNameWithoutExtension(droppedPath).ToLowerInvariant();
            return droppedName.Contains(processNameNoExt);
        }

        private static IEnumerable<SemanticCheck> CheckSysmonEvents(List<SuspiciousEvent> events)
        {
            yield return Check(SemanticCheckId.LsassMemoryAccess,
                events.Any(e => e.EventType == "LsassAccess"),
                ThreatImpact.Malicious, "LSASS memory opened");

            yield return Check(SemanticCheckId.RemoteThreadInjection,
                events.Any(e => e.EventType == "RemoteThreadInjection"),
                ThreatImpact.Malicious, "Remote thread injected into another process");

            yield return Check(SemanticCheckId.ProcessTamperingDetected,
                events.Any(e => e.EventType == "ProcessTampering"),
                ThreatImpact.Malicious, "Process memory image replaced (process hollowing)");
        }

        private static bool IsSuspiciousPath(string filePath)
        {
            string lp = filePath.ToLowerInvariant();
            return lp.Contains(@"\appdata\local\temp\") ||
                   lp.Contains(@"\users\public\") ||
                   lp.Contains(@"\programdata\") ||
                   lp.Contains(@"\windows\temp\") ||
                   lp.Contains(@"\recycle.bin\");
        }

        private static void PopulateSignatureInfo(ProcessContext ctx)
        {
            try
            {
                SignatureVerificationResult verification = SignatureVerifier.VerifyFile(ctx.FilePath);
                ctx.HasSignature = verification.HasSignature;
                ctx.IsSigned = verification.IsCryptographicallyValid;
                ctx.IsTrustedPublisher = verification.IsTrustedPublisher;
                ctx.SignerName = verification.PublisherName;
                ctx.SignatureTrustState = verification.TrustState;
                ctx.SignatureSummary = verification.Summary;
            }
            catch
            {
                ctx.HasSignature = false;
                ctx.IsSigned = false;
                ctx.IsTrustedPublisher = false;
                ctx.SignerName = "";
                ctx.SignatureTrustState = SignatureTrustState.InvalidSignature;
                ctx.SignatureSummary = "Signature check failed unexpectedly.";
            }
        }

        private static ProcessContext GatherSystemContext(ProcessProfile profile)
        {
            var ctx = new ProcessContext();
            if (profile == null)
                return ctx;

            int pid = profile.ProcessId;

            string? etwImagePath = profile.ImagePath;
            if (string.IsNullOrWhiteSpace(etwImagePath) &&
                MapToData.ActiveProfiles.TryGetValue(pid, out var existingProfile))
            {
                etwImagePath = existingProfile.ImagePath;
            }
            if (string.IsNullOrWhiteSpace(etwImagePath))
                etwImagePath = ResolveStoredImagePath(profile);

            string storedParentName = profile.ParentProcessNameAtSpawn;
            string storedParentPath = profile.ParentImagePathAtSpawn;
            int storedParentPid = profile.ParentProcessIdAtSpawn;

            if (!string.IsNullOrWhiteSpace(storedParentName))
                ctx.ParentProcess = storedParentName;
            if (!string.IsNullOrWhiteSpace(storedParentPath))
            {
                ctx.ParentFilePath = storedParentPath;
                ctx.ParentIsTrustedPublisher = IsTrustedPublisherPath(storedParentPath);
                ctx.ParentIsSuspicious = IsSuspiciousPath(storedParentPath);
            }

            ctx.AncestorChain = BuildAncestorChain(profile);
            if (ctx.AncestorChain.Count > 0)
                ctx.ParentProcess = ctx.AncestorChain[0];

            try
            {
                using var proc = Process.GetProcessById(pid);

                ctx.FilePath = proc.MainModule?.FileName ?? "UNKNOWN";
                ctx.HandleCount = proc.HandleCount;
                ctx.WorkingSetMB = proc.WorkingSet64 / (1024 * 1024);
                ctx.ThreadCount = proc.Threads.Count;
                ctx.UptimeSeconds = (DateTime.Now - proc.StartTime).TotalSeconds;

                ctx.IsSuspiciousPath = IsSuspiciousPath(ctx.FilePath);
                PopulateSignatureInfo(ctx);

                if (ctx.AncestorChain.Count == 0)
                    ctx.AncestorChain = BuildAncestorChain(profile);
                if (ctx.ParentProcess == "UNKNOWN")
                    ctx.ParentProcess = ctx.AncestorChain.FirstOrDefault() ?? storedParentName ?? "UNKNOWN";

                if (string.IsNullOrWhiteSpace(ctx.ParentFilePath) || ctx.ParentFilePath == "UNKNOWN")
                    (ctx.ParentFilePath, ctx.ParentIsTrustedPublisher) = GetParentContext(profile);
                if (!string.IsNullOrWhiteSpace(ctx.ParentFilePath) && ctx.ParentFilePath != "UNKNOWN")
                    ctx.ParentIsSuspicious = IsSuspiciousPath(ctx.ParentFilePath);

                using var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (ManagementObject obj in searcher.Get())
                    try { ctx.IsConsoleApp = obj["WindowStyle"]?.ToString() == "0"; } catch { }

                try
                {
                    using var netSearcher = new ManagementObjectSearcher(
                        @"root\StandardCimv2",
                        $"SELECT * FROM MSFT_NetTCPConnection WHERE OwningProcess = {pid}");
                    var conns = netSearcher.Get();
                    ctx.NetworkConnCount = conns.Count;
                    ctx.HasNetworkConns = ctx.NetworkConnCount > 0;
                }
                catch { }

                ctx.HasDebugPriv = CheckDebugPrivilege(proc.Handle);
                ctx.IsElevated = CheckIsElevated(proc.Handle);
            }
            catch { }

            if (ctx.FilePath == "UNKNOWN" && !string.IsNullOrEmpty(etwImagePath))
            {
                ctx.FilePath = etwImagePath;
                ctx.ProcessExited = true;
                ctx.IsSuspiciousPath = IsSuspiciousPath(ctx.FilePath);

                if (File.Exists(ctx.FilePath))
                {
                    PopulateSignatureInfo(ctx);
                }
            }

            if (ctx.AncestorChain.Count == 0 && !string.IsNullOrWhiteSpace(storedParentName))
                ctx.AncestorChain.Add(storedParentName);

            if ((string.IsNullOrWhiteSpace(ctx.ParentFilePath) || ctx.ParentFilePath == "UNKNOWN") &&
                !string.IsNullOrWhiteSpace(storedParentPath))
            {
                ctx.ParentFilePath = storedParentPath;
                ctx.ParentIsTrustedPublisher = IsTrustedPublisherPath(storedParentPath);
                ctx.ParentIsSuspicious = IsSuspiciousPath(storedParentPath);
            }

            if (ctx.ParentProcess == "UNKNOWN")
            {
                if (!string.IsNullOrWhiteSpace(storedParentName))
                {
                    ctx.ParentProcess = storedParentName;
                }
                else
                {
                    ctx.ParentIsTrustedPublisher = ctx.IsTrustedPublisher;
                    ctx.ParentFilePath = ctx.FilePath;
                    ctx.ParentIsSuspicious = false;
                }
            }

            if (ctx.ParentProcess == "UNKNOWN" && storedParentPid > 0)
                ctx.ParentProcess = $"PID {storedParentPid}";

            return ctx;
        }

        private static bool IsTrustedPublisherPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return false;

            return SignatureVerifier.VerifyFile(path).IsTrustedPublisher;
        }

        private static (string filePath, bool isTrustedPublisher) GetParentContext(ProcessProfile profile)
        {
            if (!string.IsNullOrWhiteSpace(profile.ParentImagePathAtSpawn))
                return (profile.ParentImagePathAtSpawn, IsTrustedPublisherPath(profile.ParentImagePathAtSpawn));

            int pid = profile.ProcessId;
            try
            {
                using var query = new ManagementObjectSearcher(
                    $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");

                foreach (var row in query.Get())
                {
                    int parentPid = Convert.ToInt32(row["ParentProcessId"]);
                    if (parentPid <= 0 || parentPid == pid)
                        continue;

                    using var parentProc = Process.GetProcessById(parentPid);
                    string path = parentProc.MainModule?.FileName ?? "";

                    if (string.IsNullOrEmpty(path))
                        return ("", false);

                    return (path, IsTrustedPublisherPath(path));
                }
            }
            catch { }
            return ("", false);
        }

        private static string ResolveStoredImagePath(ProcessProfile profile)
        {
            if (profile == null)
                return "";

            if (!string.IsNullOrWhiteSpace(profile.ImagePath) && File.Exists(profile.ImagePath))
                return profile.ImagePath;

            string launchPath = ExtractExecutableFromCommandLine(profile.LaunchCommandLineAtSpawn);
            string resolvedLaunchPath = ResolveExecutablePath(launchPath);
            if (!string.IsNullOrWhiteSpace(resolvedLaunchPath))
                return resolvedLaunchPath;

            if (profile.SpawnedCommandLines != null)
            {
                foreach (var spawn in profile.SpawnedCommandLines)
                {
                    string resolvedSpawnPath = ResolveExecutablePath(spawn.ImagePath);
                    if (!string.IsNullOrWhiteSpace(resolvedSpawnPath))
                        return resolvedSpawnPath;
                }
            }

            return ResolveExecutablePath(profile.ProcessName);
        }

        private static string ExtractExecutableFromCommandLine(string? commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine))
                return "";

            string trimmed = commandLine.Trim();
            if (trimmed.StartsWith('"'))
            {
                int closingQuote = trimmed.IndexOf('"', 1);
                return closingQuote > 1 ? trimmed[1..closingQuote] : trimmed.Trim('"');
            }

            int firstSpace = trimmed.IndexOf(' ');
            return firstSpace > 0 ? trimmed[..firstSpace] : trimmed;
        }

        private static string ResolveExecutablePath(string? rawExecutable)
        {
            if (string.IsNullOrWhiteSpace(rawExecutable))
                return "";

            string candidate = Environment.ExpandEnvironmentVariables(rawExecutable.Trim().Trim('"'));
            if (File.Exists(candidate))
                return candidate;

            if (!Path.HasExtension(candidate) && File.Exists(candidate + ".exe"))
                return candidate + ".exe";

            var searchDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                Environment.SystemDirectory,
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64"),
                AppContext.BaseDirectory
            };

            string pathValue = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (string part in pathValue.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
                searchDirs.Add(part.Trim());

            foreach (string dir in searchDirs.Where(Directory.Exists))
            {
                string directCandidate = Path.Combine(dir, Path.GetFileName(candidate));
                if (File.Exists(directCandidate))
                    return directCandidate;

                if (!Path.HasExtension(directCandidate))
                {
                    string exeCandidate = directCandidate + ".exe";
                    if (File.Exists(exeCandidate))
                        return exeCandidate;
                }
            }

            return "";
        }

        private static List<string> BuildAncestorChain(ProcessProfile profile, int maxDepth = 5)
        {
            var chain = new List<string>();
            if (profile == null)
                return chain;

            int current = profile.ProcessId;
            if (!string.IsNullOrWhiteSpace(profile.ParentProcessNameAtSpawn))
            {
                chain.Add(profile.ParentProcessNameAtSpawn);
                if (profile.ParentProcessIdAtSpawn <= 0)
                    return chain;

                current = profile.ParentProcessIdAtSpawn;
            }

            for (int i = chain.Count; i < maxDepth; i++)
            {
                try
                {
                    using var s = new ManagementObjectSearcher(
                        $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {current}");

                    int parentId = -1;
                    foreach (var r in s.Get())
                    {
                        parentId = Convert.ToInt32(r["ParentProcessId"]);
                    }

                    if (parentId <= 0 || parentId == current) break;

                    using var parentProc = Process.GetProcessById(parentId);
                    string parentName = parentProc.ProcessName;
                    if (!string.IsNullOrWhiteSpace(parentName) &&
                        (chain.Count == 0 || !string.Equals(chain[^1], parentName, StringComparison.OrdinalIgnoreCase)))
                    {
                        chain.Add(parentName);
                    }

                    current = parentId;
                }
                catch { break; }
            }
            return chain;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            public long Luid;
            public uint Attributes;
        }

        private static bool CheckDebugPrivilege(IntPtr processHandle)
        {
            try
            {
                if (!OpenProcessToken(processHandle, TOKEN_QUERY, out IntPtr tokenHandle)) return false;
                try
                {
                    GetTokenInformation(tokenHandle, 3, IntPtr.Zero, 0, out int length);
                    if (length == 0) return false;
                    IntPtr buffer = Marshal.AllocHGlobal(length);
                    try
                    {
                        if (!GetTokenInformation(tokenHandle, 3, buffer, length, out _)) return false;

                        int count = Marshal.ReadInt32(buffer);
                        int stride = Marshal.SizeOf<LUID_AND_ATTRIBUTES>();
                        for (int i = 0; i < count; i++)
                        {
                            IntPtr itemPtr = IntPtr.Add(buffer, 4 + i * stride);
                            var item = Marshal.PtrToStructure<LUID_AND_ATTRIBUTES>(itemPtr);
                            if ((item.Luid & 0xFFFFFFFF) == 20 && (item.Attributes & 0x00000002) != 0) return true;
                        }
                    }
                    finally { Marshal.FreeHGlobal(buffer); }
                }
                finally { CloseHandle(tokenHandle); }
            }
            catch { }
            return false;
        }

        private static bool CheckIsElevated(IntPtr processHandle)
        {
            try
            {
                if (!OpenProcessToken(processHandle, TOKEN_QUERY, out IntPtr tokenHandle)) return false;
                try
                {
                    int size = 4;
                    IntPtr buffer = Marshal.AllocHGlobal(size);
                    try
                    {

                        if (!GetTokenInformation(tokenHandle, 20, buffer, size, out _)) return false;
                        return Marshal.ReadInt32(buffer) != 0;
                    }
                    finally { Marshal.FreeHGlobal(buffer); }
                }
                finally { CloseHandle(tokenHandle); }
            }
            catch { return false; }
        }

        private static string GetCheckName(SemanticCheckId id) => id switch
        {
            SemanticCheckId.SuspiciousExecutionPath => "Suspicious Execution Path",
            SemanticCheckId.MissingProgramOnDisk => "Missing Program on Disk",
            SemanticCheckId.ProcessExitedBeforeAnalysis => "Process Exited Before Analysis",
            SemanticCheckId.SystemProcessNotInSystem32 => "System Process Not in System32",
            SemanticCheckId.SpawnedBySuspiciousParent => "Spawned by Suspicious Parent",
            SemanticCheckId.OfficeAppSpawnedShellOrTool => "Office App Spawned Shell/Tool",
            SemanticCheckId.BrowserSpawnedByNonShellParent => "Browser Spawned by Non-Shell Parent",
            SemanticCheckId.DeepAncestryChain => "Deep Ancestry Chain",
            SemanticCheckId.EncodedOrObfuscatedCommand => "Encoded or Obfuscated Command",
            SemanticCheckId.ExecutionPolicyOrProfileBypass => "Execution Policy or Profile Bypass",
            SemanticCheckId.HiddenOrMinimizedCommandExecution => "Hidden or Minimized Command Execution",
            SemanticCheckId.DestructiveCleanupCommand => "Destructive Cleanup Command",
            SemanticCheckId.RecoveryTamperingCommand => "Recovery Tampering Command",
            SemanticCheckId.PersistenceOrientedCommand => "Persistence-Oriented Command",
            SemanticCheckId.WmiProcessCreationCommand => "WMI Process Creation Command",
            SemanticCheckId.ExcessiveHandleCount => "Excessive Handle Count",
            SemanticCheckId.DisproportionateMemoryUse => "Disproportionate Memory Use",
            SemanticCheckId.UnexpectedNetworkConnections => "Unexpected Network Connections",
            SemanticCheckId.SeDebugPrivilegeSelfEnabled => "SeDebugPrivilege Actively Used",
            SemanticCheckId.SeDebugPrivilegeWithCredentialActivity => "SeDebugPrivilege Set with Suspicious Activity",
            SemanticCheckId.InheritedSeDebugPrivilege => "SeDebugPrivilege Set (Unused)",
            SemanticCheckId.UnexpectedElevation => "Unexpected Elevation",
            SemanticCheckId.HeadlessConsoleApp => "Headless Console App",
            SemanticCheckId.ImmediateHighActivityOnSpawn => "Immediate High Activity on Spawn",
            SemanticCheckId.HighOverallEventRate => "High Overall Event Rate",
            SemanticCheckId.ModerateAutomatedRate => "Moderate Automated Rate",
            SemanticCheckId.SingleRuleHighVelocity => "Single-Rule High Velocity",
            SemanticCheckId.BroadSystemScanning => "Broad System Scanning (8+ areas)",
            SemanticCheckId.ModerateSystemScanning => "Moderate System Scanning (4-7 areas)",
            SemanticCheckId.CredentialsStoreAccess => "Credentials Store Access",
            SemanticCheckId.BrowserCredentialAccess => "Browser Credential Access",
            SemanticCheckId.ThirdPartyCredentialStores => "Third-Party Credential Stores",
            SemanticCheckId.ModifyingPersistenceMechanisms => "Modifying Persistence Mechanisms",
            SemanticCheckId.DefenseToolTampering => "Defense Tool Tampering",
            SemanticCheckId.DpapiDecryptionActivity => "DPAPI Decryption Activity",
            SemanticCheckId.HighCrossSystemAreaCoverage => "High Cross-System Area Coverage",
            SemanticCheckId.AllActivityInTwoSecondBurst => "All Activity in <2 Second Burst",
            SemanticCheckId.MultiTacticActivityInFiveSecondWindow => "Multi-Tactic Activity in 5s Window",
            SemanticCheckId.MassiveAttemptCountForShortRuntime => "Massive Attempt Count for Short Runtime",
            SemanticCheckId.ExecutableDroppedToStagingFolder => "Executable Dropped to Staging Folder",
            SemanticCheckId.CredentialHarvestFileStaged => "Credential Harvest File Staged",
            SemanticCheckId.ExfiltrationChainCollectStageExfil => "Exfiltration Chain: Collect → Stage → Exfil",
            SemanticCheckId.ExfiltrationChainCollectStageNoExfilYet => "Exfiltration Chain: Collect → Stage (No Exfil Yet)",
            SemanticCheckId.UnsignedWriteToUnrelatedProgramDataFolder => "Unsigned Write to Unrelated ProgramData Folder",
            SemanticCheckId.MultipleStagingLocationsUsed => "Multiple Staging Locations Used",
            SemanticCheckId.ExecutableProgramDropped => "Executable Program Dropped",
            SemanticCheckId.ScriptFileDropped => "Script File Dropped",
            SemanticCheckId.MultipleExecutablesDropped => "Multiple Executables Dropped",
            SemanticCheckId.HighFileCreateDeleteChurn => "High File Create-Delete Churn",
            SemanticCheckId.ExcessiveFileDeletion => "Excessive File Deletion",
            SemanticCheckId.WriteDirectoryScatter => "Write Directory Scatter (3+ locations)",
            SemanticCheckId.WideWriteDirectoryScatter => "Wide Write Directory Scatter (5+ locations)",
            SemanticCheckId.ProcessSelfDeletion => "Process Self-Deletion",
            SemanticCheckId.OwnProgramDeleted => "Own Program Deleted",
            SemanticCheckId.ExecutableFileDeleted => "Executable File Deleted",
            SemanticCheckId.ExecutableFileDeletedAfterExecution => "Executable Deleted After Execution (Drop-Run-Wipe)",
            SemanticCheckId.LsassMemoryAccess => "LSASS Memory Access",
            SemanticCheckId.RemoteThreadInjection => "Remote Thread Injection",
            SemanticCheckId.ProcessTamperingDetected => "Process Tampering Detected",
            _ => id.ToString()
        };

        private static SemanticCheck Check(SemanticCheckId id, bool fired, ThreatImpact impact, string reason, bool isHardIndicator = false)
        {
            return new SemanticCheck
            {
                Id = id,
                Name = GetCheckName(id),
                IsFired = fired,
                IsHardIndicator = isHardIndicator,
                Impact = fired ? impact : ThreatImpact.Safe,
                Reason = reason
            };
        }

        private static double GetTrustMultiplier(string name, string nameNoExt, ProcessContext ctx)
        {
            if (!MapToData._processTrustMultipliers.TryGetValue(name, out double m) &&
                !MapToData._processTrustMultipliers.TryGetValue(nameNoExt, out m) &&
                !MapToData._processTrustMultipliers.TryGetValue(nameNoExt + ".exe", out m))
            {
                return 1.0;
            }

            if (m >= 1.0)
                return m;

            bool isTrustedSystemName = MapToData._trustedSystem.Any(t =>
                Path.GetFileNameWithoutExtension(t).Equals(nameNoExt, StringComparison.OrdinalIgnoreCase));
            bool isTrustedUserAppName = MapToData._trustedUserApps.Any(t =>
                Path.GetFileNameWithoutExtension(t).Equals(nameNoExt, StringComparison.OrdinalIgnoreCase));

            if (isTrustedSystemName)
            {
                bool inWindowsDirectory = ctx.FilePath.StartsWith(@"c:\windows\", StringComparison.OrdinalIgnoreCase);
                return (ctx.IsTrustedPublisher || inWindowsDirectory) ? m : 1.0;
            }

            if (isTrustedUserAppName && !ctx.IsTrustedPublisher)
                return 1.0;

            return m;
        }
    }
}
