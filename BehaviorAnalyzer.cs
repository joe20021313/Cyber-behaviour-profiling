using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Cyber_behaviour_profiling
{
    public enum ThreatImpact
    {
        Safe = 0,
        Inconclusive = 1,
        Suspicious = 2,
        Malicious = 3
    }

    public class ChainConfirmationResult
    {
        public bool HasHardIndicator { get; set; } = false;
    }

    public class BehaviorReport
    {
        public ThreatImpact FinalVerdict { get; set; } = ThreatImpact.Safe;
        public int FinalScore { get; set; } = 0; // cosmetic only — no longer determines verdict
        public List<string> DecisionReasons { get; set; } = new();
        public List<string> SafeReasons { get; set; } = new();
        public ChainConfirmationResult ChainResult { get; set; } = new();
        public int FiredChecks { get; set; } = 0;
        public int TotalChecks { get; set; } = 0;
        public int ObservedTacticCount { get; set; } = 0;
        public List<string> FiredCheckNames { get; set; } = new();
        public AnomalyResult? Anomaly { get; set; }
        public bool IsSigned { get; set; }
        public string SignerName { get; set; } = "";
        public InvestigationResult? DirectoryInvestigation { get; set; }
        public InvestigationResult? NetworkInvestigation { get; set; }
    }

    public class ProcessContext // filled by GatherSystemContext()
    {
        public string FilePath { get; set; } = "UNKNOWN";
        public bool IsSigned { get; set; } = false;
        public bool IsTrustedPublisher { get; set; } = false;
        public bool IsSuspiciousPath { get; set; } = false;
        public string SignerName { get; set; } = "";
        public string ParentProcess { get; set; } = "UNKNOWN";
        public bool ParentIsSuspicious { get; set; } = false;
        public bool ParentIsTrustedPublisher { get; set; } = false;
        public string ParentFilePath { get; set; } = "UNKNOWN";
        public List<string> AncestorChain { get; set; } = new();
        public int HandleCount { get; set; } = 0;
        public long WorkingSetMB { get; set; } = 0;
        public double CpuTimeSeconds { get; set; } = 0;
        public int ThreadCount { get; set; } = 0;
        public bool HasDebugPriv { get; set; } = false;
        public bool HasNetworkConns { get; set; } = false;
        public int NetworkConnCount { get; set; } = 0;
        public bool IsElevated { get; set; } = false;
        public bool IsConsoleApp { get; set; } = false;
        public DateTime ProcessStartTime { get; set; }
        public double UptimeSeconds { get; set; } = 0;
        public bool ProcessExited { get; set; } = false;
    }

    public class SemanticCheck
    {
        public string Name { get; set; }
        public ThreatImpact Impact { get; set; }
        public string Reason { get; set; }
        public bool IsFired { get; set; }
        public bool IsHardIndicator { get; set; }
    }

    public static class BehaviorAnalyzer
    {
        // =========================================================================================
        // NATIVE WINDOWS API CALLS (P/Invoke)
        // C# cannot natively check deep Windows security privileges or verify Authenticode signatures.
        // We use [DllImport] to bridge our C# code to the raw Windows system DLLs (C/C++ APIs).
        // =========================================================================================

        // Used by CheckDebugPrivilege() to open the security token of a process
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        // Used by CheckDebugPrivilege() to read the privileges currently enabled in that token
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInfoClass,
            IntPtr tokenInfo, int tokenInfoLength, out int returnLength);

        // Used to close the token handle when we are done, avoiding memory leaks
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        private const uint TOKEN_QUERY = 0x0008;

        // Used by VerifyAuthenticode() to check if a file has a valid digital signature
        [DllImport("wintrust.dll", SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

        // StructLayout ensures C# formats this memory block exactly the way the older Windows C API expects
        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        // The main data structure handed over to Windows to ask it to verify a signature
        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        // A magic GUID (identifier) that tells WinVerifyTrust to do a standard signature check
        private static readonly Guid WintrustActionGenericVerify =
            new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        // The specific permission required to ask Windows for a process token's details

        public static BehaviorReport Analyze(ProcessProfile profile)
        {
            var report = new BehaviorReport();
            if (profile == null || profile.EventTimeline == null || !profile.EventTimeline.Any())
                return report;

            var events = profile.EventTimeline.ToList();
            string name = profile.ProcessName?.ToLowerInvariant() ?? "";
            string nameNoExt = Path.GetFileNameWithoutExtension(name);

            bool isBlacklisted = IsBlacklisted(name, nameNoExt);

            ProcessContext ctx = GatherSystemContext(profile.ProcessId, profile.ProcessName); // investigates process

            bool hasBehavioralRedFlag = HasBehavioralRedFlag(profile, ctx);

            bool claimsTrustedName =
                MapToData._trustedSystem.Any(t => t.Contains(nameNoExt)) ||
                MapToData._trustedUserApps.Any(t => t.Contains(nameNoExt));

            if (claimsTrustedName &&
                ((ctx.FilePath != "UNKNOWN" && !ctx.IsSigned) || ctx.IsSuspiciousPath))
            {
                report.FinalVerdict = ThreatImpact.Malicious;
                report.FinalScore = 999;
                report.DecisionReasons.Add(
                    $"{profile.ProcessName}' uses a trusted name but " +
                    (!ctx.IsSigned ? "has no valid signature" : "") +
                    (ctx.IsSuspiciousPath ? $" runs from suspicious path ({ctx.FilePath})" : "") + ".");
                return report;
            }

            var checks = new List<SemanticCheck>();
            checks.AddRange(CheckBinaryProvenance(ctx, profile));
            checks.AddRange(CheckSysmonEvents(events));
            checks.AddRange(CheckParent(ctx, profile));
            checks.AddRange(CheckRuntimeAnomalies(ctx, events, profile));
            checks.AddRange(CheckVelocityAndDensity(events));
            checks.AddRange(CheckSystemAreaFootprint(events));
            checks.AddRange(CheckTemporalAnomalies(events, ctx));
            checks.AddRange(CheckContextFolderBehavior(ctx, events, profile));
            checks.AddRange(CheckExecutableDrops(ctx, events, profile));
            checks.AddRange(CheckFileChurnBehavior(ctx, profile));
            checks.AddRange(CheckDirectoryScatter(ctx, profile));
            checks.AddRange(CheckSelfDeletion(ctx, profile));

            var anomaly = AnomalyDetector.Evaluate(profile, ctx);
            var historyAnomaly = AnomalyDetector.EvaluateHistory(profile);
            if (historyAnomaly.AnomalyDetected == true)
            {
                report.Anomaly = historyAnomaly; 
            }
            else
            {
                report.Anomaly = anomaly;       
            }
            report.IsSigned = ctx.IsSigned;
            report.SignerName = ctx.SignerName;

            var chainResult = new ChainConfirmationResult
            {
                HasHardIndicator = isBlacklisted || events.Any(IsHardIndicatorEvent)
            };
            if (!chainResult.HasHardIndicator)
                chainResult.HasHardIndicator = checks.Any(c => c.IsFired && c.IsHardIndicator);
            report.ChainResult = chainResult;

            double trustMult = GetTrustMultiplier(name, nameNoExt);


            if (!hasBehavioralRedFlag && trustMult <= 1.0)
            {
                if (ctx.IsSigned && ctx.IsTrustedPublisher && !ctx.IsSuspiciousPath)
                {
                    trustMult *= 0.5;
                    report.DecisionReasons.Add(
                        $"  [dampened] Signed by trusted publisher '{ctx.SignerName}', " +
                        $"standard path, no red flags → effective multiplier {trustMult:F2}x");
                }
                else if (ctx.IsSigned && !ctx.IsSuspiciousPath)
                {
                    trustMult *= 0.7;
                    report.DecisionReasons.Add(
                        $"  [dampened] Signed by '{ctx.SignerName}' (not on trusted list), " +
                        $"standard path, no red flags → effective multiplier {trustMult:F2}x");
                }
            }
            ThreatImpact highestImpact = ThreatImpact.Safe;
            int firedCount = 0;
            foreach (var check in checks.Where(c => c.IsFired))
            {
                if (!chainResult.HasHardIndicator && _softDrivenChecks.Contains(check.Name))
                {
                    report.DecisionReasons.Add($"  [suppressed] {check.Name}: {check.Reason} (no hard indicator present)");
                    continue;
                }

                if (check.Impact > highestImpact) highestImpact = check.Impact;
                firedCount++;
                report.FiredCheckNames.Add(check.Name);
                report.DecisionReasons.Add($"  [{check.Impact}] {check.Name}: {check.Reason}");
            }

            if (anomaly.AnomalyDetected)
            {
                ThreatImpact anomalyImpact = ThreatImpact.Inconclusive;
                if (anomalyImpact > highestImpact) highestImpact = anomalyImpact;
                firedCount++;
                string metrics = anomaly.SpikedMetrics.Count > 0
                    ? string.Join(", ", anomaly.SpikedMetrics)
                    : "behaviour deviation from baseline";
                report.DecisionReasons.Add(
                    $"  [{anomalyImpact}] KNN Anomaly: {metrics}");
            }

            if (firedCount >= 6)
            {
                if (ThreatImpact.Suspicious > highestImpact) highestImpact = ThreatImpact.Suspicious;
                report.DecisionReasons.Add($"  [Convergence] {firedCount} checks fired.");
            }
            else if (firedCount >= 3)
            {
                if (ThreatImpact.Inconclusive > highestImpact) highestImpact = ThreatImpact.Inconclusive;
                report.DecisionReasons.Add($"  [Partial convergence] {firedCount} checks fired.");
            }

            if (isBlacklisted)
            {
                highestImpact = ThreatImpact.Malicious;
                firedCount++;
                report.FiredCheckNames.Add("Blacklisted Process");
                report.DecisionReasons.Add(
                    $"  [Malicious] '{profile.ProcessName}' is a known offensive tool — full behavioural analysis follows.");
            }

            int observedTacticCount = events
                .Where(e => !string.IsNullOrEmpty(e.Category))
                .Select(e => e.Category)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();

            var dirInvestigation = RunDirectoryInvestigation(profile);
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
                    string tag = f.Severity == FindingSeverity.Alert ? "ALERT" :
                                 f.Severity == FindingSeverity.Warning ? "WARNING" : "INFO";
                    report.DecisionReasons.Add($"  [Investigation/{tag}] {f.Description}");
                    foreach (var child in f.Children)
                        report.DecisionReasons.Add($"    ↳ {child.Description}");
                }

                if (dirInvestigation.OverallSuspicion >= SuspicionLevel.High && !chainResult.HasHardIndicator)
                    chainResult.HasHardIndicator = true;
            }

            var netInvestigation = RunNetworkInvestigation(events, profile);
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
                    string tag = f.Severity == FindingSeverity.Alert ? "ALERT" :
                                 f.Severity == FindingSeverity.Warning ? "WARNING" : "INFO";
                    report.DecisionReasons.Add($"  [Investigation/{tag}] {f.Description}");
                    foreach (var child in f.Children)
                        report.DecisionReasons.Add($"    ↳ {child.Description}");
                }

                if (netInvestigation.OverallSuspicion >= SuspicionLevel.High && !chainResult.HasHardIndicator)
                    chainResult.HasHardIndicator = true;
            }

            if (!chainResult.HasHardIndicator && !hasBehavioralRedFlag && trustMult <= 0.6)
            {
                if (highestImpact == ThreatImpact.Malicious) 
                {
                    highestImpact = ThreatImpact.Suspicious;
                    report.DecisionReasons.Add("  [Trust Dampening] Highly trusted publisher — downgrading heuristic MALICIOUS impact to SUSPICIOUS.");
                }
                else if (highestImpact == ThreatImpact.Suspicious)
                {
                    highestImpact = ThreatImpact.Inconclusive;
                    report.DecisionReasons.Add("  [Trust Dampening] Highly trusted publisher — downgrading heuristic SUSPICIOUS impact to INCONCLUSIVE.");
                }
            }

            if ((chainResult.HasHardIndicator || hasBehavioralRedFlag) && highestImpact < ThreatImpact.Malicious)
            {
                highestImpact = ThreatImpact.Malicious;
                report.DecisionReasons.Add("  [Malicious Veto] Hard indicator or behavioural red flag present — verdict locked to MALICIOUS.");
            }

            if (highestImpact <= ThreatImpact.Suspicious &&
                !chainResult.HasHardIndicator &&
                !hasBehavioralRedFlag &&
                ctx.IsSigned && ctx.IsTrustedPublisher && !ctx.IsSuspiciousPath &&
                firedCount < 8)
            {
                highestImpact = ThreatImpact.Safe;
                report.DecisionReasons.Add($"  [Safe Veto] Signed by trusted publisher '{ctx.SignerName}', standard path, no hard flags — verdict forced to SAFE.");
            }

            // ── Final verdict ──
            report.FinalVerdict = highestImpact;
            report.FinalScore = (int)highestImpact * 30; // cosmetic only for UI display
            report.FiredChecks = firedCount;
            report.TotalChecks = checks.Count;
            report.ObservedTacticCount = observedTacticCount;
            string grade = highestImpact switch
            {
                ThreatImpact.Malicious    => "MALICIOUS",
                ThreatImpact.Suspicious   => "SUSPICIOUS",
                ThreatImpact.Inconclusive => "INCONCLUSIVE",
                _                         => "SAFE"
            };
            report.DecisionReasons.Insert(0,
                $"[VERDICT] {profile.ProcessName} (PID:{profile.ProcessId}) → " +
                $"{grade} | Impact: {highestImpact} | Checks fired: {firedCount}/{checks.Count}" +
                (!chainResult.HasHardIndicator ? " | No hard indicators" : ""));

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
            catch (Exception ex)
            {
                InvestigationLog.Write($"Directory investigation error: {ex.Message}");
                return null;
            }
        }

        private static InvestigationResult? RunNetworkInvestigation(
            List<SuspiciousEvent> events, ProcessProfile profile)
        {
            try
            {
                var networkEvents = events
                    .Where(e => e.EventType == "NetworkConnect" && e.Category is not "network_c2" and not "dns_c2")
                    .ToList();

                if (networkEvents.Count == 0 || profile.DirectorySnapshotBefore == null)
                    return null;

                var downloadDirs = SystemDiscovery.GetDownloadDirectories();
                var afterSnapshot = SystemDiscovery.TakeDirectorySnapshot(downloadDirs);

                var combined = new InvestigationResult();
                foreach (var netEvent in networkEvents)
                {
                    var r = SystemDiscovery.InvestigateNetworkEvent(
                        netEvent, profile,
                        profile.DirectorySnapshotBefore, afterSnapshot);

                    combined.Findings.AddRange(r.Findings);
                    combined.ScoreAdjustment += r.ScoreAdjustment;
                    if (r.ShouldInvestigateFurther)
                        combined.ShouldInvestigateFurther = true;
                    if (r.OverallSuspicion > combined.OverallSuspicion)
                        combined.OverallSuspicion = r.OverallSuspicion;
                }

                return combined.Findings.Count > 0 ? combined : null;
            }
            catch (Exception ex)
            {
                InvestigationLog.Write($"Network investigation error: {ex.Message}");
                return null;
            }
        }

        private static List<string> BuildSafeReasons(
            ProcessContext ctx, ProcessProfile profile, List<SuspiciousEvent> events,
            List<SemanticCheck>? checks = null, AnomalyResult? anomaly = null,
            int firedCount = 0, int totalChecks = 0)
        {
            var reasons = new List<string>();

            if (ctx.IsSigned && ctx.IsTrustedPublisher)
                reasons.Add($"Signed by verified publisher '{ctx.SignerName}' (publisher on trusted whitelist).");
            else if (ctx.IsSigned)
                reasons.Add($"Digitally signed by '{ctx.SignerName}', but publisher is not on the trusted whitelist. Signature confirms the binary has not been tampered with.");
            else if (ctx.FilePath != "UNKNOWN")
                reasons.Add("Binary is unsigned — no digital signature found.");

            if (ctx.FilePath != "UNKNOWN" && !ctx.IsSuspiciousPath)
                reasons.Add($"Running from a standard install location ({ctx.FilePath}).");

            var genericShells = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "explorer", "explorer.exe", "cmd", "cmd.exe",
                "powershell", "powershell.exe", "pwsh", "pwsh.exe",
                "wscript", "wscript.exe", "cscript", "cscript.exe"
            };

            if (ctx.ParentIsSuspicious)
            {
                reasons.Add($"Parent process '{ctx.ParentProcess}' is flagged as suspicious — this does not confirm the child is dangerous, but warrants attention.");
            }
            else if (genericShells.Contains(ctx.ParentProcess))
            {
                reasons.Add($"Parent process is '{ctx.ParentProcess}' (the Windows shell). This is neutral — most user-launched applications start from explorer.");
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

            var activityParts = new List<string>();
            if (fileEvents > 0) activityParts.Add($"{fileEvents} file operation(s)");
            if (netEvents > 0) activityParts.Add($"{netEvents} network connection(s)");
            if (procEvents > 0) activityParts.Add($"{procEvents} child process(es)");
            if (regEvents > 0) activityParts.Add($"{regEvents} registry access(es)");

            if (activityParts.Count > 0)
                reasons.Add($"Observed activity: {string.Join(", ", activityParts)} — none matched threat patterns in the rule database.");
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
            if (!events.Any(e => e.EventType == "BlacklistedProcess"))
                absent.Add("no known malicious tools");
            if (!events.Any(e => e.EventType is "NetworkConnect" or "DNS_Query"))
                absent.Add("no outbound network activity");

            if (absent.Count > 0)
                reasons.Add($"Absent threat indicators: {string.Join(", ", absent)}.");

            if (anomaly != null)
            {
                if (!anomaly.AnomalyDetected)
                    reasons.Add("Anomaly detector (KNN): behaviour is within the normal statistical range.");
                else
                    reasons.Add($"Note: anomaly detector flagged deviation — {string.Join(", ", anomaly.SpikedMetrics)}.");
            }

            reasons.Add("ETW event data is available for manual review if further investigation is needed.");

            return reasons;
        }

        private static bool IsHardIndicatorEvent(SuspiciousEvent ev)
        {
            if (ev.EventType is "DPAPI_Decrypt" or "BlacklistedProcess" or "AccessibilityBinaryOverwrite"
                    or "LsassAccess" or "RemoteThreadInjection" or "ProcessTampering")
                return true;
            if (ev.EventType is "NetworkConnect" or "DNS_Query")
                return ev.Category is "network_c2" or "dns_c2";
            if (ev.EventType == "SensitiveDirAccess")
            {
                string raw = (ev.RawData ?? "").ToLowerInvariant();
                return raw.Contains("\\protect\\") || raw.Contains("\\credentials\\") || raw.Contains("\\vault\\");
            }
            if (ev.Category is "credential_file_access" or "registry_credential_access"
                           or "lsass_access")
                return true;
            return false;
        }

        private static readonly HashSet<string> _softDrivenChecks = new(StringComparer.OrdinalIgnoreCase)
        {
            "Unsigned Binary",
            "Suspicious Execution Path",
            "All Activity in <2 Second Burst",
            "Multi-Tactic Activity in 5s Window",
            "Massive Attempt Count for Short Runtime",
            "Excessive Handle Count",
            "Disproportionate Memory Use",
            "Headless Console App",
            "Immediate High Activity on Spawn",
            "High Overall Event Rate",
            "Moderate Automated Rate",
            "Single-Rule High Velocity",
            "Broad System Scanning",
            "Moderate System Scanning",
            "Modifying Persistence Mechanisms",
            "High Cross-System Area Coverage",
            "Executable Dropped to Staging Folder",
            "Unsigned Write to Unrelated ProgramData Folder",
            "Multiple Staging Locations Used",
            "Script File Dropped",
            "High File Create-Delete Churn",
            "Excessive File Deletion",
            "Write Directory Scatter (3+ locations)",
            "Wide Write Directory Scatter (5+ locations)",
            "Multiple Executables Dropped",
            "Process Exited Before Analysis",
        };

        private static IEnumerable<SemanticCheck> CheckBinaryProvenance(ProcessContext ctx, ProcessProfile profile)
        {
            yield return Check("Unsigned Binary",
                !ctx.IsSigned && ctx.FilePath != "UNKNOWN",
                ThreatImpact.Inconclusive, "No valid digital signature.");

            yield return Check("Suspicious Execution Path",
                ctx.IsSuspiciousPath,
                ThreatImpact.Suspicious, $"Running from '{ctx.FilePath}'.");

            bool isRootedPath = Path.IsPathRooted(ctx.FilePath);
            bool binaryMissing = ctx.FilePath == "UNKNOWN";
            
            // Only claim it was deleted if we actually had a full, valid path to check against
            bool binaryDeletedFromDisk = ctx.FilePath != "UNKNOWN" && ctx.ProcessExited && isRootedPath && !File.Exists(ctx.FilePath);

            // Expand the trusted check to include Lolbins and Shell Interpreters (like powershell) 
            // since they are valid system-installed binaries that shouldn't self-delete
            string name = profile.ProcessName.ToLowerInvariant();
            bool claimsSystemName = MapToData._processTrustMultipliers.ContainsKey(name) || 
                                    MapToData._processTrustMultipliers.ContainsKey(name + ".exe");

            bool inSystemDir = ctx.FilePath.StartsWith(@"c:\windows\", StringComparison.OrdinalIgnoreCase);

            if (claimsSystemName)
                binaryDeletedFromDisk = false;

            yield return Check("Missing Binary on Disk",
                binaryDeletedFromDisk,
                ThreatImpact.Malicious, $"Binary '{ctx.FilePath}' no longer exists on disk — self-deletion or fileless execution.");

            yield return Check("Process Exited Before Analysis",
                binaryMissing,
                ThreatImpact.Inconclusive, "Process terminated before context could be gathered — short-lived or evasive execution.");

            yield return Check("System Process Not in System32",
                claimsSystemName && !inSystemDir && isRootedPath,
                ThreatImpact.Malicious, $"Claims to be a Windows process but lives at '{ctx.FilePath}'.");
        }

        private static IEnumerable<SemanticCheck> CheckParent(ProcessContext ctx, ProcessProfile profile)
        {
            bool badParent =
                ctx.ParentIsSuspicious ||
                MapToData._blacklistedProcesses.Contains(ctx.ParentProcess.ToLower()) ||
                MapToData._blacklistedProcesses.Contains(ctx.ParentProcess.ToLower() + ".exe");

            yield return Check("Spawned by Suspicious Parent",
                badParent,
                ThreatImpact.Suspicious, $"Parent '{ctx.ParentProcess}' is flagged.");

            yield return Check("Office App Spawned Shell/Tool",
                MapToData._officeApps.Contains(ctx.ParentProcess) &&
                (profile.ProcessName.ToLower().Contains("cmd") ||
                 profile.ProcessName.ToLower().Contains("powershell") ||
                 profile.ProcessName.ToLower().Contains("wscript") ||
                 profile.ProcessName.ToLower().Contains("cscript")),
                ThreatImpact.Malicious, $"'{ctx.ParentProcess}' spawned '{profile.ProcessName}' — macro/phishing pattern.");

            bool deepChain = ctx.AncestorChain.Count >= 4;
            bool chainHasSuspicious = ctx.AncestorChain.Any(a =>
                MapToData._blacklistedProcesses.Contains(a.ToLower()) ||
                MapToData._blacklistedProcesses.Contains(a.ToLower() + ".exe"));

            yield return Check("Deep or Tainted Ancestry Chain",
                deepChain || chainHasSuspicious,
                ThreatImpact.Suspicious, $"Ancestry: [{string.Join(" → ", ctx.AncestorChain)}]. " +
                    (chainHasSuspicious ? "Contains a flagged process." : "Unusually deep chain."));
        }

        private static IEnumerable<SemanticCheck> CheckRuntimeAnomalies(
            ProcessContext ctx, List<SuspiciousEvent> events, ProcessProfile profile)
        {
            yield return Check("Excessive Handle Count",
                ctx.HandleCount > 500,
                ThreatImpact.Inconclusive, $"{ctx.HandleCount} open handles.");

            yield return Check("Disproportionate Memory Use",
                ctx.WorkingSetMB > 200 && events.Count < 5,
                ThreatImpact.Inconclusive, $"{ctx.WorkingSetMB}MB with few events.");

            string lowerName = profile.ProcessName.ToLower();
            string lowerNameNoExt = Path.GetFileNameWithoutExtension(lowerName);
            bool isInstalledApp = ctx.FilePath.StartsWith(@"C:\Program Files\", StringComparison.OrdinalIgnoreCase) ||
                                  ctx.FilePath.StartsWith(@"C:\Program Files (x86)\", StringComparison.OrdinalIgnoreCase);
            bool expectsNetwork =
                isInstalledApp ||
                MapToData._trustedUserApps.Any(t => Path.GetFileNameWithoutExtension(t) == lowerNameNoExt) ||
                MapToData._trustedSystem.Any(t => Path.GetFileNameWithoutExtension(t) == lowerNameNoExt);

            yield return Check("Unexpected Network Connections",
                ctx.HasNetworkConns && !expectsNetwork,
                ThreatImpact.Suspicious, $"{ctx.NetworkConnCount} active connection(s) on a non-network process.");


            bool parentAlsoHasDebug = false;
            try
            {
                if (ctx.ParentProcess != "UNKNOWN")
                {
                    using var parentSearcher = new ManagementObjectSearcher(
                        $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {profile.ProcessId}");
                    foreach (ManagementObject row in parentSearcher.Get())
                    {
                        int ppid = (int)(uint)row["ParentProcessId"];
                        if (ppid > 0 && ppid != profile.ProcessId)
                        {
                            try
                            {
                                using var parentProc = Process.GetProcessById(ppid);
                                parentAlsoHasDebug = CheckDebugPrivilege(parentProc.Handle);
                            }
                            catch { }
                        }
                    }
                }
            }
            catch { }

            bool hasCredentialActivity = events.Any(e =>
                e.EventType is "LsassAccess" or "DPAPI_Decrypt" ||
                e.Category is "credential_file_access" or "registry_credential_access" or "lsass_access");

            ThreatImpact debugImpact;
            string debugReason;
            if (ctx.HasDebugPriv && !parentAlsoHasDebug)
            {
                // Process acquired the privilege itself — always alarming
                debugImpact = ThreatImpact.Malicious;
                debugReason = "SeDebugPrivilege active and NOT inherited from parent — process explicitly enabled it.";
            }
            else if (ctx.HasDebugPriv && hasCredentialActivity)
            {
                // Inherited but paired with credential theft — still Malicious
                debugImpact = ThreatImpact.Malicious;
                debugReason = "SeDebugPrivilege active with credential access events — regardless of inheritance, this combination is a strong indicator.";
            }
            else if (ctx.HasDebugPriv && parentAlsoHasDebug)
            {
                // Inherited from admin parent, no credential activity — normal for dev tools
                debugImpact = ThreatImpact.Inconclusive;
                debugReason = $"SeDebugPrivilege active but inherited from parent '{ctx.ParentProcess}' (also has it) — common on admin accounts.";
            }
            else
            {
                debugImpact = ThreatImpact.Suspicious;
                debugReason = "SeDebugPrivilege active — allows reading any process memory including LSASS.";
            }

            yield return Check("SeDebugPrivilege Enabled",
                ctx.HasDebugPriv,
                debugImpact, debugReason);

            bool isKnownSystemBinary = MapToData._trustedSystem.Any(t =>
                Path.GetFileNameWithoutExtension(t) == lowerNameNoExt);

            yield return Check("Unexpected Elevation",
                ctx.IsElevated && !isKnownSystemBinary && !ctx.IsSigned,
                ThreatImpact.Suspicious, "Running elevated but not a recognised system binary.");

            yield return Check("Headless Console App",
                ctx.IsConsoleApp && ctx.ThreadCount <= 4,
                ThreatImpact.Inconclusive, "Minimal-thread console process with no window.");

            bool immediatelyActive = ctx.UptimeSeconds < 2.0 && events.Count > 10;
            yield return Check("Immediate High Activity on Spawn",
                immediatelyActive,
                ThreatImpact.Inconclusive, $"{events.Count} events within {ctx.UptimeSeconds:F1}s of starting.");
        }

        private static IEnumerable<SemanticCheck> CheckVelocityAndDensity(List<SuspiciousEvent> events)
        {
            if (!events.Any()) yield break;

            var sessionStart = events.Min(e => e.Timestamp);
            var sessionEnd = events.Max(e => e.LastSeen);
            double sessionSecs = Math.Max((sessionEnd - sessionStart).TotalSeconds, 1.0);
            int totalAttempts = events.Sum(e => e.AttemptCount);
            double overallRate = totalAttempts / sessionSecs;

            yield return Check("High Overall Event Rate",
                overallRate > 50,
                ThreatImpact.Inconclusive, $"{totalAttempts} events in {sessionSecs:F1}s = {overallRate:F0}/sec.");

            yield return Check("Moderate Automated Rate",
                overallRate > 10 && overallRate <= 50,
                ThreatImpact.Inconclusive, $"{overallRate:F0} events/sec.");

            foreach (var ev in events)
            {
                double dur = Math.Max((ev.LastSeen - ev.Timestamp).TotalSeconds, 1.0);
                double rate = ev.AttemptCount / dur;
                if (rate > 15 && ev.AttemptCount >= 30)
                {
                    yield return Check("Single-Rule High Velocity",
                        true,
                        ThreatImpact.Suspicious, $"Rule '{ev.MatchedIndicator}' hit {ev.AttemptCount}x in {dur:F1}s ({rate:F0}/sec).");
                    yield break;
                }
            }

            int distinctIndicators = events.Select(e => e.MatchedIndicator).Distinct().Count();

            yield return Check("Broad System Scanning (8+ areas)",
                distinctIndicators >= 8,
                ThreatImpact.Suspicious, $"{distinctIndicators} distinct indicators hit.");

            yield return Check("Moderate System Scanning (4–7 areas)",
                distinctIndicators >= 4 && distinctIndicators < 8,
                ThreatImpact.Inconclusive, $"{distinctIndicators} distinct indicators.");
        }

        private static IEnumerable<SemanticCheck> CheckSystemAreaFootprint(List<SuspiciousEvent> events)
        {
            var areas = new HashSet<string>();

            foreach (var ev in events)
            {
                string raw = (ev.RawData ?? "").ToLower();
                string ind = (ev.MatchedIndicator ?? "").ToLower();

                if (raw.Contains("\\credentials\\") || raw.Contains("\\protect\\") ||
                    raw.Contains("\\vault\\") || ind.Contains("credential"))
                    areas.Add("WindowsCredentialStore");

                if (raw.Contains("\\google\\chrome\\") || raw.Contains("\\mozilla\\") ||
                    raw.Contains("\\microsoft\\edge\\") || raw.Contains("\\brave\\"))
                    areas.Add("BrowserCredentials");

                if (ev.EventType == "Registry" &&
                    (ind.Contains("vnc") || ind.Contains("putty") || ind.Contains("intelliforms")))
                    areas.Add("ThirdPartyCredentials");

                if (ev.EventType == "Registry" &&
                    (raw.Contains("currentversion\\run") || raw.Contains("winlogon") ||
                     raw.Contains("\\services")))
                    areas.Add("PersistenceMechanisms");

                if (raw.Contains("amsi") || raw.Contains("image file execution options"))
                    areas.Add("DefenseTools");

                if (raw.Contains("\\public\\") || raw.Contains("\\perflogs\\") ||
                    raw.Contains("\\fonts\\") || raw.Contains("\\$recycle.bin\\"))
                    areas.Add("UnusualWriteLocations");

                if (ev.EventType == "NetworkConnect" || ev.EventType == "DNS_Query")
                    areas.Add("NetworkCommunication");

                if (ev.EventType is "ProcessSpawn" or "BlacklistedProcess"
                    or "SuspiciousCommand" or "DiscoverySpawn")
                    areas.Add("ProcessExecution");

                if (ev.EventType == "DPAPI_Decrypt")
                    areas.Add("DPAPIDecryption");
            }

            bool hasNetwork = events.Any(e => e.EventType == "NetworkConnect" || e.EventType == "DNS_Query");
            bool contextIsExec = events
                .Where(e => e.EventType == "ContextSignal")
                .Any(e =>
                {
                    string ext = Path.GetExtension(e.RawData ?? "").ToLowerInvariant();
                    return ext is ".exe" or ".dll" or ".bat" or ".ps1" or ".vbs" or ".cmd";
                });
            if (events.Any(e => e.EventType == "ContextSignal") && (hasNetwork || contextIsExec))
                areas.Add("UnusualWriteLocations");

            yield return Check("Credentials Store Access",
                areas.Contains("WindowsCredentialStore"),
                ThreatImpact.Malicious, "Accessed Windows Credential Manager / DPAPI storage.");

            yield return Check("Browser Credential Access",
                areas.Contains("BrowserCredentials"),
                ThreatImpact.Malicious, "Accessed browser profile directories with saved passwords/cookies.");

            yield return Check("Third-Party Credential Stores",
                areas.Contains("ThirdPartyCredentials"),
                ThreatImpact.Malicious, "Accessed VNC/PuTTY/SSH registry keys that store credentials.");

            yield return Check("Modifying Persistence Mechanisms",
                areas.Contains("PersistenceMechanisms"),
                ThreatImpact.Suspicious, "Touched registry paths used for persistent execution.");

            yield return Check("Defense Tool Tampering",
                areas.Contains("DefenseTools"),
                ThreatImpact.Malicious, "Accessed AMSI or IFEO registry keys.");

            yield return Check("DPAPI Decryption Activity",
                areas.Contains("DPAPIDecryption"),
                ThreatImpact.Malicious, "Invoked DPAPI decryption on browser credential storage.");

            int areaCount = areas.Count;
            int weightedAreaScore = 0;
            var highValue = MapToData._areaWeights?.high_value ?? new();
            var mediumValue = MapToData._areaWeights?.medium_value ?? new();
            foreach (var area in areas)
            {
                if (highValue.Contains(area)) weightedAreaScore += 12;
                else if (mediumValue.Contains(area)) weightedAreaScore += 6;
                else weightedAreaScore += 2;
            }

            yield return Check("High Cross-System Area Coverage",
                areaCount >= 4,
                ThreatImpact.Suspicious,
                $"Touched {areaCount} distinct sensitive system areas: {string.Join(", ", areas)}.");
        }

        private static IEnumerable<SemanticCheck> CheckTemporalAnomalies(
            List<SuspiciousEvent> events, ProcessContext ctx)
        {
            if (events.Count < 2) yield break;

            var ordered = events.OrderBy(e => e.Timestamp).ToList();
            var first = ordered.First().Timestamp;
            var last = ordered.Last().LastSeen;
            double totalSpan = Math.Max((last - first).TotalSeconds, 1.0);

            yield return Check("All Activity in <2 Second Burst",
                totalSpan < 2.0 && events.Count > 3,
                ThreatImpact.Suspicious, $"{events.Count} event types in {totalSpan:F2}s.");

            var recentWindow = ordered.Where(e => (e.Timestamp - first).TotalSeconds <= 5.0).ToList();
            var tacticDiversity = recentWindow
                .Where(e => !string.IsNullOrEmpty(e.Category))
                .Select(e => e.Category)
                .Distinct()
                .Count();

            yield return Check("Multi-Tactic Activity in 5s Window",
                tacticDiversity >= 3,
                ThreatImpact.Suspicious, $"{tacticDiversity} different tactics in first 5 seconds.");

            long totalAttempts = events.Sum(e => (long)e.AttemptCount);
            yield return Check("Massive Attempt Count for Short Runtime",
                ctx.UptimeSeconds < 60 && totalAttempts > 1000,
                ThreatImpact.Suspicious, $"{totalAttempts} attempts in {ctx.UptimeSeconds:F0}s.");
        }

        private static IEnumerable<SemanticCheck> CheckContextFolderBehavior(
            ProcessContext ctx, List<SuspiciousEvent> events, ProcessProfile profile)
        {
            var contextEvents = events.Where(e => e.EventType == "ContextSignal").ToList();
            if (!contextEvents.Any()) yield break;

            string nameNoExt = Path.GetFileNameWithoutExtension(
                profile.ProcessName?.ToLowerInvariant() ?? "");
            bool isUnsigned = !ctx.IsSigned;

            var execWrites = new List<SuspiciousEvent>();
            foreach (var e in contextEvents)
            {
                string file = Path.GetFileName(e.RawData ?? "").ToLowerInvariant();
                bool isExecutable = MapToData._executableExtensions.Contains(Path.GetExtension(file));
                bool isBenign = MapToData._benignDropPrefixes.Any(pfx => file.StartsWith(pfx));
                if (isExecutable && !isBenign)
                    execWrites.Add(e);
            }

            yield return Check("Executable Dropped to Staging Folder",
                execWrites.Any(),
                ThreatImpact.Inconclusive,
                $"{execWrites.Count} executable/script file(s) written to staging path" +
                (isUnsigned ? " by an unsigned process" : "") + ": " +
                string.Join(", ", execWrites.Take(3).Select(e => Path.GetFileName(e.RawData ?? "?"))));

            var harvestKeywords = new[] {
                "dump", "loot", "creds", "output", "pass", "hash", "ntlm",
                "shadow", "sam_", "stolen", "harvest", "exfil", "data_out",
                "results", "grabbed", "pwned", "leaked"
            };
            var harvestWrites = contextEvents
                .Where(e =>
                {
                    string fn = Path.GetFileNameWithoutExtension(e.RawData ?? "").ToLowerInvariant();
                    return harvestKeywords.Any(k => fn.Contains(k));
                }).ToList();

            yield return Check("Credential Harvest File Staged",
                harvestWrites.Any(),
                ThreatImpact.Malicious,
                $"File(s) with harvest-indicating names written to staging path: " +
                string.Join(", ", harvestWrites.Take(3).Select(e => Path.GetFileName(e.RawData ?? "?"))));

            DateTime earliestCredAccess = DateTime.MaxValue;
            int credEventsCount = 0;

            // Step 1: Did the process access credential/sensitive files?
            foreach (var e in events)
            {
                bool isCredentialAccess = e.Category is "credential_file_access" or "registry_credential_access" or "lsass_access";
                
                if (!isCredentialAccess && e.EventType == "SensitiveDirAccess")
                {
                    string rawData = (e.RawData ?? "").ToLowerInvariant();
                    if (rawData.Contains(@"\protect\") || rawData.Contains(@"\credentials\") || rawData.Contains(@"\vault\"))
                    {
                        isCredentialAccess = true;
                    }
                }

                if (isCredentialAccess)
                {
                    credEventsCount++;
                    if (e.Timestamp < earliestCredAccess)
                    {
                        earliestCredAccess = e.Timestamp;
                    }
                }
            }

            DateTime earliestStaging = DateTime.MaxValue;
            int stagingAfterCredsCount = 0;

            // Step 2: Did staging writes happen AFTER credential access?
            if (credEventsCount > 0)
            {
                foreach (var e in contextEvents)
                {
                    if (e.Timestamp >= earliestCredAccess)
                    {
                        stagingAfterCredsCount++;
                        if (e.Timestamp < earliestStaging)
                        {
                            earliestStaging = e.Timestamp;
                        }
                    }
                }
            }

            int networkAfterStagingCount = 0;

            // Step 3: Did outbound network activity happen AFTER staging?
            if (stagingAfterCredsCount > 0)
            {
                foreach (var e in events)
                {
                    if (e.EventType == "NetworkConnect" || e.EventType == "DNS_Query")
                    {
                        if (e.Timestamp >= earliestStaging)
                        {
                            networkAfterStagingCount++;
                        }
                    }
                }
            }

            bool fullChain = credEventsCount > 0 && stagingAfterCredsCount > 0 && networkAfterStagingCount > 0;
            bool partialChain = credEventsCount > 0 && stagingAfterCredsCount > 0 && networkAfterStagingCount == 0;

            string timeString = earliestCredAccess == DateTime.MaxValue ? "N/A" : earliestCredAccess.ToString("HH:mm:ss");

            yield return Check("Exfiltration Chain: Collect → Stage → Exfil",
                fullChain,
                ThreatImpact.Malicious,
                $"Complete exfiltration chain detected: " +
                $"credential access ({credEventsCount} event(s)) at {timeString} → " +
                $"staging write ({stagingAfterCredsCount} file(s)) → " +
                $"outbound network ({networkAfterStagingCount} connection(s)). " +
                $"Data theft pattern confirmed.",
                isHardIndicator: true);

            yield return Check("Exfiltration Chain: Collect → Stage (No Exfil Yet)",
                partialChain,
                ThreatImpact.Suspicious,
                $"Partial exfiltration chain: credential access ({credEventsCount} event(s)) " +
                $"followed by staging write ({stagingAfterCredsCount} file(s)) — " +
                $"data gathered but not yet sent out.");

            var programDataWrites = contextEvents
                .Where(e => (e.RawData ?? "").ToLowerInvariant().Contains(@"c:\programdata\"))
                .ToList();

            bool writesToUnrelatedProgramData = programDataWrites.Any(e =>
            {
                string path = (e.RawData ?? "").ToLowerInvariant();
                return !path.Contains(nameNoExt)
                    && !path.Contains("microsoft")
                    && !path.Contains("windows");
            });

            yield return Check("Unsigned Write to Unrelated ProgramData Folder",
                isUnsigned && writesToUnrelatedProgramData,
                ThreatImpact.Suspicious,
                $"Unsigned process '{profile.ProcessName}' wrote to a ProgramData subfolder " +
                $"unrelated to its own name — possible persistence or payload staging.");

            var contextPaths = MapToData._contextSignalPaths ?? new List<string>();
            var touchedContextFolders = contextPaths
                .Where(cp => contextEvents.Any(e =>
                    (e.RawData ?? "").ToLowerInvariant().Contains(cp)))
                .ToList();

            yield return Check("Multiple Staging Locations Used",
                touchedContextFolders.Count >= 2,
                ThreatImpact.Suspicious,
                $"Process touched {touchedContextFolders.Count} distinct staging locations: " +
                string.Join(", ", touchedContextFolders));
        }

        private static IEnumerable<SemanticCheck> CheckExecutableDrops(
            ProcessContext ctx, List<SuspiciousEvent> events, ProcessProfile profile)
        {
            if (profile.ExeDropPaths.IsEmpty) yield break;

            string nameNoExt = Path.GetFileNameWithoutExtension(
                profile.ProcessName?.ToLowerInvariant() ?? "");

            var suspiciousPaths = profile.ExeDropPaths.Keys
                .Where(IsSuspiciousDropPath)
                .Where(p => !IsSelfUpdate(p, nameNoExt))
                .Where(p =>
                {
                    if (profile.DirectorySnapshotBefore != null &&
                        profile.DirectorySnapshotBefore.Files.ContainsKey(p))
                        return false;

                    if (File.Exists(p) && SystemDiscovery.VerifyFileSignature(p))
                        return false;

                    return true;
                })
                .ToList();

            if (!suspiciousPaths.Any()) yield break;

            var binaryExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".scr", ".pif", ".com", ".msi" };

            var binaryPaths = suspiciousPaths.Where(p => binaryExts.Contains(Path.GetExtension(p))).ToList();
            var scriptPaths = suspiciousPaths.Where(p =>
            {
                var ext = Path.GetExtension(p);
                return MapToData._executableExtensions.Contains(ext) && !binaryExts.Contains(ext);
            }).ToList();

            var binaryExtsFound = binaryPaths.Select(p => Path.GetExtension(p).ToLowerInvariant()).Distinct();
            var scriptExtsFound = scriptPaths.Select(p => Path.GetExtension(p).ToLowerInvariant()).Distinct();

            yield return Check("Executable Binary Dropped",
                binaryPaths.Any(),
                ThreatImpact.Malicious,
                $"{binaryPaths.Count} binary file(s) ({string.Join(", ", binaryExtsFound)}) written to staging/user-writable path" +
                (!ctx.IsSigned ? " by unsigned process" : "") + ": " +
                string.Join(", ", binaryPaths.Take(3).Select(p => Path.GetFileName(p))));

            yield return Check("Script File Dropped",
                scriptPaths.Any(),
                ThreatImpact.Suspicious,
                $"{scriptPaths.Count} script file(s) ({string.Join(", ", scriptExtsFound)}) written to staging/user-writable path" +
                (!ctx.IsSigned ? " by unsigned process" : "") + ": " +
                string.Join(", ", scriptPaths.Take(3).Select(p => Path.GetFileName(p))));

            int totalDrops = binaryPaths.Count + scriptPaths.Count;
            yield return Check("Multiple Executables Dropped",
                totalDrops >= 3,
                ThreatImpact.Malicious,
                $"{totalDrops} executable/script files dropped to staging locations in a single session.");
        }

        private static IEnumerable<SemanticCheck> CheckFileChurnBehavior(
            ProcessContext ctx, ProcessProfile profile)
        {
            int writes = profile.TotalFileWrites;
            int deletes = profile.TotalFileDeletes;
            int total = writes + deletes;

            double runtime = Math.Max(ctx.UptimeSeconds, 1.0);
            double churnRate = total / runtime;

            yield return Check("High File Create-Delete Churn",
                deletes >= 5 && churnRate > 10,
                ThreatImpact.Suspicious,
                $"{writes} writes + {deletes} deletes ({churnRate:F0} ops/sec) — rapid file staging/unpacking pattern.");

            yield return Check("Excessive File Deletion",
                deletes >= 20,
                ThreatImpact.Suspicious,
                $"{deletes} files deleted — bulk cleanup or anti-forensic activity.");
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

            yield return Check("Write Directory Scatter (3+ locations)",
                topDirs.Count >= 3 && topDirs.Count < 5,
                ThreatImpact.Inconclusive,
                $"Wrote to {topDirs.Count} distinct directory trees: {string.Join(", ", topDirs.Take(5))}.");

            yield return Check("Wide Write Directory Scatter (5+ locations)",
                topDirs.Count >= 5,
                ThreatImpact.Suspicious,
                $"Wrote to {topDirs.Count} distinct directory trees — payload distribution pattern: {string.Join(", ", topDirs.Take(6))}.");
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
                string lowerChild = spawn.Name.ToLowerInvariant();
                string lowerCmd = spawn.CommandLine.ToLowerInvariant();

                if (!lowerChild.Contains("cmd") && !lowerChild.Contains("powershell") && !lowerChild.Contains("pwsh"))
                    continue;

                bool hasDeleteVerb = lowerCmd.Contains("del ") || lowerCmd.Contains("del \"") ||
                                     lowerCmd.Contains("erase ") || lowerCmd.Contains("remove-item") ||
                                     lowerCmd.Contains("rm ") || lowerCmd.Contains("rd /s") || lowerCmd.Contains("rmdir");
                bool referencesOwn = (ownPath != "unknown" && lowerCmd.Contains(ownPath)) || (ownName.Length > 3 && lowerCmd.Contains(ownName));
                bool hasDelayAndDelete = (lowerCmd.Contains("ping") || lowerCmd.Contains("timeout") || lowerCmd.Contains("choice")) && hasDeleteVerb;

                if (hasDeleteVerb && (referencesOwn || hasDelayAndDelete))
                    return spawn.CommandLine;
            }
            return null;
        }

        private static IEnumerable<SemanticCheck> CheckSelfDeletion(
            ProcessContext ctx, ProcessProfile profile)
        {
            string ownPath = (ctx.FilePath ?? "UNKNOWN").ToLowerInvariant();
            string ownName = Path.GetFileName(ownPath);

            string? selfDeleteCmd = FindSelfDeleteCommand(profile.SpawnedCommandLines, ownPath, ownName);

            yield return Check("Process Self-Deletion",
                selfDeleteCmd != null,
                ThreatImpact.Malicious,
                $"Process spawned shell command to delete its own executable: '{selfDeleteCmd?.Substring(0, Math.Min(selfDeleteCmd.Length, 80))}'",
                isHardIndicator: true);

            var deletedExes = profile.DeletedPaths
                .Where(p => MapToData._executableExtensions.Contains(Path.GetExtension(p)))
                .Where(p =>
                {
                    var fn = Path.GetFileName(p).ToLowerInvariant();
                    return !MapToData._benignDropPrefixes.Any(pfx => fn.StartsWith(pfx));
                })
                .ToList();

            bool deletedSelf = ownPath != "unknown" && profile.DeletedPaths
                .Any(p => p.ToLowerInvariant() == ownPath);

            yield return Check("Own Binary Deleted",
                deletedSelf,
                ThreatImpact.Malicious,
                $"Process deleted its own executable at '{ctx.FilePath}' — anti-forensic self-destruction.");

            yield return Check("Executable File Deleted",
                deletedExes.Any() && !deletedSelf,
                ThreatImpact.Malicious,
                $"{deletedExes.Count} executable file(s) deleted: {string.Join(", ", deletedExes.Take(3).Select(p => Path.GetFileName(p)))}",
                isHardIndicator: true);
        }

        private static bool HasBehavioralRedFlag(ProcessProfile profile, ProcessContext ctx)
        {
            string processNameNoExt = Path.GetFileNameWithoutExtension(
                profile.ProcessName?.ToLowerInvariant() ?? "");

            // Only flag exe drops to STAGING paths (not Program Files, node_modules, etc.)
            // Exclude self-updates: if the dropped filename contains the process's own name, it's an auto-updater
            if (profile.ExeDropPaths != null && profile.ExeDropPaths.Keys.Any(p =>
                IsSuspiciousDropPath(p) && !IsSelfUpdate(p, processNameNoExt)))
                return true;

            if (profile.DeletedPaths != null)
            {
                foreach (string p in profile.DeletedPaths)
                {
                    string fn = Path.GetFileName(p).ToLowerInvariant();
                    bool isExe = MapToData._executableExtensions.Contains(Path.GetExtension(p));
                    bool isBenign = MapToData._benignDropPrefixes.Any(pfx => fn.StartsWith(pfx));
                    // Only flag deleted executables in staging paths
                    if (isExe && !isBenign && IsSuspiciousDropPath(p))
                        return true;
                }
            }

            if (profile.SpawnedCommandLines != null)
            {
                foreach (var spawn in profile.SpawnedCommandLines)
                {
                    if (string.IsNullOrEmpty(spawn.CommandLine)) continue;
                    string cl = spawn.CommandLine.ToLowerInvariant();
                    bool hasDelete = cl.Contains("del ") || cl.Contains("remove-item") || cl.Contains("rmdir") || cl.Contains("rd /s");
                    bool hasDelay = (cl.Contains("ping") || cl.Contains("timeout") || cl.Contains("choice")) && cl.Contains("del");
                    if (hasDelete || hasDelay)
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
            yield return Check("LSASS Memory Access",
                events.Any(e => e.EventType == "LsassAccess"),
                ThreatImpact.Malicious, "Process opened LSASS memory — credential dumping technique (Mimikatz/procdump pattern).");

            yield return Check("Remote Thread Injection",
                events.Any(e => e.EventType == "RemoteThreadInjection"),
                ThreatImpact.Malicious, "Process created a remote thread in another process — classic code injection.");

            yield return Check("Process Tampering Detected",
                events.Any(e => e.EventType == "ProcessTampering"),
                ThreatImpact.Malicious, "Sysmon detected process image replacement — process hollowing or herpaderping.");
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
                if (VerifyAuthenticode(ctx.FilePath))
                {
                    ctx.IsSigned = true;
                    string? publisher = ExtractPublisherName(ctx.FilePath);
                    ctx.SignerName = publisher ?? "Unknown Publisher (signed)";
                    ctx.IsTrustedPublisher = publisher != null
                        && MapToData._trustedPublishers.Contains(publisher);
                }
            }
            catch { ctx.IsSigned = false; }
        }

        private static ProcessContext GatherSystemContext(int pid, string processName)
        {
            var ctx = new ProcessContext();

            // Try to retrieve ETW-captured image path as a fallback for dead processes
            string? etwImagePath = null;
            if (MapToData.ActiveProfiles.TryGetValue(pid, out var existingProfile))
                etwImagePath = existingProfile.ImagePath; // exact filepath as it was recorded

            try
            {
                // STEP 1: Interrogator hooks into the live process to extract facts
                using var proc = Process.GetProcessById(pid);

                // STEP 2: Basic Identity & Resources
                // Example Chrome: "C:\Program Files\Google\Chrome\Application\chrome.exe"
                ctx.FilePath = proc.MainModule?.FileName ?? "UNKNOWN";
                // Example Chrome: holds 850 open files/registry keys and uses 245MB RAM
                ctx.HandleCount = proc.HandleCount;
                ctx.WorkingSetMB = proc.WorkingSet64 / (1024 * 1024);
                // Example Chrome: actively crunching data for 12.4 CPU seconds, spread across 42 threads
                ctx.CpuTimeSeconds = proc.TotalProcessorTime.TotalSeconds;
                ctx.ThreadCount = proc.Threads.Count;
                ctx.ProcessStartTime = proc.StartTime;
                ctx.UptimeSeconds = (DateTime.Now - proc.StartTime).TotalSeconds;

                // STEP 3: Cryptography & Path Validation
                ctx.IsSuspiciousPath = IsSuspiciousPath(ctx.FilePath); // e.g. False (Program Files is safe)
                PopulateSignatureInfo(ctx); // e.g. Valid digital signature from "Google LLC"

                // STEP 4: Family Tree / Ancestry
                ctx.AncestorChain = BuildAncestorChain(pid); // e.g. ["explorer"]
                ctx.ParentProcess = ctx.AncestorChain.FirstOrDefault() ?? "UNKNOWN";
                
                // Check if the parent is known malware
                ctx.ParentIsSuspicious = ctx.AncestorChain.Any(a =>
                    MapToData._blacklistedProcesses.Contains(a.ToLower()) ||
                    MapToData._blacklistedProcesses.Contains(a.ToLower() + ".exe"));

                // Get parent's specific file path and check if the parent is digitally signed
                (ctx.ParentFilePath, ctx.ParentIsTrustedPublisher) = GetParentContext(pid);
                if (ctx.ParentProcess == "UNKNOWN")
                {
                    ctx.ParentIsTrustedPublisher = ctx.IsTrustedPublisher;
                    ctx.ParentFilePath = ctx.FilePath;
                }

                // STEP 5: GUI Profiling (Is it hidden?)
                using var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (ManagementObject obj in searcher.Get())
                    try { ctx.IsConsoleApp = obj["WindowStyle"]?.ToString() == "0"; } catch { } // "0" usually means hidden headless console

                // STEP 6: Network Connections 
                try
                {
                    using var netSearcher = new ManagementObjectSearcher(
                        @"root\StandardCimv2",
                        $"SELECT * FROM MSFT_NetTCPConnection WHERE OwningProcess = {pid}");
                    var conns = netSearcher.Get();
                    ctx.NetworkConnCount = conns.Count; // e.g. Chrome has 22 open internet connections
                    ctx.HasNetworkConns = ctx.NetworkConnCount > 0;
                }
                catch { }

                // STEP 7: Check for dangerous memory-reading rights (used to steal LSASS passwords)
                ctx.HasDebugPriv = CheckDebugPrivilege(proc.Handle);
            }
            catch { }

            if (ctx.FilePath == "UNKNOWN" && !string.IsNullOrEmpty(etwImagePath)) // saves a backup image in case proces exits too fast
            {
                ctx.FilePath = etwImagePath;
                ctx.ProcessExited = true;
                ctx.IsSuspiciousPath = IsSuspiciousPath(ctx.FilePath);

                if (File.Exists(ctx.FilePath))
                {
                    PopulateSignatureInfo(ctx);
                }
            }

            return ctx;
        }

        private static (string filePath, bool isTrustedPublisher) GetParentContext(int pid)
        {
            try
            {
                using var query = new ManagementObjectSearcher(
                    $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");

                foreach (var row in query.Get())
                {
                    // 1. Get the Parent's ID (Convert it safely to an integer)
                    int parentPid = Convert.ToInt32(row["ParentProcessId"]);
                    
                    // Ignore invalid parents
                    if (parentPid <= 0 || parentPid == pid) 
                        continue;

                    // 2. Hook onto the parent process and get its file path
                    using var parentProc = Process.GetProcessById(parentPid);
                    string path = parentProc.MainModule?.FileName ?? "";

                    if (string.IsNullOrEmpty(path)) 
                        return ("", false);

                    // 3. Assume the parent is NOT trusted by default
                    bool isTrusted = false;

                    // 4. Do a deep background check on the parent's file
                    bool hasValidSignature = VerifyAuthenticode(path);
                    
                    // 5. If the signature is valid, check who signed it
                    if (hasValidSignature)
                    {
                        string publisher = ExtractPublisherName(path);
                        
                        // If the publisher is in our trusted whitelist (e.g., Microsoft)
                        if (publisher != null && MapToData._trustedPublishers.Contains(publisher))
                        {
                            isTrusted = true;
                        }
                    }
                    
                    // 6. Return the parent's file path and whether it passed the trust check
                    return (path, isTrusted);
                }
            }
            catch { }
            return ("", false);
        }

        private static List<string> BuildAncestorChain(int pid, int maxDepth = 5)
        {
            var chain = new List<string>();
            int current = pid;

            for (int i = 0; i < maxDepth; i++)
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
                    
                    var parentProc = Process.GetProcessById(parentId);
                    chain.Add(parentProc.ProcessName);
                    
                    current = parentId;
                }
                catch { break; }
            }
            return chain;
        }

        private static bool CheckDebugPrivilege(IntPtr processHandle)
        {
            try
            {
                if (!OpenProcessToken(processHandle, TOKEN_QUERY, out IntPtr tokenHandle)) return false;
                try
                {
                    GetTokenInformation(tokenHandle, 3, IntPtr.Zero, 0, out int length);
                    IntPtr buffer = Marshal.AllocHGlobal(length);
                    try
                    {
                        if (!GetTokenInformation(tokenHandle, 3, buffer, length, out _)) return false;

                        int count = Marshal.ReadInt32(buffer);
                        for (int i = 0; i < count; i++)
                        {
                            long luidLow = Marshal.ReadInt32(buffer, 4 + i * 12);
                            uint attrs = (uint)Marshal.ReadInt32(buffer, 4 + i * 12 + 8);
                            if (luidLow == 20 && (attrs & 0x00000002) != 0) return true;
                        }
                    }
                    finally { Marshal.FreeHGlobal(buffer); }
                }
                finally { CloseHandle(tokenHandle); }
            }
            catch { }
            return false;
        }
private static SemanticCheck Check(string name, bool fired, ThreatImpact impact, string reason, bool isHardIndicator = false)
{
    var box = new SemanticCheck();
    
    box.Name = name;
    box.IsFired = fired;
    box.IsHardIndicator = isHardIndicator;

    if (fired == true)
    {
        box.Impact = impact;
        box.Reason = reason;
    }
    else
    {
        box.Impact = ThreatImpact.Safe;
        box.Reason = "";
    }

    return box;
}


        private static bool IsBlacklisted(string name, string nameNoExt) =>
            MapToData._blacklistedProcesses.Contains(name) ||
            MapToData._blacklistedProcesses.Contains(name + ".exe") ||
            MapToData._blacklistedProcesses.Any(b =>
                Path.GetFileNameWithoutExtension(b).Equals(nameNoExt, StringComparison.OrdinalIgnoreCase));

        private static string? ExtractPublisherName(string filePath)
        {
            try
            {
#pragma warning disable SYSLIB0057
                var cert = X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
                if (cert == null) return null;

                using var cert2 = new X509Certificate2(cert);
                string subject = cert2.Subject ?? "";
                foreach (var part in subject.Split(','))
                {
                    string trimmed = part.Trim();
                    if (trimmed.StartsWith("O=", StringComparison.OrdinalIgnoreCase))
                    {
                        string org = trimmed.Substring(2).Trim().Trim('"');
                        if (!string.IsNullOrWhiteSpace(org))
                            return org;
                    }
                }

                string simpleName = cert2.GetNameInfo(X509NameType.SimpleName, false);
                return string.IsNullOrWhiteSpace(simpleName) ? null : simpleName;
            }
            catch
            {
                return null;
            }
        }

        private static bool VerifyAuthenticode(string filePath)
        {
            IntPtr pFilePath = IntPtr.Zero;
            IntPtr pFile = IntPtr.Zero;
            try
            {
                pFilePath = Marshal.StringToHGlobalUni(filePath);
                var fileInfo = new WINTRUST_FILE_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                    pcwszFilePath = pFilePath,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };
                pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
                Marshal.StructureToPtr(fileInfo, pFile, false);

                Guid actionId = WintrustActionGenericVerify;
                var trust = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = 2,
                    fdwRevocationChecks = 0,
                    dwUnionChoice = 1,
                    pFile = pFile,
                    dwStateAction = 0,
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = IntPtr.Zero,
                    dwProvFlags = 0x00000010,
                    dwUIContext = 0,
                    pSignatureSettings = IntPtr.Zero
                };
                return WinVerifyTrust(IntPtr.Zero, ref actionId, ref trust) == 0;
            }
            catch { return false; }
            finally
            {
                if (pFilePath != IntPtr.Zero) Marshal.FreeHGlobal(pFilePath);
                if (pFile != IntPtr.Zero) Marshal.FreeHGlobal(pFile);
            }
        }

        private static double GetTrustMultiplier(string name, string nameNoExt)
        {
            if (MapToData._processTrustMultipliers.TryGetValue(name, out double m)) return m;
            if (MapToData._processTrustMultipliers.TryGetValue(nameNoExt, out m)) return m;
            if (MapToData._processTrustMultipliers.TryGetValue(nameNoExt + ".exe", out m)) return m;
            return 1.0;
        }
    }
}
