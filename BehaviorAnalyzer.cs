using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;

namespace Cyber_behaviour_profiling
{
    public class ChainConfirmationResult
    {
        public bool HasConfirmedChain { get; set; } = false;
        public bool HasHardIndicator  { get; set; } = false;
        public List<string> ConfirmedChains  { get; set; } = new();
        public List<string> AbsentIndicators { get; set; } = new();
    }

    public class BehaviorReport
    {
        public bool IsSuspicious { get; set; } = false;
        public int FinalScore { get; set; } = 0;
        public string Severity { get; set; } = "BENIGN";
        public List<string> DecisionReasons { get; set; } = new();
        public ChainConfirmationResult ChainResult { get; set; } = new();
        public int FiredChecks { get; set; } = 0;
        public int ObservedTacticCount { get; set; } = 0;
    }

    public class ProcessContext
    {
        public string FilePath { get; set; } = "UNKNOWN";
        public bool IsSigned { get; set; } = false;
        public bool IsTrustedPublisher { get; set; } = false;
        public bool IsSuspiciousPath { get; set; } = false;
        public string SignerName { get; set; } = "";
        public string ParentProcess { get; set; } = "UNKNOWN";
        public string ParentPath { get; set; } = "UNKNOWN";
        public bool   ParentIsSuspicious      { get; set; } = false;
        public bool   ParentIsTrustedPublisher { get; set; } = false;
        public string ParentFilePath           { get; set; } = "UNKNOWN";
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
    }

    public class SemanticCheck
    {
        public string Name { get; set; }
        public int Score { get; set; }
        public string Reason { get; set; }
        public bool IsFired { get; set; }
    }

    public static class BehaviorAnalyzer
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInfoClass,
            IntPtr tokenInfo, int tokenInfoLength, out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("wintrust.dll", SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

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

        private static readonly Guid WintrustActionGenericVerify =
            new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        private const uint TOKEN_QUERY = 0x0008;

        public static BehaviorReport Analyze(ProcessProfile profile)
        {
            var report = new BehaviorReport();
            if (profile == null || profile.EventTimeline == null || !profile.EventTimeline.Any())
                return report;

            var events = profile.EventTimeline.ToList();
            string name = profile.ProcessName?.ToLowerInvariant() ?? "";
            string nameNoExt = Path.GetFileNameWithoutExtension(name);

            if (IsBlacklisted(name, nameNoExt))
            {
                report.IsSuspicious = true;
                report.FinalScore = 999;
                report.Severity = "CRITICAL";
                report.ChainResult.HasConfirmedChain = true;
                report.ChainResult.HasHardIndicator = true;
                report.ChainResult.ConfirmedChains.Add("Blacklisted Process");
                report.DecisionReasons.Add($"[CRITICAL] '{profile.ProcessName}' is a known offensive tool.");
                return report;
            }

            ProcessContext ctx = GatherSystemContext(profile.ProcessId, profile.ProcessName);

            bool hasBehavioralRedFlag = HasBehavioralRedFlag(profile, ctx);

            if (ctx.IsSigned && ctx.IsTrustedPublisher && !ctx.IsSuspiciousPath && !ctx.ParentIsSuspicious)
            {
                bool hasHighValueEvent = events.Any(e =>
                    e.Tactic == "CredentialAccess" ||
                    e.Tactic == "CommandAndControl" ||
                    e.Tactic == "Exfiltration" ||
                    e.EventType == "BlacklistedProcess" ||
                    e.EventType == "DPAPI_Decrypt");

                if (!hasHighValueEvent && !hasBehavioralRedFlag)
                {
                    report.IsSuspicious = false;
                    report.FinalScore = 0;
                    report.Severity = "BENIGN";
                    report.DecisionReasons.Add(
                        $"[BENIGN] '{profile.ProcessName}' carries a valid Authenticode signature " +
                        $"('{ctx.SignerName}'), launched normally by '{ctx.ParentProcess}'. " +
                        $"Routine system activity suppressed.");
                    return report;
                }
            }

            var _genericShells = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "explorer", "explorer.exe", "cmd", "cmd.exe",
                "powershell", "powershell.exe", "pwsh", "pwsh.exe",
                "wscript", "wscript.exe", "cscript", "cscript.exe"
            };
            bool parentIsGenericShell = _genericShells.Contains(ctx.ParentProcess);

            if (ctx.ParentIsTrustedPublisher && !parentIsGenericShell &&
                ctx.IsSigned && !ctx.IsSuspiciousPath && !ctx.ParentIsSuspicious)
            {
                bool hasHighValueEvent = events.Any(e =>
                    e.Tactic == "CredentialAccess" ||
                    e.Tactic == "CommandAndControl" ||
                    e.Tactic == "Exfiltration" ||
                    e.EventType == "BlacklistedProcess" ||
                    e.EventType == "DPAPI_Decrypt");

                if (!hasHighValueEvent && !hasBehavioralRedFlag)
                {
                    report.IsSuspicious = false;
                    report.FinalScore   = 0;
                    report.Severity     = "BENIGN";
                    report.DecisionReasons.Add(
                        $"[SAFE] '{profile.ProcessName}' is a signed subprocess of verified signed application " +
                        $"'{ctx.ParentProcess}' ({ctx.ParentFilePath}). " +
                        $"Activity monitored but not scored — no high-value events detected.");
                    return report;
                }
            }

            bool claimsTrustedName =
                MapToData._trustedSystem.Any(t => t.Contains(nameNoExt)) ||
                MapToData._trustedUserApps.Any(t => t.Contains(nameNoExt));

            if (claimsTrustedName)
            {
                if ((ctx.FilePath != "UNKNOWN" && !ctx.IsSigned) || ctx.IsSuspiciousPath)
                {
                    report.IsSuspicious = true;
                    report.FinalScore = 999;
                    report.Severity = "CRITICAL";
                    report.DecisionReasons.Add(
                        $"{profile.ProcessName}' uses a trusted name but " +
                        (!ctx.IsSigned ? "has no valid signature" : "") +
                        (ctx.IsSuspiciousPath ? $" runs from suspicious path ({ctx.FilePath})" : "") + ".");
                    return report;
                }

                string parentLower = ctx.ParentProcess.ToLowerInvariant();
                string parentWithExt = parentLower.EndsWith(".exe") ? parentLower : parentLower + ".exe";

                bool parentOk =
                    MapToData._trustedSystem.Any(t => t == parentLower || t == parentWithExt) ||
                    MapToData._trustedUserApps.Any(t => t == parentLower || t == parentWithExt) ||
                    parentLower == "explorer" || parentLower == "svchost" || parentLower == "services" ||
                    parentLower == nameNoExt || parentLower == "unknown";

                if (parentOk && !ctx.ParentIsSuspicious)
                {
                    report.IsSuspicious = false;
                    report.FinalScore = 0;
                    report.Severity = "BENIGN";
                    report.DecisionReasons.Add(
                        $"[BENIGN] '{profile.ProcessName}' is a valid signed application launched normally by parent '{ctx.ParentProcess}'. Safely ignored to avoid false positives.");
                    return report;
                }

                report.DecisionReasons.Add($"Verified trusted process ({ctx.SignerName}), but parent '{ctx.ParentProcess}' is unrecognised. Continuing analysis.");
            }

            var checks = new List<SemanticCheck>();
            checks.AddRange(CheckBinaryProvenance(ctx, profile));
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

            var chainResult = EvaluateAttackChains(events);
            if (!chainResult.HasHardIndicator)
                chainResult.HasHardIndicator = checks.Any(c => c.IsFired &&
                    (c.Name == "Executable Binary Dropped" || c.Name == "Process Self-Deletion" || c.Name == "Executable File Deleted"));
            report.ChainResult = chainResult;

            double trustMult = GetTrustMultiplier(name, nameNoExt);

            int score = 0;
            int firedCount = 0;
            foreach (var check in checks.Where(c => c.IsFired))
            {
                if (!chainResult.HasHardIndicator && _softDrivenChecks.Contains(check.Name))
                {
                    report.DecisionReasons.Add($"  [suppressed] {check.Name}: {check.Reason} (no hard indicator present)");
                    continue;
                }

                int adj = (int)(check.Score * trustMult);
                score += adj;
                firedCount++;
                report.DecisionReasons.Add($"  [{adj:+#;-#;0}pts] {check.Name}: {check.Reason}");
            }

            if (firedCount >= 6)
            {
                int bonus = firedCount * 8;
                score += bonus;
                report.DecisionReasons.Add($"  [+{bonus}pts] Convergence: {firedCount} checks fired.");
            }
            else if (firedCount >= 3)
            {
                int bonus = firedCount * 4;
                score += bonus;
                report.DecisionReasons.Add($"  [+{bonus}pts] Partial convergence: {firedCount} checks fired.");
            }

            if (chainResult.HasConfirmedChain)
            {
                foreach (var chainName in chainResult.ConfirmedChains)
                {
                    var kcRule = MapToData._killChains
                        .FirstOrDefault(k => k.name.Equals(chainName, StringComparison.OrdinalIgnoreCase));
                    if (kcRule != null)
                    {
                        score += kcRule.bonus;
                        report.DecisionReasons.Add($"  [+{kcRule.bonus}pts] Kill Chain: {kcRule.description}");
                    }
                }
            }

            int observedTacticCount = events
                .Where(e => !string.IsNullOrEmpty(e.Tactic))
                .Select(e => e.Tactic)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();

            report.FinalScore = score;
            report.FiredChecks = firedCount;
            report.ObservedTacticCount = observedTacticCount;
            report.Severity = score >= MapToData._scoring.critical_threshold ? "CRITICAL" :
                              score >= MapToData._scoring.high_threshold     ? "HIGH"     :
                              score >= MapToData._scoring.medium_threshold   ? "MEDIUM"   :
                              score >= MapToData._scoring.low_threshold      ? "LOW"      : "BENIGN";
            report.IsSuspicious = score >= MapToData._scoring.medium_threshold;

            string grade = AttackNarrator.ToGrade(score, chainResult, firedCount, observedTacticCount);
            report.DecisionReasons.Insert(0,
                $"[VERDICT] {profile.ProcessName} (PID:{profile.ProcessId}) → " +
                $"{grade} | Score: {score} | Checks fired: {firedCount}/{checks.Count}" +
                (chainResult.HasConfirmedChain ? $" | Chains: {string.Join(", ", chainResult.ConfirmedChains)}" : "") +
                (!chainResult.HasHardIndicator ? " | No hard indicators" : ""));

            return report;
        }

        private static ChainConfirmationResult EvaluateAttackChains(List<SuspiciousEvent> events)
        {
            var result = new ChainConfirmationResult();

            var observedTactics = events
                .Where(e => !string.IsNullOrEmpty(e.Tactic))
                .Select(e => e.Tactic)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var observedEventTypes = events
                .Select(e => e.EventType)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var observedCategories = events
                .Where(e => !string.IsNullOrEmpty(e.TechniqueName))
                .Select(e => e.TechniqueId)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            result.HasHardIndicator = events.Any(IsHardIndicatorEvent);

            foreach (var chain in MapToData._confirmationChains ?? new())
            {
                bool hasRequired = chain.required_tactics?.Any(t => observedTactics.Contains(t)) == true;
                bool hasCorroboratingTactic = chain.corroborating_tactics?.Any(t => observedTactics.Contains(t)) == true;
                bool hasCorroboratingEvent  = chain.corroborating_events?.Any(e => observedEventTypes.Contains(e)) == true;

                if (hasRequired && (hasCorroboratingTactic || hasCorroboratingEvent))
                {
                    result.HasConfirmedChain = true;
                    result.ConfirmedChains.Add(chain.name);
                }
            }

            if (!observedTactics.Contains("CredentialAccess"))
                result.AbsentIndicators.Add("No credential access detected");
            if (!observedTactics.Contains("CommandAndControl") &&
                !observedEventTypes.Contains("NetworkConnect") &&
                !observedEventTypes.Contains("DNS_Query"))
                result.AbsentIndicators.Add("No network exfiltration or C2 communication detected");
            if (!observedEventTypes.Contains("DPAPI_Decrypt"))
                result.AbsentIndicators.Add("No DPAPI decryption activity");
            if (!observedEventTypes.Contains("BlacklistedProcess"))
                result.AbsentIndicators.Add("No known malicious tools spawned");
            if (!observedTactics.Contains("DefenseEvasion"))
                result.AbsentIndicators.Add("No defense evasion activity");
            if (!observedTactics.Contains("Execution") && !observedEventTypes.Contains("ProcessSpawn"))
                result.AbsentIndicators.Add("No suspicious process spawning");

            return result;
        }

        private static bool IsHardIndicatorEvent(SuspiciousEvent ev)
        {
            if (ev.Tactic is "CredentialAccess" or "CommandAndControl")
                return true;
            if (ev.EventType is "DPAPI_Decrypt" or "BlacklistedProcess" or "AccessibilityBinaryOverwrite" or "NetworkConnect" or "DNS_Query")
                return true;
            if (ev.EventType == "SensitiveDirAccess")
            {
                string raw = (ev.RawData ?? "").ToLowerInvariant();
                return raw.Contains("\\protect\\") || raw.Contains("\\credentials\\") || raw.Contains("\\vault\\");
            }
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
        };

        private static IEnumerable<SemanticCheck> CheckBinaryProvenance(ProcessContext ctx, ProcessProfile profile)
        {
            yield return Check("Unsigned Binary",
                !ctx.IsSigned && ctx.FilePath != "UNKNOWN",
                12, "No valid digital signature.");

            yield return Check("Suspicious Execution Path",
                ctx.IsSuspiciousPath,
                20, $"Running from '{ctx.FilePath}'.");

            yield return Check("Missing Binary on Disk",
                ctx.FilePath == "UNKNOWN",
                25, "Binary path not found possible process hollowing or fileless execution.");

            bool inSystemDir = ctx.FilePath.StartsWith(@"c:\windows\", StringComparison.OrdinalIgnoreCase);
            bool claimsSystemName = MapToData._trustedSystem.Any(t => t.Contains(profile.ProcessName.ToLower()));

            yield return Check("System Process Not in System32",
                claimsSystemName && !inSystemDir && ctx.FilePath != "UNKNOWN",
                30, $"Claims to be a Windows process but lives at '{ctx.FilePath}'.");
        }

        private static IEnumerable<SemanticCheck> CheckParent(ProcessContext ctx, ProcessProfile profile)
        {
            var officeApps = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
                "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                "acrord32.exe", "foxit reader.exe", "notepad.exe", "mspaint.exe"
            };

            bool badParent =
                ctx.ParentIsSuspicious ||
                MapToData._blacklistedProcesses.Contains(ctx.ParentProcess.ToLower()) ||
                MapToData._blacklistedProcesses.Contains(ctx.ParentProcess.ToLower() + ".exe");

            yield return Check("Spawned by Suspicious Parent",
                badParent,
                35, $"Parent '{ctx.ParentProcess}' is flagged.");

            yield return Check("Office App Spawned Shell/Tool",
                officeApps.Contains(ctx.ParentProcess) &&
                (profile.ProcessName.ToLower().Contains("cmd") ||
                 profile.ProcessName.ToLower().Contains("powershell") ||
                 profile.ProcessName.ToLower().Contains("wscript") ||
                 profile.ProcessName.ToLower().Contains("cscript")),
                40, $"'{ctx.ParentProcess}' spawned '{profile.ProcessName}' — macro/phishing pattern.");

            bool deepChain = ctx.AncestorChain.Count >= 4;
            bool chainHasSuspicious = ctx.AncestorChain.Any(a =>
                MapToData._blacklistedProcesses.Contains(a.ToLower()) ||
                MapToData._blacklistedProcesses.Contains(a.ToLower() + ".exe"));

            yield return Check("Deep or Tainted Ancestry Chain",
                deepChain || chainHasSuspicious,
                20, $"Ancestry: [{string.Join(" → ", ctx.AncestorChain)}]. " +
                    (chainHasSuspicious ? "Contains a flagged process." : "Unusually deep chain."));
        }

        private static IEnumerable<SemanticCheck> CheckRuntimeAnomalies(
            ProcessContext ctx, List<SuspiciousEvent> events, ProcessProfile profile)
        {
            yield return Check("Excessive Handle Count",
                ctx.HandleCount > 500,
                15, $"{ctx.HandleCount} open handles.");

            yield return Check("Disproportionate Memory Use",
                ctx.WorkingSetMB > 200 && events.Count < 5,
                12, $"{ctx.WorkingSetMB}MB with few events.");

            bool expectsNetwork = profile.ProcessName.ToLower().Contains("chrome") ||
                                  profile.ProcessName.ToLower().Contains("edge") ||
                                  profile.ProcessName.ToLower().Contains("firefox") ||
                                  profile.ProcessName.ToLower().Contains("teams") ||
                                  profile.ProcessName.ToLower().Contains("outlook");

            yield return Check("Unexpected Network Connections",
                ctx.HasNetworkConns && !expectsNetwork,
                18, $"{ctx.NetworkConnCount} active connection(s) on a non-network process.");

            yield return Check("SeDebugPrivilege Enabled",
                ctx.HasDebugPriv,
                30, "SeDebugPrivilege active — allows reading any process memory including LSASS.");

            bool isKnownSystemBinary = MapToData._trustedSystem.Any(t => profile.ProcessName.ToLower().Contains(t));

            yield return Check("Unexpected Elevation",
                ctx.IsElevated && !isKnownSystemBinary && !ctx.IsSigned,
                15, "Running elevated but not a recognised system binary.");

            yield return Check("Headless Console App",
                ctx.IsConsoleApp && ctx.ThreadCount <= 4,
                10, "Minimal-thread console process with no window.");

            bool immediatelyActive = ctx.UptimeSeconds < 2.0 && events.Count > 10;
            yield return Check("Immediate High Activity on Spawn",
                immediatelyActive,
                18, $"{events.Count} events within {ctx.UptimeSeconds:F1}s of starting.");
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
                25, $"{totalAttempts} events in {sessionSecs:F1}s = {overallRate:F0}/sec.");

            yield return Check("Moderate Automated Rate",
                overallRate > 10 && overallRate <= 50,
                12, $"{overallRate:F0} events/sec.");

            foreach (var ev in events)
            {
                double dur = Math.Max((ev.LastSeen - ev.Timestamp).TotalSeconds, 1.0);
                double rate = ev.AttemptCount / dur;
                if (rate > 15 && ev.AttemptCount >= 30)
                {
                    yield return Check("Single-Rule High Velocity",
                        true,
                        20, $"Rule '{ev.MatchedIndicator}' hit {ev.AttemptCount}x in {dur:F1}s ({rate:F0}/sec).");
                    yield break;
                }
            }

            int distinctIndicators = events.Select(e => e.MatchedIndicator).Distinct().Count();

            yield return Check("Broad System Scanning (8+ areas)",
                distinctIndicators >= 8,
                28, $"{distinctIndicators} distinct indicators hit.");

            yield return Check("Moderate System Scanning (4–7 areas)",
                distinctIndicators >= 4 && distinctIndicators < 8,
                12, $"{distinctIndicators} distinct indicators.");
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

                if (ind.Contains("vnc") || ind.Contains("putty") || ind.Contains("intelliforms"))
                    areas.Add("ThirdPartyCredentials");

                if (raw.Contains("currentversion\\run") || raw.Contains("winlogon") ||
                    raw.Contains("\\services"))
                    areas.Add("PersistenceMechanisms");

                if (raw.Contains("amsi") || raw.Contains("image file execution options"))
                    areas.Add("DefenseTools");

                if (raw.Contains("\\public\\") || raw.Contains("\\perflogs\\") ||
                    raw.Contains("\\fonts\\") || raw.Contains("\\$recycle.bin\\"))
                    areas.Add("UnusualWriteLocations");

                if (ev.EventType == "NetworkConnect" || ev.EventType == "DNS_Query")
                    areas.Add("NetworkCommunication");

                if (ev.Tactic == "Execution" || ev.EventType == "ProcessSpawn" ||
                    ev.EventType == "BlacklistedProcess")
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
                25, "Accessed Windows Credential Manager / DPAPI storage.");

            yield return Check("Browser Credential Access",
                areas.Contains("BrowserCredentials"),
                30, "Accessed browser profile directories with saved passwords/cookies.");

            yield return Check("Third-Party Credential Stores",
                areas.Contains("ThirdPartyCredentials"),
                28, "Accessed VNC/PuTTY/SSH registry keys that store credentials.");

            yield return Check("Modifying Persistence Mechanisms",
                areas.Contains("PersistenceMechanisms"),
                25, "Touched registry paths used for persistent execution.");

            yield return Check("Defense Tool Tampering",
                areas.Contains("DefenseTools"),
                35, "Accessed AMSI or IFEO registry keys.");

            yield return Check("DPAPI Decryption Activity",
                areas.Contains("DPAPIDecryption"),
                35, "Invoked DPAPI decryption on browser credential storage.");

            int areaCount = areas.Count;
            int weightedAreaScore = 0;
            var highValue   = MapToData._areaWeights?.high_value   ?? new();
            var mediumValue = MapToData._areaWeights?.medium_value ?? new();
            foreach (var area in areas)
            {
                if (highValue.Contains(area))        weightedAreaScore += 12;
                else if (mediumValue.Contains(area)) weightedAreaScore += 6;
                else                                 weightedAreaScore += 2;
            }

            yield return Check("High Cross-System Area Coverage",
                areaCount >= 4,
                weightedAreaScore,
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
                22, $"{events.Count} event types in {totalSpan:F2}s.");

            var recentWindow = ordered.Where(e => (e.Timestamp - first).TotalSeconds <= 5.0).ToList();
            var tacticDiversity = recentWindow
                .Where(e => !string.IsNullOrEmpty(e.Tactic))
                .Select(e => e.Tactic)
                .Distinct()
                .Count();

            yield return Check("Multi-Tactic Activity in 5s Window",
                tacticDiversity >= 3,
                25, $"{tacticDiversity} different tactics in first 5 seconds.");

            long totalAttempts = events.Sum(e => (long)e.AttemptCount);
            yield return Check("Massive Attempt Count for Short Runtime",
                ctx.UptimeSeconds < 60 && totalAttempts > 1000,
                20, $"{totalAttempts} attempts in {ctx.UptimeSeconds:F0}s.");
        }

        private static IEnumerable<SemanticCheck> CheckContextFolderBehavior(
            ProcessContext ctx, List<SuspiciousEvent> events, ProcessProfile profile)
        {
            var contextEvents = events.Where(e => e.EventType == "ContextSignal").ToList();
            if (!contextEvents.Any()) yield break;

            string nameNoExt = Path.GetFileNameWithoutExtension(
                profile.ProcessName?.ToLowerInvariant() ?? "");
            bool isUnsigned = !ctx.IsSigned;

            var execExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { ".exe", ".dll", ".bat", ".ps1", ".vbs", ".cmd", ".hta", ".js", ".jar", ".scr", ".pif" };

            var execWrites = contextEvents
                .Where(e => execExtensions.Contains(Path.GetExtension(e.RawData ?? "")))
                .ToList();

            yield return Check("Executable Dropped to Staging Folder",
                execWrites.Any(),
                isUnsigned ? 28 : 14,
                $"{execWrites.Count} executable/script file(s) written to staging path" +
                (isUnsigned ? " by an unsigned process" : "") + ": " +
                string.Join(", ", execWrites.Take(3).Select(e => Path.GetFileName(e.RawData ?? "?"))));

            var harvestKeywords = new[] {
                "dump", "loot", "creds", "output", "pass", "hash", "ntlm",
                "shadow", "sam_", "stolen", "harvest", "exfil", "data_out",
                "results", "grabbed", "pwned", "leaked"
            };
            var harvestWrites = contextEvents
                .Where(e => {
                    string fn = Path.GetFileNameWithoutExtension(e.RawData ?? "").ToLowerInvariant();
                    return harvestKeywords.Any(k => fn.Contains(k));
                }).ToList();

            yield return Check("Credential Harvest File Staged",
                harvestWrites.Any(),
                35,
                $"File(s) with harvest-indicating names written to staging path: " +
                string.Join(", ", harvestWrites.Take(3).Select(e => Path.GetFileName(e.RawData ?? "?"))));

            bool hasNetworkAfterStage = contextEvents.Any(ctxEv =>
                events.Any(e =>
                    (e.EventType == "NetworkConnect" || e.EventType == "DNS_Query") &&
                    e.Timestamp >= ctxEv.Timestamp));

            yield return Check("Staged File Then Network Contact",
                hasNetworkAfterStage,
                28,
                "Files written to staging folder, then outbound network activity observed — " +
                "possible dropper payload delivery or exfiltration staging.");

            var programDataWrites = contextEvents
                .Where(e => (e.RawData ?? "").ToLowerInvariant().Contains(@"c:\programdata\"))
                .ToList();

            bool writesToUnrelatedProgramData = programDataWrites.Any(e => {
                string path = (e.RawData ?? "").ToLowerInvariant();
                return !path.Contains(nameNoExt)
                    && !path.Contains("microsoft")
                    && !path.Contains("windows");
            });

            yield return Check("Unsigned Write to Unrelated ProgramData Folder",
                isUnsigned && writesToUnrelatedProgramData,
                18,
                $"Unsigned process '{profile.ProcessName}' wrote to a ProgramData subfolder " +
                $"unrelated to its own name — possible persistence or payload staging.");

            var contextPaths = MapToData._contextSignalPaths ?? new List<string>();
            var touchedContextFolders = contextPaths
                .Where(cp => contextEvents.Any(e =>
                    (e.RawData ?? "").ToLowerInvariant().Contains(cp)))
                .ToList();

            yield return Check("Multiple Staging Locations Used",
                touchedContextFolders.Count >= 2,
                20,
                $"Process touched {touchedContextFolders.Count} distinct staging locations: " +
                string.Join(", ", touchedContextFolders));
        }

        private static IEnumerable<SemanticCheck> CheckExecutableDrops(
            ProcessContext ctx, List<SuspiciousEvent> events, ProcessProfile profile)
        {
            if (!profile.ExeDropPaths.Any()) yield break;

            static bool IsSuspiciousDropPath(string path)
            {
                string lp = path.ToLowerInvariant();
                bool staging =
                    lp.Contains(@"\appdata\")     ||
                    lp.Contains(@"\temp\")         ||
                    lp.Contains(@"\programdata\") ||
                    lp.Contains(@"\users\public\") ||
                    lp.Contains(@"\windows\temp\") ||
                    lp.Contains(@"\$recycle.bin\");
                bool legitimate =
                    lp.Contains(@"\program files\")       ||
                    lp.Contains(@"\program files (x86)\") ||
                    lp.Contains(@"\windows\system32\")    ||
                    lp.Contains(@"\windows\syswow64\");
                return staging && !legitimate;
            }

            var suspiciousPaths = profile.ExeDropPaths
                .Where(IsSuspiciousDropPath)
                .ToList();

            if (!suspiciousPaths.Any()) yield break;

            var binaryExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".scr", ".pif" };
            var scriptExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".bat", ".ps1", ".cmd", ".vbs", ".hta", ".wsf" };

            var binaryPaths = suspiciousPaths.Where(p => binaryExts.Contains(Path.GetExtension(p))).ToList();
            var scriptPaths = suspiciousPaths.Where(p => scriptExts.Contains(Path.GetExtension(p))).ToList();

            var binaryExtsFound = binaryPaths.Select(p => Path.GetExtension(p).ToLowerInvariant()).Distinct();
            var scriptExtsFound = scriptPaths.Select(p => Path.GetExtension(p).ToLowerInvariant()).Distinct();

            yield return Check("Executable Binary Dropped",
                binaryPaths.Any(),
                !ctx.IsSigned ? 28 : 15,
                $"{binaryPaths.Count} binary file(s) ({string.Join(", ", binaryExtsFound)}) written to staging/user-writable path" +
                (!ctx.IsSigned ? " by unsigned process" : "") + ": " +
                string.Join(", ", binaryPaths.Take(3).Select(p => Path.GetFileName(p))));

            yield return Check("Script File Dropped",
                scriptPaths.Any(),
                !ctx.IsSigned ? 22 : 10,
                $"{scriptPaths.Count} script file(s) ({string.Join(", ", scriptExtsFound)}) written to staging/user-writable path" +
                (!ctx.IsSigned ? " by unsigned process" : "") + ": " +
                string.Join(", ", scriptPaths.Take(3).Select(p => Path.GetFileName(p))));

            int totalDrops = binaryPaths.Count + scriptPaths.Count;
            yield return Check("Multiple Executables Dropped",
                totalDrops >= 3,
                32,
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
                20,
                $"{writes} writes + {deletes} deletes ({churnRate:F0} ops/sec) — rapid file staging/unpacking pattern.");

            yield return Check("Excessive File Deletion",
                deletes >= 20,
                18,
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
                18,
                $"Wrote to {topDirs.Count} distinct directory trees: {string.Join(", ", topDirs.Take(5))}.");

            yield return Check("Wide Write Directory Scatter (5+ locations)",
                topDirs.Count >= 5,
                28,
                $"Wrote to {topDirs.Count} distinct directory trees — payload distribution pattern: {string.Join(", ", topDirs.Take(6))}.");
        }

        private static string? NormalizeToTopDir(string path)
        {
            try
            {
                var parts = path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (parts.Length >= 2)
                    return string.Join(Path.DirectorySeparatorChar.ToString(),
                        parts.Take(Math.Min(parts.Length, 3))).ToLowerInvariant();
            }
            catch { }
            return null;
        }

        private static IEnumerable<SemanticCheck> CheckSelfDeletion(
            ProcessContext ctx, ProcessProfile profile)
        {
            string ownPath = (ctx.FilePath ?? "UNKNOWN").ToLowerInvariant();
            string ownName = Path.GetFileName(ownPath);

            bool selfDeleteViaCommand = false;
            string matchedCommand = "";
            foreach ((string childName, string cmdLine) in profile.SpawnedCommandLines)
            {
                string lowerCmd = cmdLine.ToLowerInvariant();
                string lowerChild = childName.ToLowerInvariant();

                bool isShell = lowerChild.Contains("cmd") || lowerChild.Contains("powershell") || lowerChild.Contains("pwsh");
                if (!isShell) continue;

                bool hasDeleteVerb = lowerCmd.Contains("del ") || lowerCmd.Contains("del \"") ||
                                     lowerCmd.Contains("erase ") || lowerCmd.Contains("remove-item") ||
                                     lowerCmd.Contains("rm ") || lowerCmd.Contains("rd /s") ||
                                     lowerCmd.Contains("rmdir");
                bool referencesOwn = (ownPath != "unknown" && lowerCmd.Contains(ownPath)) ||
                                    (ownName.Length > 3 && lowerCmd.Contains(ownName));

                bool hasDelayPattern = (lowerCmd.Contains("ping") || lowerCmd.Contains("timeout") ||
                                        lowerCmd.Contains("choice")) && hasDeleteVerb;

                if (hasDeleteVerb && (referencesOwn || hasDelayPattern))
                {
                    selfDeleteViaCommand = true;
                    matchedCommand = cmdLine;
                    break;
                }
            }

            yield return Check("Process Self-Deletion",
                selfDeleteViaCommand,
                55,
                $"Process spawned shell command to delete its own executable: '{matchedCommand.Substring(0, Math.Min(matchedCommand.Length, 80))}'");

            var exeExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { ".exe", ".dll", ".scr", ".pif", ".bat", ".ps1", ".cmd" };

            var deletedExes = profile.DeletedPaths
                .Where(p => exeExts.Contains(Path.GetExtension(p)))
                .ToList();

            bool deletedSelf = ownPath != "unknown" && profile.DeletedPaths
                .Any(p => p.ToLowerInvariant() == ownPath);

            yield return Check("Own Binary Deleted",
                deletedSelf,
                60,
                $"Process deleted its own executable at '{ctx.FilePath}' — anti-forensic self-destruction.");

            yield return Check("Executable File Deleted",
                deletedExes.Any() && !deletedSelf,
                25,
                $"{deletedExes.Count} executable file(s) deleted: {string.Join(", ", deletedExes.Take(3).Select(p => Path.GetFileName(p)))}");
        }

        private static bool HasBehavioralRedFlag(ProcessProfile profile, ProcessContext ctx)
        {
            if (profile.ExeDropPaths != null && profile.ExeDropPaths.Any())
                return true;

            var exeExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs" };
            if (profile.DeletedPaths != null &&
                profile.DeletedPaths.Any(p => exeExts.Contains(Path.GetExtension(p))))
                return true;

            if (profile.SpawnedCommandLines != null)
            {
                string ownPath = ctx.FilePath ?? "";
                string ownName = Path.GetFileName(ownPath);
                foreach ((string _, string cmdLine) in profile.SpawnedCommandLines)
                {
                    if (string.IsNullOrEmpty(cmdLine)) continue;
                    string cl = cmdLine.ToLowerInvariant();
                    if (cl.Contains("del ") || cl.Contains("remove-item") ||
                        cl.Contains("rmdir") || cl.Contains("rd /s"))
                    {
                        return true;
                    }
                    if ((cl.Contains("ping") || cl.Contains("timeout") || cl.Contains("choice")) &&
                        (cl.Contains("del") || cl.Contains("remove")))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static ProcessContext GatherSystemContext(int pid, string processName)
        {
            var ctx = new ProcessContext();
            try
            {
                using var proc = Process.GetProcessById(pid);

                ctx.FilePath = proc.MainModule?.FileName ?? "UNKNOWN";
                ctx.HandleCount = proc.HandleCount;
                ctx.WorkingSetMB = proc.WorkingSet64 / (1024 * 1024);
                ctx.CpuTimeSeconds = proc.TotalProcessorTime.TotalSeconds;
                ctx.ThreadCount = proc.Threads.Count;
                ctx.ProcessStartTime = proc.StartTime;
                ctx.UptimeSeconds = (DateTime.Now - proc.StartTime).TotalSeconds;

                string lp = ctx.FilePath.ToLowerInvariant();
                ctx.IsSuspiciousPath =
                    lp.Contains(@"\appdata\local\temp\") ||
                    lp.Contains(@"\users\public\") ||
                    lp.Contains(@"\programdata\") ||
                    lp.Contains(@"\windows\temp\") ||
                    lp.Contains(@"\recycle.bin\");

                try
                {
                    if (VerifyAuthenticode(ctx.FilePath))
                    {
                        ctx.IsSigned = true;
                        ctx.IsTrustedPublisher = true;
                        ctx.SignerName = "Trusted Publisher (Authenticode verified)";
                    }
                    else if (ctx.FilePath.Contains(@"\program files\windowsapps\", StringComparison.OrdinalIgnoreCase))
                    {

                        ctx.IsSigned = true;
                        ctx.IsTrustedPublisher = true;
                        ctx.SignerName = "Microsoft Corporation (Windows Store App)";
                    }
                }
                catch { ctx.IsSigned = false; }

                ctx.AncestorChain = BuildAncestorChain(pid);
                ctx.ParentProcess = ctx.AncestorChain.FirstOrDefault() ?? "UNKNOWN";
                ctx.ParentIsSuspicious = ctx.AncestorChain.Any(a =>
                    MapToData._blacklistedProcesses.Contains(a.ToLower()) ||
                    MapToData._blacklistedProcesses.Contains(a.ToLower() + ".exe"));
                try
                {
                    using var parentQuery = new ManagementObjectSearcher(
                        $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");
                    foreach (ManagementObject row in parentQuery.Get().Cast<ManagementObject>())
                    {
                        int parentPid = (int)(uint)row["ParentProcessId"];
                        if (parentPid > 0 && parentPid != pid)
                        {
                            using var parentProc = Process.GetProcessById(parentPid);
                            string parentPath = parentProc.MainModule?.FileName ?? "";
                            ctx.ParentFilePath = parentPath;

                            if (!string.IsNullOrEmpty(parentPath))
                            {
                                if (VerifyAuthenticode(parentPath))
                                    ctx.ParentIsTrustedPublisher = true;
                                else if (parentPath.Contains(@"\program files\windowsapps\",
                                             StringComparison.OrdinalIgnoreCase))
                                    ctx.ParentIsTrustedPublisher = true;
                            }
                        }
                    }
                }
                catch { }

                if (ctx.ParentProcess == "UNKNOWN")
                {
                    ctx.ParentIsTrustedPublisher = ctx.IsTrustedPublisher;
                    ctx.ParentFilePath           = ctx.FilePath;
                }

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
            }
            catch { }

            return ctx;
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
                        parentId = (int)(uint)r["ParentProcessId"];

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

        private static SemanticCheck Check(string name, bool fired, int score, string reason) =>
            new() { Name = name, IsFired = fired, Score = fired ? score : 0, Reason = fired ? reason : "" };

        private static bool IsBlacklisted(string name, string nameNoExt) =>
            MapToData._blacklistedProcesses.Contains(name) ||
            MapToData._blacklistedProcesses.Contains(name + ".exe") ||
            MapToData._blacklistedProcesses.Any(b =>
                Path.GetFileNameWithoutExtension(b).Equals(nameNoExt, StringComparison.OrdinalIgnoreCase));

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
