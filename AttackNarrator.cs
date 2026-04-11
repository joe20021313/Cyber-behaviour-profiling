using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Cyber_behaviour_profiling
{
    public class NarrativeStep
    {
        public DateTime Timestamp { get; set; }
        public string Category { get; set; }
        public string Headline { get; set; }
        public string Detail { get; set; }
    }

    public class AttackNarrative
    {
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public string Grade { get; set; } = "SAFE";
        public bool HasObservedTimeline { get; set; }
        public DateTime FirstSeen { get; set; }
        public double TotalSeconds { get; set; }
        public List<NarrativeStep> Timeline { get; set; } = new();
        public List<string> DecisionReasons { get; set; } = new();
        public List<string> SafeReasons { get; set; } = new();

        public List<string> DroppedFiles { get; set; } = new();
        public List<string> RuntimeArtifactFiles { get; set; } = new();
        public List<string> DeletedFiles { get; set; } = new();
        public List<string> DeletedRuntimeArtifactFiles { get; set; } = new();
        public List<string> LaunchContext { get; set; } = new();
        public bool IsSpawnedProcess { get; set; }
        public List<SpawnedProcess> SpawnedCommands { get; set; } = new();
        public bool HasSignature { get; set; }
        public bool IsSigned { get; set; }
        public string SignerName { get; set; } = "";
        public SignatureTrustState SignatureTrustState { get; set; } = SignatureTrustState.NoSignature;
        public string SignatureSummary { get; set; } = "";
    }

    internal static class ObservedTimelineWindow
    {
        public static bool TryCompute(
            IEnumerable<SuspiciousEvent> events,
            out DateTime firstSeen,
            out DateTime lastSeen,
            out double totalSeconds)
        {
            var ordered = events
                .OrderBy(e => e.Timestamp)
                .ToList();

            if (ordered.Count == 0)
            {
                firstSeen = DateTime.MinValue;
                lastSeen = DateTime.MinValue;
                totalSeconds = 0;
                return false;
            }

            firstSeen = ordered.First().Timestamp;
            lastSeen = ordered.Max(e => e.LastSeen);
            totalSeconds = Math.Max((lastSeen - firstSeen).TotalSeconds, 0);
            return true;
        }
    }

    public static class AttackNarrator
    {
        public static bool IsHighValueCategory(string category) =>
            category is "credential_file_access" or "registry_credential_access"
                     or "lsass_access" or "dpapi_decrypt"
                     or "network_c2" or "dns_c2";

        public static string ToGrade(ThreatImpact impact) => impact switch
        {
            ThreatImpact.Malicious    => "MALICIOUS",
            ThreatImpact.Suspicious   => "SUSPICIOUS",
            ThreatImpact.Inconclusive => "INCONCLUSIVE",
            _                         => "SAFE"
        };

        public static bool IsPlaceholderNarrative(AttackNarrative? narrative) =>
            narrative != null &&
            narrative.ProcessId <= 0 &&
            narrative.Timeline.Count == 0 &&
            narrative.TotalSeconds <= 0 &&
            string.Equals(narrative.Grade, "SAFE", StringComparison.OrdinalIgnoreCase);

        public static string ResolveSignatureSummary(AttackNarrative? narrative)
        {
            if (narrative == null || string.IsNullOrWhiteSpace(narrative.SignatureSummary))
                return "Signature status unavailable.";

            return narrative.SignatureSummary;
        }

        public static AttackNarrative BuildNarrative(ProcessProfile profile, BehaviorReport report)
        {
            var events = profile.EventTimeline
                .OrderBy(e => e.Timestamp)
                .ToList();

            string grade = ToGrade(report.FinalVerdict);
            var launchContext = BuildLaunchContext(profile);
            DateTime narrativeStart = ResolveNarrativeStart(profile);


            bool isSpawned = launchContext.Count > 0;

            if (!events.Any())
                return new AttackNarrative
                {
                    ProcessName      = profile.ProcessName,
                    ProcessId        = profile.ProcessId,
                    Grade            = grade,
                    HasObservedTimeline = false,
                    FirstSeen        = narrativeStart,
                    DecisionReasons  = report.DecisionReasons,
                    SafeReasons      = report.SafeReasons,
                    DroppedFiles     = profile.ExeDropPaths.Keys.ToList(),
                    RuntimeArtifactFiles = profile.RuntimeArtifactPaths.Keys.ToList(),
                    DeletedFiles     = profile.DeletedPaths.ToList(),
                    DeletedRuntimeArtifactFiles = profile.DeletedRuntimeArtifacts.ToList(),
                    LaunchContext    = launchContext,
                    IsSpawnedProcess = isSpawned,
                    SpawnedCommands  = profile.SpawnedCommandLines.ToList(),
                    HasSignature     = report.HasSignature,
                    IsSigned         = report.IsSigned,
                    SignerName       = report.SignerName,
                    SignatureTrustState = report.SignatureTrustState,
                    SignatureSummary = report.SignatureSummary
                };

            var steps = events.Select(TranslateEvent).ToList();
            ObservedTimelineWindow.TryCompute(events, out var firstSeen, out _, out var totalSeconds);

            return new AttackNarrative
            {
                ProcessName      = profile.ProcessName,
                ProcessId        = profile.ProcessId,
                Grade            = grade,
                HasObservedTimeline = true,
                FirstSeen        = firstSeen == DateTime.MinValue ? narrativeStart : firstSeen,
                TotalSeconds     = totalSeconds,
                Timeline         = steps,
                DecisionReasons  = report.DecisionReasons,
                SafeReasons      = report.SafeReasons,
                DroppedFiles     = profile.ExeDropPaths.Keys.ToList(),
                RuntimeArtifactFiles = profile.RuntimeArtifactPaths.Keys.ToList(),
                DeletedFiles     = profile.DeletedPaths.ToList(),
                DeletedRuntimeArtifactFiles = profile.DeletedRuntimeArtifacts.ToList(),
                LaunchContext    = launchContext,
                IsSpawnedProcess = isSpawned,
                SpawnedCommands  = profile.SpawnedCommandLines.ToList(),
                HasSignature     = report.HasSignature,
                IsSigned         = report.IsSigned,
                SignerName       = report.SignerName,
                SignatureTrustState = report.SignatureTrustState,
                SignatureSummary = report.SignatureSummary
            };
        }

        public static string DescribeSpawnedCommand(string childName, string? cmdLine)
        {
            string lowerChild = (childName ?? "").ToLowerInvariant();

            var cmdMatch = MapToData.CommandRules
                .FirstOrDefault(r => MapToData.CommandLineMatchesRule(cmdLine ?? "", r.Pattern));
            if (cmdMatch != null && !string.IsNullOrEmpty(cmdMatch.Description))
                return $"{childName} — {cmdMatch.Description}";

            var discMatch = MapToData.DiscoveryRules
                .FirstOrDefault(r => lowerChild.Contains(r.Pattern));
            if (discMatch != null)
                return $"{childName} — {discMatch.Description}";

            var lolMatch = MapToData.LolbinRules
                .FirstOrDefault(r => lowerChild.Contains(r.Pattern) || r.Pattern.Contains(lowerChild));
            if (lolMatch != null)
                return $"{childName} — {lolMatch.Description}";

            return string.IsNullOrWhiteSpace(cmdLine) ? childName : cmdLine;
        }

        private static DateTime ResolveNarrativeStart(ProcessProfile profile) =>
            profile.SpawnedAt != DateTime.MinValue ? profile.SpawnedAt : profile.FirstSeen;

        private static List<string> BuildLaunchContext(ProcessProfile profile)
        {
            var context = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            void AddContext(string? parentName, int parentPid, string? commandLine)
            {
                string line = DescribeLaunchContext(parentName, parentPid, commandLine);
                if (!string.IsNullOrWhiteSpace(line) && seen.Add(line))
                    context.Add(line);
            }

            AddContext(
                profile.ParentProcessNameAtSpawn,
                profile.ParentProcessIdAtSpawn,
                profile.LaunchCommandLineAtSpawn);

            if (context.Count == 0 && profile.InheritedCommandContexts != null)
            {
                foreach (var inherited in profile.InheritedCommandContexts.OrderBy(item => item.Timestamp))
                    AddContext(inherited.ParentProcessName, inherited.ParentProcessId, inherited.CommandLine);
            }

            return context;
        }

        private static string DescribeLaunchContext(string? parentName, int parentPid, string? commandLine)
        {
            string parentLabel = string.IsNullOrWhiteSpace(parentName) ? "unknown parent" : parentName;
            string source = parentPid > 0 ? $"{parentLabel} (PID {parentPid})" : parentLabel;

            if (!string.IsNullOrWhiteSpace(commandLine))
                return $"Launched by {source}: {commandLine}";

            return string.Equals(source, "unknown parent", StringComparison.OrdinalIgnoreCase)
                ? ""
                : $"Launched by {source}";
        }

        private static NarrativeStep TranslateEvent(SuspiciousEvent ev)
        {
            var step = new NarrativeStep
            {
                Timestamp = ev.Timestamp,
                Detail = ev.RawData ?? ev.MatchedIndicator
            };

            step.Category = ev.EventType switch
            {
                "ContextSignal"                                                             => "Info",
                "FileRead" or "FileWrite" or "FileOpen" or "FileDelete" or "FileRename"
                    or "SensitiveDirAccess" or "UncommonWrite"
                    or "AccessibilityBinaryOverwrite"
                    or "Executable Drop"                                                    => "File",
                "Registry"                                                                  => "Registry",
                "NetworkConnect" or "DNS_Query"                                             => "Network",
                "ProcessSpawn" or "SuspiciousCommand" or "DiscoverySpawn"
                    or "DPAPI_Decrypt"
                    or "LsassAccess" or "RemoteThreadInjection" or "ProcessTampering"       => "Process",
                _                                                                           => "System"
            };

            step.Headline = BuildHeadline(ev, step.Category);
            return step;
        }

        private static string BuildHeadline(SuspiciousEvent ev, string category)
        {
            string raw = (ev.RawData ?? "").ToLowerInvariant();
            string ind = (ev.MatchedIndicator ?? "").ToLowerInvariant();
            string reps = RepeatSuffix(ev.AttemptCount);

            return category switch
            {
                "Info" => BuildInfoHeadline(ev, raw, ind, reps),
                "File" => BuildFileHeadline(ev, raw, ind, reps),
                "Registry" => BuildRegistryHeadline(ev, ind, reps),
                "Network" => BuildNetworkHeadline(ev, ind, reps),
                "Process" => BuildProcessHeadline(ev, ind, reps),
                _ => $"{ev.EventType}: {ShortPath(ev.RawData)}{reps}"
            };
        }

        private static string RepeatSuffix(int attemptCount) =>
            attemptCount > 1 ? $" ({attemptCount}x)" : "";

        private static string BuildInfoHeadline(SuspiciousEvent ev, string raw, string ind, string reps)
        {
            if (raw.Contains("\\temp\\") || ind.Contains("temp"))
                return $"Wrote to temp folder → '{ShortPath(ev.RawData)}'{reps}";

            return $"Context file activity → '{ShortPath(ev.RawData)}'{reps}";
        }

        private static string BuildFileHeadline(SuspiciousEvent ev, string raw, string ind, string reps)
        {
            if (ind.Contains("login data") || ind.Contains("logins.json"))
                return $"Read browser saved-password database{reps}";
            if (ind.Contains("cookies") || ind.Contains("network\\cookies"))
                return $"Read browser session cookies{reps}";
            if (ind.Contains("key4.db") || ind.Contains("cert9.db"))
                return $"Read Firefox key store{reps}";
            if (ind.Contains("local state"))
                return $"Read browser master encryption key{reps}";
            if (raw.Contains("\\protect\\"))
                return $"Accessed DPAPI credential folder{reps}";
            if (raw.Contains("\\credentials\\"))
                return $"Accessed Windows Credential Manager vault{reps}";
            if (raw.Contains("\\vault\\"))
                return $"Accessed Windows Vault{reps}";
            if (ind.Contains("sethc") || ind.Contains("utilman") || ind.Contains("osk"))
                return $"Touched accessibility binary{reps}";
            if (raw.Contains("\\fonts\\"))
                return $"Wrote to system fonts folder{reps}";
            if (raw.Contains("\\perflogs\\") || raw.Contains("\\public\\"))
                return $"Wrote to world-writable system directory{reps}";
            if (ev.EventType == "Executable Drop")
            {
                string ext = Path.GetExtension(ev.RawData ?? "");
                return $"Dropped {ext} executable{reps} → '{ev.RawData}'";
            }
            if (ev.EventType == "FileDelete")
                return $"Deleted file{reps} → '{ev.RawData}'";
            if (ev.EventType == "FileRename")
                return $"Renamed/moved file{reps} → '{ev.RawData}'";
            if (ev.EventType == "FileWrite")
                return $"Wrote file{reps} → '{ev.RawData}'";
            if (ev.EventType == "FileRead")
                return $"Read file{reps} → '{ev.RawData}'";

            return $"Opened '{ev.RawData}'{reps}";
        }

        private static string BuildRegistryHeadline(SuspiciousEvent ev, string ind, string reps)
        {
            if (ind.Contains("currentversion\\run"))
                return $"Added/modified startup Run key{reps}";
            if (ind.Contains("runonce"))
                return $"Set RunOnce key{reps}";
            if (ind.Contains("winlogon"))
                return $"Modified Winlogon key{reps}";
            if (ind.Contains("\\services"))
                return $"Modified services registry key{reps}";
            if (ind.Contains("amsi"))
                return $"Accessed AMSI key{reps}";
            if (ind.Contains("image file execution options"))
                return $"Accessed IFEO key{reps}";
            if (ind.Contains("ms-settings") || ind.Contains("classes\\exefile"))
                return $"Modified shell command handler{reps}";
            if (ind.Contains("realvnc") || ind.Contains("tightvnc"))
                return $"Read VNC credentials from registry{reps}";
            if (ind.Contains("putty"))
                return $"Read PuTTY session credentials{reps}";
            if (ind.Contains("intelliforms"))
                return $"Read IE saved form credentials{reps}";
            if (ind.Contains("wow6432node"))
                return $"Accessed 32-bit registry hive{reps}";

            return $"Accessed registry key{reps} → '{ShortKey(ev.RawData)}'";
        }

        private static string BuildNetworkHeadline(SuspiciousEvent ev, string ind, string reps)
        {
            if (ind.Contains("telegram") || ind.Contains("t.me"))
                return $"Connected to Telegram API{reps}";
            if (ind.Contains("discord"))
                return $"Connected to Discord webhook{reps}";
            if (ind.Contains("pastebin"))
                return $"Connected to Pastebin{reps}";
            if (ind.Contains("raw.githubusercontent"))
                return $"Fetched raw content from GitHub{reps}";
            if (ind.Contains("ngrok"))
                return $"Connected to ngrok tunnel{reps}";
            if (ind.Contains("transfer.sh") || ind.Contains("file.io") ||
                ind.Contains("anonfiles") || ind.Contains("gofile"))
                return $"Connected to anonymous file-sharing service{reps}";
            if (ev.EventType == "DNS_Query")
                return $"Resolved suspicious domain: '{ind}'{reps}";

            return $"Connected to '{ind}'{reps}";
        }

        private static string BuildProcessHeadline(SuspiciousEvent ev, string ind, string reps)
        {
            if (ev.EventType == "LsassAccess")
                return $"[!!!] Opened LSASS memory — credential dump attempt{reps}";
            if (ev.EventType == "RemoteThreadInjection")
                return $"[!!!] Injected remote thread into '{ind}'{reps}";
            if (ev.EventType == "ProcessTampering")
                return $"[!!!] Process image replaced — hollowing/herpaderping{reps}";
            if (ev.EventType == "DPAPI_Decrypt")
                return $"Called DPAPI to decrypt protected data{reps}";

            if (ind.Contains("del") || ind.Contains("remove-item") || ind.Contains("erase"))
                return $"[!!!] Spawned delete command{reps} → '{ShortCmd(ev.RawData)}'";
            if (ind.Contains("cmd /c copy") || ind.Contains("cmd /c move") || ind.Contains("cmd /c xcopy"))
                return $"Spawned file copy/move command{reps} → '{ShortCmd(ev.RawData)}'";
            if (ind.Contains("ping localhost") || ind.Contains("ping 127.0.0.1") ||
                ind.Contains("timeout") || ind.Contains("choice /c"))
                return $"[!!!] Delay-and-execute pattern{reps} → '{ShortCmd(ev.RawData)}'";
            if (ind.Contains("start /min") || ind.Contains("cmd /c start"))
                return $"Spawned hidden/minimized process{reps} → '{ShortCmd(ev.RawData)}'";

            if (ind.Contains("powershell") || ind.Contains("pwsh"))
                return $"Launched PowerShell{reps} → '{ShortCmd(ev.RawData)}'";
            if (ind.Contains("cmd.exe"))
                return $"Launched cmd.exe{reps} → '{ShortCmd(ev.RawData)}'";
            if (ind.Contains("wscript") || ind.Contains("cscript"))
                return $"Executed script via WSH{reps}";
            if (ind.Contains("mshta"))
                return $"Executed HTA via mshta.exe{reps}";
            if (ind.Contains("rundll32"))
                return $"Executed via rundll32{reps}";
            if (ind.Contains("regsvr32"))
                return $"Registered/executed DLL via regsvr32{reps}";
            if (ind.Contains("certutil"))
                return $"Used certutil.exe{reps}";
            if (ind.Contains("whoami") || ind.Contains("systeminfo") ||
                ind.Contains("ipconfig") || ind.Contains("net.exe"))
                return $"Ran discovery command: '{ind}'{reps}";
            if (ind.Contains("-encodedcommand") || ind.Contains("-enc "))
                return $"Executed encoded PowerShell command{reps}";
            if (ind.Contains("-nop") || ind.Contains("-exec bypass") || ind.Contains("-win hidden"))
                return $"PowerShell with bypass flags{reps}";

            return $"Spawned '{ind}'{reps} → '{ShortCmd(ev.RawData)}'";
        }

        private static string ShortPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            var parts = path.Replace('/', '\\').Split('\\');
            return parts.Length >= 2
                ? $"...\\{parts[^2]}\\{parts[^1]}"
                : path;
        }

        private static string ShortKey(string key)
        {
            if (string.IsNullOrEmpty(key)) return "";
            var parts = key.Split('\\');
            return parts.Length >= 3
                ? $"...\\{parts[^2]}\\{parts[^1]}"
                : key;
        }

        private static string ShortCmd(string cmd)
        {
            if (string.IsNullOrEmpty(cmd)) return "";
            return cmd.Length > 60 ? cmd[..57] + "..." : cmd;
        }

    }
}
