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
        public string Tactic { get; set; }
        public string Icon { get; set; }
        public string Headline { get; set; }
        public string Detail { get; set; }
        public int RepeatCount { get; set; }
    }

    public class AttackNarrative
    {
        public string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public string Grade { get; set; } = "SAFE";
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public double TotalSeconds { get; set; }
        public List<NarrativeStep> Timeline { get; set; } = new();
        public string OverallStory { get; set; }
        public List<string> AbsentIndicators { get; set; } = new();
        public List<string> AnomalyFindings { get; set; } = new();
        public List<string> DecisionReasons { get; set; } = new();
        public List<string> SafeReasons { get; set; } = new();
        public int FinalScore { get; set; }

        public List<string> DroppedFiles { get; set; } = new();
        public List<string> DeletedFiles { get; set; } = new();
        public List<(string ChildName, string CommandLine)> SpawnedCommands { get; set; } = new();
        public bool IsSigned { get; set; }
        public string SignerName { get; set; } = "";
    }

    public static class AttackNarrator
    {
        private static readonly Dictionary<string, (string Tactic, string TechniqueId, string TechniqueName)> _categoryMap =
            new(StringComparer.OrdinalIgnoreCase)
        {
            ["registry_persistence"] = ("Persistence", "T1547", "Boot or Logon Autostart Execution"),
            ["registry_defense_evasion"] = ("DefenseEvasion", "T1562", "Impair Defenses"),
            ["registry_privilege_escalation"] = ("PrivilegeEscalation", "T1548", "Abuse Elevation Control Mechanism"),
            ["registry_credential_access"] = ("CredentialAccess", "T1552", "Unsecured Credentials in Registry"),
            ["file_defense_evasion"] = ("DefenseEvasion", "T1036", "Masquerading - Suspicious Write Location"),
            ["file_persistence"] = ("Persistence", "T1546.008", "Accessibility Features"),
            ["credential_file_access"] = ("CredentialAccess", "T1555", "Credentials from Password Stores"),
            ["collection"] = ("Collection", "T1005", "Data from Local System"),
            ["context_signal"] = ("", "", ""),
            ["network_c2"] = ("CommandAndControl", "T1071", "Application Layer Protocol"),
            ["process_lolbin"] = ("Execution", "T1218", "System Binary Proxy Execution"),
            ["process_accessibility"] = ("Persistence", "T1546.008", "Accessibility Features"),
            ["process_defense_evasion"] = ("DefenseEvasion", "T1562.001", "Disable or Modify Tools"),
            ["process_discovery"] = ("Discovery", "T1082", "System Information Discovery"),
            ["process_blacklisted"] = ("Execution", "T1059", "Command and Scripting Interpreter"),
            ["dpapi_decrypt"] = ("CredentialAccess", "T1555.004", "Credentials from Windows Credential Manager"),
            ["dns_c2"] = ("CommandAndControl", "T1071", "Application Layer Protocol"),
            ["file_exe_drop"] = ("Execution", "T1105", "Ingress Tool Transfer"),
            ["network_outbound"] = ("", "", "Outbound Network Connection"),
        };

        public static (string Tactic, string TechniqueId, string TechniqueName) ResolveCategory(string category) =>
            _categoryMap.TryGetValue(category ?? "", out var r) ? r : ("", "", "");

        public static bool IsHighValueCategory(string category) =>
            ResolveCategory(category).Tactic is "CredentialAccess" or "CommandAndControl" or "Exfiltration";

        public static string ToGrade(int score) =>
            ToGrade(score, new ChainConfirmationResult());

        public static string ToGrade(int score, ChainConfirmationResult chainResult,
            int firedChecks = 0, int observedTacticCount = 0)
        {
            if (score >= MapToData._scoring.critical_threshold)
                return (chainResult.HasConfirmedChain || chainResult.HasHardIndicator) ? "MALICIOUS" : "SUSPICIOUS";

            if (score >= MapToData._scoring.review_threshold && chainResult.HasHardIndicator)
                return "SUSPICIOUS";

            if (score >= MapToData._scoring.review_threshold)
                return (observedTacticCount >= 1 || firedChecks >= 3) ? "SUSPICIOUS" : "INCONCLUSIVE";

            if (score >= MapToData._scoring.medium_threshold)
                return "INCONCLUSIVE";

            return "SAFE";
        }

        public static AttackNarrative BuildNarrative(ProcessProfile profile, BehaviorReport report)
        {
            var events = profile.EventTimeline
                .OrderBy(e => e.Timestamp)
                .ToList();

            string grade = ToGrade(report.FinalScore, report.ChainResult, report.FiredChecks, report.ObservedTacticCount);

            if (!events.Any())
                return new AttackNarrative
                {
                    ProcessName      = profile.ProcessName,
                    ProcessId        = profile.ProcessId,
                    Grade            = grade,
                    OverallStory     = ReturnVerdict(grade),
                    AbsentIndicators = report.ChainResult?.AbsentIndicators ?? new(),
                    AnomalyFindings  = report.Anomaly?.SpikedMetrics ?? new(),
                    DecisionReasons  = report.DecisionReasons,
                    SafeReasons      = report.SafeReasons,
                    FinalScore       = report.FinalScore,
                    DroppedFiles     = profile.ExeDropPaths.ToList(),
                    DeletedFiles     = profile.DeletedPaths.ToList(),
                    SpawnedCommands  = profile.SpawnedCommandLines.ToList(),
                    IsSigned         = report.IsSigned,
                    SignerName       = report.SignerName
                };

            var steps = events.Select(TranslateEvent).ToList();

            string story = grade == "SAFE"
                ? (report.DecisionReasons.FirstOrDefault(r =>
                       r.StartsWith("[BENIGN]") || r.StartsWith("[SAFE]"))
                   ?? ReturnVerdict(grade))
                : ReturnVerdict(grade);

            return new AttackNarrative
            {
                ProcessName      = profile.ProcessName,
                ProcessId        = profile.ProcessId,
                Grade            = grade,
                FirstSeen        = events.First().Timestamp,
                LastSeen         = events.Last().LastSeen,
                TotalSeconds     = (events.Last().LastSeen - events.First().Timestamp).TotalSeconds,
                Timeline         = steps,
                OverallStory     = story,
                AbsentIndicators = report.ChainResult?.AbsentIndicators ?? new(),
                AnomalyFindings  = report.Anomaly?.SpikedMetrics ?? new(),
                DecisionReasons  = report.DecisionReasons,
                SafeReasons      = report.SafeReasons,
                FinalScore       = report.FinalScore,
                DroppedFiles     = profile.ExeDropPaths.ToList(),
                DeletedFiles     = profile.DeletedPaths.ToList(),
                SpawnedCommands  = profile.SpawnedCommandLines.ToList(),
                IsSigned         = report.IsSigned,
                SignerName       = report.SignerName
            };
        }

        private static NarrativeStep TranslateEvent(SuspiciousEvent ev)
        {
            var step = new NarrativeStep
            {
                Timestamp   = ev.Timestamp,
                RepeatCount = ev.AttemptCount,
                Detail      = ev.RawData ?? ev.MatchedIndicator
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
                    or "BlacklistedProcess" or "DPAPI_Decrypt"                              => "Process",
                _                                                                           => "System"
            };

            step.Icon = step.Category switch
            {
                "File"     => "[FILE]",
                "Registry" => "[REG ]",
                "Network"  => "[NET ]",
                "Process"  => "[PROC]",
                "Info"     => "[INFO]",
                _          => "[SYS ]"
            };

            step.Tactic = ev.Tactic ?? "";
            step.Headline = BuildHeadline(ev, step.Category);
            return step;
        }

        private static string BuildHeadline(SuspiciousEvent ev, string category)
        {
            string raw  = (ev.RawData ?? "").ToLower();
            string ind  = (ev.MatchedIndicator ?? "").ToLower();
            string reps = ev.AttemptCount > 1 ? $" ({ev.AttemptCount}x)" : "";

            if (category == "Info")
            {
                if (raw.Contains("\\temp\\") || ind.Contains("temp"))
                    return $"Wrote to temp folder → '{ShortPath(ev.RawData)}'{reps}";
                return $"Context file activity → '{ShortPath(ev.RawData)}'{reps}";
            }

            if (category == "File")
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

            if (category == "Registry")
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

            if (category == "Network")
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

            if (category == "Process")
            {
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
                if (ev.EventType == "BlacklistedProcess")
                    return $"[!!!] Spawned known malicious tool: '{ind}'";
                return $"Spawned '{ind}'{reps} → '{ShortCmd(ev.RawData)}'";
            }

            return $"{ev.EventType}: {ShortPath(ev.RawData)}{reps}";
        }

        private static string ReturnVerdict(string grade) => grade switch
        {
            "MALICIOUS"    => "MALICIOUS — Confirmed malicious attack chain detected. Immediate attention required.",
            "SUSPICIOUS"   => "SUSPICIOUS — Abnormal behavior detected that deviates from expected program activity. No confirmed damage.",
            "INCONCLUSIVE" => "INCONCLUSIVE — Some activity detected but insufficient evidence to determine intent.",
            _              => "SAFE — No suspicious activity detected."
        };

        public static void PrintNarrative(AttackNarrative narrative) { }

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

        private static string Truncate(string s, int max) =>
            string.IsNullOrEmpty(s) ? "" : s.Length > max ? s[..max] + "…" : s;
    }
}
