using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;

namespace Cyber_behaviour_profiling
{
    internal enum DroppedProgramVerdict { Malicious, Suspicious, Info }

    internal sealed record DroppedProgramFinding(
        DroppedProgramVerdict Verdict,
        string RuleId,
        string Reason,
        string? ChildReason = null);

    [SupportedOSPlatform("windows")]
    internal static class DroppedProgramClassifier
    {
        private static readonly HashSet<string> _peExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".pif", ".com", ".msi", ".drv", ".efi"
        };

        private static readonly HashSet<string> _scriptExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".hta", ".jar"
        };

        private static readonly HashSet<string> _systemProgramNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "svchost", "explorer", "lsass", "csrss", "winlogon", "services",
            "spoolsv", "wininit", "smss", "dwm", "taskhostw", "conhost",
            "rundll32", "dllhost", "taskhost", "taskeng", "ctfmon", "sihost"
        };

        private static readonly string[] _brandTokens =
        {
            "windows", "microsoft", "chrome", "google", "edge",
            "mozilla", "firefox", "adobe", "teams", "zoom", "steam", "nvidia", "intel"
        };

        private static readonly string[] _updaterStemTokens =
        {
            "update", "updater", "updt", "setup", "install", "svc"
        };

        private static readonly HashSet<string> _docExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
            "txt", "rtf", "jpg", "jpeg", "png", "gif", "zip", "rar"
        };

        private static readonly HashSet<string> _execExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            "exe", "scr", "cmd", "bat", "ps1", "vbs", "js", "wsf",
            "hta", "cpl", "com", "pif"
        };

        internal static bool IsPeOrScript(string extension) =>
            _peExtensions.Contains(extension) || _scriptExtensions.Contains(extension);

        public static DroppedProgramFinding Classify(
            string filePath,
            SignatureVerificationResult? sig)
        {
            string fileName = Path.GetFileName(filePath);
            string ext      = Path.GetExtension(filePath);
            string stem     = Path.GetFileNameWithoutExtension(filePath);
            bool isPe       = _peExtensions.Contains(ext);
            bool isScript   = !isPe && _scriptExtensions.Contains(ext);

            if (!isPe && !isScript)
                return BuildInfoFinding(filePath, sig, isPe: false);

            
            if (isPe && sig != null &&
                (sig.TrustState == SignatureTrustState.InvalidSignature ||
                 sig.TrustState == SignatureTrustState.Revoked))
            {
                string sigReason = MapHResultToReason(sig.HResult, sig.TrustState, sig.PublisherName);
                return new DroppedProgramFinding(
                    DroppedProgramVerdict.Malicious,
                    "Signature.Invalid",
                    $"Program with invalid or revoked signature dropped or changed: {filePath}",
                    sigReason);
            }

            
            string fileNameLower = fileName.ToLowerInvariant();
            if (MapToData._malwareArtifacts.Contains(fileNameLower))
            {
                return new DroppedProgramFinding(
                    DroppedProgramVerdict.Malicious,
                    "MalwareName.KnownArtifact",
                    $"Known offensive-security tool dropped: {filePath}",
                    $"Filename '{fileName}' matches a known malware tool");
            }

            
            if (isPe && _systemProgramNames.Contains(stem))
            {
                string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                bool inSystemDir =
                    filePath.StartsWith(Path.Combine(win, "System32"), StringComparison.OrdinalIgnoreCase) ||
                    filePath.StartsWith(Path.Combine(win, "SysWOW64"), StringComparison.OrdinalIgnoreCase) ||
                    filePath.StartsWith(Path.Combine(win, "WinSxS"),   StringComparison.OrdinalIgnoreCase);

                if (!inSystemDir)
                {
                    string folder = Path.GetDirectoryName(filePath) ?? filePath;
                    return new DroppedProgramFinding(
                        DroppedProgramVerdict.Malicious,
                        "Pattern.SystemImpersonation",
                        $"Uses a system program name '{stem}.exe' outside the System32 folder — " +
                        $"found in '{folder}'; real system apps only live in the System32 folder.");
                }
            }

            
            {
                string stemLower = stem.ToLowerInvariant();
                string? matchedUpdaterToken = _updaterStemTokens.FirstOrDefault(t => stemLower.Contains(t));
                string? matchedBrand        = _brandTokens.FirstOrDefault(t => stemLower.Contains(t));

                if (matchedUpdaterToken != null && matchedBrand != null && IsUserWritablePath(filePath))
                {
                    string folder = Path.GetDirectoryName(filePath) ?? filePath;
                    return new DroppedProgramFinding(
                        DroppedProgramVerdict.Malicious,
                        "Pattern.VendorImpersonation",
                        $"Impersonates a {matchedBrand} updater ('{fileName}') in " +
                        $"user-writable path '{folder}' — " +
                        $"real {matchedBrand} updaters live under Program Files");
                }
            }

            
            {
                string[] parts = fileName.Split('.');
                if (parts.Length >= 3)
                {
                    string secondLast = parts[^2];
                    string last       = parts[^1];
                    if (_docExtensions.Contains(secondLast) && _execExtensions.Contains(last))
                    {
                        return new DroppedProgramFinding(
                            DroppedProgramVerdict.Malicious,
                            "Pattern.DoubleExtension",
                            $"Uses double extension '{secondLast}.{last}' — " +
                            $"the real extension is '.{last}', disguised as '.{secondLast}'; " +
                            "this pattern is a classic phishing disguise");
                    }
                }
            }

            
            {
                string? obfReason = DetectObfuscation(stem, filePath);
                if (obfReason != null)
                    return new DroppedProgramFinding(DroppedProgramVerdict.Malicious, "Pattern.Obfuscation", obfReason);
            }

            
            if (isPe && IsUserWritablePath(filePath) &&
                (sig == null || sig.TrustState == SignatureTrustState.NoSignature))
            {
                return new DroppedProgramFinding(
                    DroppedProgramVerdict.Suspicious,
                    "Pattern.UnsignedInUserPath",
                    $"Unsigned program dropped in user-writable folder: {filePath}",
                    "No digital signature found. Cannot verify who made it. " +
                    "If this program acts like malware, it will be flagged as Malicious.");
            }

            
            return BuildInfoFinding(filePath, sig, isPe);
        }

        private static DroppedProgramFinding BuildInfoFinding(
            string filePath, SignatureVerificationResult? sig, bool isPe)
        {
            string ext  = Path.GetExtension(filePath);
            bool actuallyPe = isPe || _peExtensions.Contains(ext);
            string kind = actuallyPe ? "program" : "script";

            if (actuallyPe && sig?.TrustState == SignatureTrustState.TrustedPublisherVerified)
                return new DroppedProgramFinding(DroppedProgramVerdict.Info, "Safe.SignedProgram",
                    $"New signed {kind}: {filePath} (maker: {sig.PublisherName})");

            if (actuallyPe && sig?.TrustState == SignatureTrustState.ValidSignatureUntrustedPublisher)
                return new DroppedProgramFinding(DroppedProgramVerdict.Info, "Safe.UntrustedPublisher",
                    $"New {kind} with a valid signature but an untrusted maker: {filePath} (maker: {sig.PublisherName})");

            if (actuallyPe)
                return new DroppedProgramFinding(DroppedProgramVerdict.Info, "Safe.UnsignedProgram",
                    $"New unsigned {kind}: {filePath}");

            return new DroppedProgramFinding(DroppedProgramVerdict.Info, "Safe.Script",
                $"New script: {filePath}");
        }

        private static bool IsUserWritablePath(string filePath)
        {
            string appData       = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string localAppData  = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string temp          = Path.GetTempPath();
            string userProfile   = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string publicDir     = Environment.GetEnvironmentVariable("PUBLIC") ?? "";

            return filePath.StartsWith(appData,       StringComparison.OrdinalIgnoreCase) ||
                   filePath.StartsWith(localAppData,  StringComparison.OrdinalIgnoreCase) ||
                   filePath.StartsWith(temp,          StringComparison.OrdinalIgnoreCase) ||
                   filePath.StartsWith(userProfile,   StringComparison.OrdinalIgnoreCase) ||
                   filePath.StartsWith(commonAppData, StringComparison.OrdinalIgnoreCase) ||
                   (!string.IsNullOrEmpty(publicDir) &&
                    filePath.StartsWith(publicDir,    StringComparison.OrdinalIgnoreCase));
        }

        private static string? DetectObfuscation(string stem, string filePath)
        {
            
            foreach (char c in stem)
            {
                if (c == '\u202E')
                    return "Filename contains RTL override character (U+202E)typical filename disguise technique";
                if (c == '\u200B' || c == '\u200C' || c == '\u200D')
                    return "Filename contains zero-width Unicode character — used to evade visual detection";
                
                if (c == '\u0430' || c == '\u0435' || c == '\u043E' ||
                    c == '\u0440' || c == '\u0441' || c == '\u0445')
                    return "Filename contains Cyrillic homoglyph characters masquerading as Latin letters";
            }

            
            if (stem.Length <= 2 && IsUserWritablePath(filePath))
                return $"Filename stem is only {stem.Length} character(s) long in a user-writable path — typical of auto-generated dropper names";

            
            if (stem.Length >= 8)
            {
                double entropy = ComputeShannonEntropy(stem);
                if (entropy >= 3.5 && !HasDictionarySubstring(stem))
                    return $"Filename has high randomness (entropy {entropy:F2} bits/char) with no recognisable word — typical of auto-generated malware names";
            }

            return null;
        }

        private static double ComputeShannonEntropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            var freq = new Dictionary<char, int>(s.Length);
            foreach (char c in s)
                freq[c] = freq.TryGetValue(c, out int v) ? v + 1 : 1;

            double entropy = 0;
            double len = s.Length;
            foreach (var kv in freq)
            {
                double p = kv.Value / len;
                entropy -= p * Math.Log2(p);
            }
            return entropy;
        }

        private static readonly HashSet<string> _commonWords = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "firefox", "edge", "opera", "update", "setup", "install", "uninstall",
            "launch", "start", "stop", "service", "host", "helper", "agent", "client",
            "server", "loader", "runner", "worker", "manager", "monitor", "scanner",
            "backup", "sync", "cloud", "drive", "share", "print", "audio", "video",
            "screen", "window", "system", "process", "task", "java", "python", "dotnet",
            "runtime", "engine", "plugin", "driver", "device", "config", "settings",
            "profile", "session", "network", "connect", "remote", "secure", "crypt",
            "cipher", "token", "access", "admin", "user", "data", "file", "folder",
            "cache", "temp", "report", "export", "import", "convert", "compress",
            "extract", "archive", "patch", "deploy", "build", "compile", "debug",
            "test", "check", "scan", "clean", "repair", "restore", "recover",
            "power", "sleep", "wake", "lock", "login", "logout", "auth",
            "verify", "sign", "cert", "store", "vault", "safe", "shield",
            "guard", "block", "filter", "detect", "alert", "notify", "send", "receive",
            "listen", "watch", "trace", "track", "record", "capture", "snap", "dump",
            "read", "write", "copy", "move", "delete", "create", "open", "close",
            "register", "microsoft", "google", "adobe", "apple", "intel", "nvidia",
            "amd", "steam", "origin", "zoom", "teams", "slack", "discord", "skype",
            "office", "word", "excel", "outlook", "paint", "photo", "image", "media",
            "player", "sound", "mixer", "camera", "sensor", "battery", "display",
            "keyboard", "mouse", "touch", "quick", "smart", "auto", "easy", "fast",
            "light", "dark", "mini", "mega", "ultra", "super", "nano", "micro"
        };

        private static bool HasDictionarySubstring(string stem)
        {
            string lower = stem.ToLowerInvariant();
            foreach (string word in _commonWords)
            {
                if (word.Length >= 4 && lower.Contains(word))
                    return true;
            }
            return false;
        }

        private static string MapHResultToReason(uint hresult, SignatureTrustState state, string publisherName)
        {
            string pub = string.IsNullOrWhiteSpace(publisherName) ? "" : $" (publisher: {publisherName})";

            if (state == SignatureTrustState.Revoked)
                return $"Signing certificate was revoked by the issuer{pub}";

            return hresult switch
            {
                0x80096010 => $"File contents don't match the signed hash — tampered after signing{pub}",
                0x800B0101 => $"Signing certificate has expired{pub}",
                0x800B0102 => $"Certificate validity period nesting is invalid{pub}",
                0x800B0109 => $"Signed by a certificate whose root is not in the trusted store{pub}",
                0x800B010A => $"Certificate chain is broken or contains an untrusted link{pub}",
                0x800B0112 => $"A CA in the certificate chain is not trusted{pub}",
                0x800B0004 => $"Signed by a publisher not on the trusted-publisher list{pub}",
                0         => $"Signature present but chain validation failed{pub}",
                _         => $"Signature present but Windows refused to trust it (HRESULT 0x{hresult:X8}){pub}"
            };
        }
    }
}
