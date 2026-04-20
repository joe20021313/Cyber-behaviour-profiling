using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Cyber_behaviour_profiling
{
    public enum FindingSeverity { Info, Warning, Alert }
    public enum SuspicionLevel { None, Low, Medium, High }

    public sealed class InvestigationFinding
    {
        public string Description { get; set; } = "";
        public string ArtifactPath { get; set; } = "";
        public string CorrelationKey { get; set; } = "";
        public FindingSeverity Severity { get; set; } = FindingSeverity.Info;
        public List<InvestigationFinding> Children { get; set; } = new();
    }

    public sealed class InvestigationResult
    {
        public List<InvestigationFinding> Findings { get; set; } = new();
        public SuspicionLevel OverallSuspicion { get; set; } = SuspicionLevel.None;
    }

    public sealed class FileSnapshot
    {
        public string FullPath { get; set; } = "";
        public DateTime LastWriteUtc { get; set; }
        public long Size { get; set; }
    }

    public sealed class DirectorySnapshot
    {
        public DateTime CapturedAtUtc { get; set; }
        public Dictionary<string, FileSnapshot> Files { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    public sealed class SnapshotDiff
    {
        public List<FileSnapshot> NewFiles { get; set; } = new();
        public List<FileSnapshot> ModifiedFiles { get; set; } = new();
        public List<string> DeletedFiles { get; set; } = new();
    }

    [SupportedOSPlatform("windows")]
    public static class SystemDiscovery
    {
        private const int SnapshotDepthLimit = 4;

        public static DirectorySnapshot TakeDirectorySnapshot(IEnumerable<string> directories)
        {
            var snapshot = new DirectorySnapshot { CapturedAtUtc = DateTime.UtcNow };

            foreach (string rawDir in directories)
            {
                string dir = Environment.ExpandEnvironmentVariables(rawDir);
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (string file in EnumerateFilesWithinDepth(dir, SnapshotDepthLimit))
                    {
                        try
                        {
                            var info = new FileInfo(file);
                            snapshot.Files[file] = new FileSnapshot
                            {
                                FullPath     = file,
                                LastWriteUtc = info.LastWriteTimeUtc,
                                Size         = info.Length
                            };
                        }
                        catch { }
                    }
                }
                catch { }
            }

            return snapshot;
        }

        public static List<string> ExpandSensitiveDirectoryCandidates(string rawDirectory)
        {
            var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(rawDirectory))
                return candidates.ToList();

            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

            string normalized = rawDirectory.Replace('/', '\\').Trim();
            string trimmed = normalized.Trim('\\');
            string relative = trimmed.Replace('\\', Path.DirectorySeparatorChar);

            void AddCandidate(string? candidate)
            {
                if (string.IsNullOrWhiteSpace(candidate))
                    return;

                string normalizedCandidate = candidate.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (!string.IsNullOrWhiteSpace(normalizedCandidate))
                    candidates.Add(normalizedCandidate);
            }

            if (Path.IsPathRooted(normalized))
                AddCandidate(Environment.ExpandEnvironmentVariables(normalized));

            if (trimmed.StartsWith(".ssh", StringComparison.OrdinalIgnoreCase))
                AddCandidate(Path.Combine(userProfile, relative));

            if (trimmed.Equals("appdata", StringComparison.OrdinalIgnoreCase))
                AddCandidate(Path.Combine(userProfile, "AppData"));

            if (trimmed.Equals("appdata\\local", StringComparison.OrdinalIgnoreCase))
                AddCandidate(localAppData);

            if (trimmed.StartsWith("appdata\\local\\", StringComparison.OrdinalIgnoreCase))
                AddCandidate(Path.Combine(localAppData,
                    trimmed["appdata\\local\\".Length..].Replace('\\', Path.DirectorySeparatorChar)));

            if (trimmed.Equals("appdata\\roaming", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals("roaming", StringComparison.OrdinalIgnoreCase))
                AddCandidate(appData);

            if (trimmed.StartsWith("appdata\\roaming\\", StringComparison.OrdinalIgnoreCase))
                AddCandidate(Path.Combine(appData,
                    trimmed["appdata\\roaming\\".Length..].Replace('\\', Path.DirectorySeparatorChar)));

            if (trimmed.StartsWith("roaming\\", StringComparison.OrdinalIgnoreCase))
                AddCandidate(Path.Combine(appData,
                    trimmed["roaming\\".Length..].Replace('\\', Path.DirectorySeparatorChar)));

            if (trimmed.StartsWith("drivers\\etc", StringComparison.OrdinalIgnoreCase))
                AddCandidate(Path.Combine(windowsDir, "System32",
                    trimmed.Replace('\\', Path.DirectorySeparatorChar)));

            if (trimmed.StartsWith("appdata\\", StringComparison.OrdinalIgnoreCase))
                AddCandidate(Path.Combine(userProfile, relative));

            if (!string.IsNullOrWhiteSpace(commonAppData))
                AddCandidate(Path.Combine(commonAppData, relative));

            if (!string.IsNullOrWhiteSpace(windowsDir))
                AddCandidate(Path.Combine(windowsDir, relative));

            return candidates.ToList();
        }

        public static SnapshotDiff CompareSnapshots(DirectorySnapshot before, DirectorySnapshot after)
        {
            var diff = new SnapshotDiff();

            foreach (var (path, afterFile) in after.Files)
            {
                if (!before.Files.TryGetValue(path, out var beforeFile))
                {
                    diff.NewFiles.Add(afterFile);
                }
                else if (afterFile.LastWriteUtc != beforeFile.LastWriteUtc || afterFile.Size != beforeFile.Size)
                {
                    diff.ModifiedFiles.Add(afterFile);
                }
            }

            foreach (var path in before.Files.Keys)
            {
                if (!after.Files.ContainsKey(path))
                    diff.DeletedFiles.Add(path);
            }

            return diff;
        }

        public static InvestigationResult InvestigateDirectoryChanges(
            DirectorySnapshot? before, DirectorySnapshot? after,
            IReadOnlyList<string>? sensitiveDirs = null,
            int depth = 0)
        {
            var result = new InvestigationResult();
            if (before == null || after == null) return result;

            var diff = CompareSnapshots(before, after);

            foreach (var file in diff.NewFiles)
            {
                if (IsNoise(file.FullPath)) continue;

                string ext  = Path.GetExtension(file.FullPath).ToLowerInvariant();
                string name = Path.GetFileName(file.FullPath).ToLowerInvariant();

                if (DroppedProgramClassifier.IsPeOrScript(ext))
                {
                    bool supportsEmbeddedSignature = SignatureVerifier.SupportsEmbeddedSignature(file.FullPath);
                    SignatureVerificationResult? sig = supportsEmbeddedSignature
                        ? GetFileSignatureInfo(file.FullPath)
                        : null;

                    var verdict = DroppedProgramClassifier.Classify(file.FullPath, sig);

                    FindingSeverity severity = verdict.Verdict switch
                    {
                        DroppedProgramVerdict.Malicious  => FindingSeverity.Alert,
                        DroppedProgramVerdict.Suspicious => FindingSeverity.Warning,
                        _                               => FindingSeverity.Info
                    };

                    var finding = new InvestigationFinding
                    {
                        Description = verdict.Reason,
                        ArtifactPath = file.FullPath,
                        Severity = severity
                    };

                    if (verdict.ChildReason != null)
                        finding.Children.Add(new InvestigationFinding
                        {
                            Description = verdict.ChildReason,
                            Severity = severity
                        });

                    bool inSensitiveDir = sensitiveDirs?.Any(d =>
                        file.FullPath.ToLowerInvariant().Contains(d.ToLowerInvariant())) == true;
                    if (inSensitiveDir)
                    {
                        finding.Children.Add(new InvestigationFinding
                        {
                            Description = "Dropped into a sensitive/credential directory",
                            Severity = FindingSeverity.Alert
                        });
                        if (finding.Severity != FindingSeverity.Alert)
                            finding.Severity = FindingSeverity.Alert;
                    }

                    result.Findings.Add(finding);
                }
                else if (MapToData._malwareArtifacts.Contains(name))
                {
                    result.Findings.Add(new InvestigationFinding
                    {
                        Description = $"Known malware artifact appeared: {file.FullPath}",
                        ArtifactPath = file.FullPath,
                        Severity = FindingSeverity.Alert
                    });
                }
                else if (sensitiveDirs?.Any(d =>
                    file.FullPath.ToLowerInvariant().Contains(d.ToLowerInvariant())) == true)
                {
                    result.Findings.Add(new InvestigationFinding
                    {
                        Description = $"New file in sensitive directory: {file.FullPath} ({file.Size:N0} bytes)",
                        ArtifactPath = file.FullPath,
                        Severity = FindingSeverity.Info
                    });
                }
            }

            foreach (var file in diff.ModifiedFiles)
            {
                if (IsNoise(file.FullPath)) continue;

                string ext = Path.GetExtension(file.FullPath).ToLowerInvariant();
                if (!DroppedProgramClassifier.IsPeOrScript(ext)) continue;

                bool supportsEmbeddedSignature = SignatureVerifier.SupportsEmbeddedSignature(file.FullPath);
                SignatureVerificationResult? sig = supportsEmbeddedSignature
                    ? GetFileSignatureInfo(file.FullPath)
                    : null;



                
                
                var verdict = DroppedProgramClassifier.Classify(file.FullPath, sig);

                if (verdict.Verdict == DroppedProgramVerdict.Malicious ||
                    verdict.Verdict == DroppedProgramVerdict.Suspicious)
                {
                    FindingSeverity sev = verdict.Verdict == DroppedProgramVerdict.Malicious
                        ? FindingSeverity.Alert : FindingSeverity.Warning;
                    var finding = new InvestigationFinding
                    {
                        Description = verdict.Reason,
                        ArtifactPath = file.FullPath,
                        Severity = sev
                    };
                    if (verdict.ChildReason != null)
                        finding.Children.Add(new InvestigationFinding
                        {
                            Description = verdict.ChildReason,
                            Severity = sev
                        });
                    result.Findings.Add(finding);
                }
                else
                {
                    result.Findings.Add(new InvestigationFinding
                    {
                        Description = $"{(supportsEmbeddedSignature ? "Program" : "Script")} modified during monitoring: {file.FullPath}",
                        ArtifactPath = file.FullPath,
                        Severity = FindingSeverity.Info
                    });
                }
            }

            foreach (string path in diff.DeletedFiles)
            {
                if (IsNoise(path)) continue;
                string ext = Path.GetExtension(path).ToLowerInvariant();
                if (MapToData._executableExtensions.Contains(ext))
                {
                    result.Findings.Add(new InvestigationFinding
                    {
                        Description = SignatureVerifier.SupportsEmbeddedSignature(path)
                            ? $"Program deleted during monitoring: {path}"
                            : $"Script deleted during monitoring: {path}",
                        ArtifactPath = path,
                        Severity = FindingSeverity.Warning
                    });
                }
            }

            int alertCount   = result.Findings.Count(f => f.Severity == FindingSeverity.Alert);
            int warningCount = result.Findings.Count(f => f.Severity == FindingSeverity.Warning);

            result.OverallSuspicion = alertCount >= 2 ? SuspicionLevel.High :
                                     alertCount == 1 ? SuspicionLevel.Medium :
                                     warningCount > 0 ? SuspicionLevel.Low :
                                                        SuspicionLevel.None;

            return result;
        }

        public static InvestigationResult InvestigateNetworkEvent(
            SuspiciousEvent networkEvent,
            ProcessProfile profile,
            DirectorySnapshot? beforeSnapshot,
            DirectorySnapshot? afterSnapshot,
            int depth = 0)
        {
            var result = new InvestigationResult();
            string destination = networkEvent.RawData ?? networkEvent.MatchedIndicator ?? "unknown";

            if (beforeSnapshot == null || afterSnapshot == null)
                return result;

            var diff = CompareSnapshots(beforeSnapshot, afterSnapshot);

            var networkTime = networkEvent.Timestamp;
            var newFilesNearNetwork = diff.NewFiles
                .Where(f => Math.Abs((f.LastWriteUtc - networkTime.ToUniversalTime()).TotalSeconds) < 10)
                .ToList();
            var informationalFiles = new List<FileSnapshot>();

            foreach (var file in newFilesNearNetwork)
            {
                if (IsNoise(file.FullPath)) continue;

                string ext  = Path.GetExtension(file.FullPath).ToLowerInvariant();
                string name = Path.GetFileName(file.FullPath).ToLowerInvariant();
                bool supportsEmbeddedSignature = SignatureVerifier.SupportsEmbeddedSignature(file.FullPath);

                if (MapToData._executableExtensions.Contains(ext))
                {
                    bool isSuspiciousDomain = networkEvent.Category is "network_c2" or "dns_c2";

                    SignatureVerificationResult? sig = supportsEmbeddedSignature
                        ? GetFileSignatureInfo(file.FullPath)
                        : null;

                    var classifierVerdict = DroppedProgramClassifier.Classify(file.FullPath, sig);

                    FindingSeverity severity;
                    if (isSuspiciousDomain || classifierVerdict.Verdict == DroppedProgramVerdict.Malicious)
                        severity = FindingSeverity.Alert;
                    else if (classifierVerdict.Verdict == DroppedProgramVerdict.Suspicious)
                        severity = FindingSeverity.Warning;
                    else
                        severity = FindingSeverity.Info;

                    string trustLabel = sig != null ? $" (trust: {sig.ShortLabel})" : "";
                    string description = supportsEmbeddedSignature
                        ? $"Program appeared after connecting to {destination}: {file.FullPath}{trustLabel}"
                        : $"Script appeared after connecting to {destination}: {file.FullPath}";

                    var finding = new InvestigationFinding
                    {
                        Description = description,
                        ArtifactPath = file.FullPath,
                        Severity = severity
                    };

                    if (classifierVerdict.ChildReason != null)
                        finding.Children.Add(new InvestigationFinding
                        {
                            Description = classifierVerdict.ChildReason,
                            Severity = severity
                        });

                    if (isSuspiciousDomain)
                        finding.Children.Add(new InvestigationFinding
                        {
                            Description = $"Connection destination '{destination}' is on the suspicious-domain list",
                            Severity = FindingSeverity.Alert
                        });

                    if (MapToData._malwareArtifacts.Contains(name))
                    {
                        finding.Children.Add(new InvestigationFinding
                        {
                            Description = $"Filename '{name}' matches known malware tool",
                            Severity = FindingSeverity.Alert
                        });
                        finding.Severity = FindingSeverity.Alert;
                    }

                    if (supportsEmbeddedSignature && sig != null)
                        AppendSignatureContext(finding, sig, elevateTrustFailures: false);

                    result.Findings.Add(finding);
                }
                else
                {
    
                    informationalFiles.Add(file);
                }
            }

            if (informationalFiles.Count == 1)
            {
                var file = informationalFiles[0];
                result.Findings.Add(new InvestigationFinding
                {
                    Description = $"File appeared after connecting to {destination}: {Path.GetFileName(file.FullPath)} ({file.Size:N0} bytes)",
                    ArtifactPath = file.FullPath,
                    Severity = FindingSeverity.Info
                });
            }
            else if (informationalFiles.Count > 1)
            {
                string[] sampleNames = informationalFiles
                    .Select(f => Path.GetFileName(f.FullPath))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(3)
                    .ToArray();
                int distinctCount = informationalFiles
                    .Select(f => Path.GetFileName(f.FullPath))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Count();
                string remainderText = distinctCount > sampleNames.Length
                    ? $", +{distinctCount - sampleNames.Length} more"
                    : "";

                result.Findings.Add(new InvestigationFinding
                {
                    Description = $"{informationalFiles.Count} files appeared within 10s of connecting to {destination}; samples: {string.Join(", ", sampleNames)}{remainderText}",
                    CorrelationKey = $"network-summary::{NormalizeCorrelationKey(destination)}",
                    Severity = FindingSeverity.Info
                });
            }

            var downloadDirs = GetDownloadDirectories();
            var droppedToDownloadDirs = diff.NewFiles
                .Where(f => downloadDirs.Any(d =>
                    f.FullPath.StartsWith(d, StringComparison.OrdinalIgnoreCase)))
                .Where(f => !IsNoise(f.FullPath))
                .ToList();

            if (droppedToDownloadDirs.Count > 0 && droppedToDownloadDirs.Count != newFilesNearNetwork.Count)
            {

                foreach (var f in droppedToDownloadDirs.Take(5))
                {
                    string ext = Path.GetExtension(f.FullPath).ToLowerInvariant();
                    if (MapToData._executableExtensions.Contains(ext))
                    {
                        result.Findings.Add(new InvestigationFinding
                        {
                            Description = $"Executable in download directory: {f.FullPath}",
                            ArtifactPath = f.FullPath,
                            Severity = FindingSeverity.Warning
                        });
                    }
                }
            }

            if (result.Findings.Count == 0)
            {
                result.OverallSuspicion = SuspicionLevel.None;
            }
            else
            {
                int alertCount = result.Findings.Count(f => f.Severity == FindingSeverity.Alert);
                result.OverallSuspicion = alertCount >= 1 ? SuspicionLevel.High :
                                          result.Findings.Any(f => f.Severity == FindingSeverity.Warning)
                                              ? SuspicionLevel.Low : SuspicionLevel.None;
            }

            return result;
        }

        public static List<string> GetDownloadDirectories()
        {
            var dirs = new List<string>();

            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(userProfile))
                dirs.Add(Path.Combine(userProfile, "Downloads"));

            string temp = Path.GetTempPath();
            if (!string.IsNullOrEmpty(temp))
                dirs.Add(temp);

            string progData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            if (!string.IsNullOrEmpty(progData))
                dirs.Add(progData);

            string publicFolder = Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public";
            dirs.Add(publicFolder);

            return dirs.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        public static List<string> GetMonitoredDirectories(IReadOnlyList<string>? sensitiveDirs = null)
        {
            var dirs = new HashSet<string>(GetDownloadDirectories(), StringComparer.OrdinalIgnoreCase);

            if (sensitiveDirs != null)
            {
                foreach (string sd in sensitiveDirs)
                {
                    foreach (string candidate in ExpandSensitiveDirectoryCandidates(sd))
                    {
                        if (Directory.Exists(candidate))
                            dirs.Add(candidate);
                    }
                }
            }

            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (Directory.Exists(appData))
                dirs.Add(appData);
            if (Directory.Exists(localAppData))
                dirs.Add(localAppData);

            return dirs.ToList();
        }

        public static bool VerifyFileSignature(string filePath)
        {
            return GetFileSignatureInfo(filePath).IsTrustedPublisher;
        }

        public static SignatureVerificationResult GetFileSignatureInfo(string filePath) =>
            SignatureVerifier.VerifyFile(filePath);

        private static string BuildNewArtifactDescription(
            string filePath,
            long size,
            bool supportsEmbeddedSignature,
            string trustLabel = "")
        {
            string kind = supportsEmbeddedSignature ? "program" : "script";
            string suffix = string.IsNullOrWhiteSpace(trustLabel)
                ? $"(size: {size:N0} bytes)"
                : $"(size: {size:N0} bytes, trust: {trustLabel})";

            return $"New {kind} dropped: {filePath} {suffix}";
        }

        private static void AppendSignatureContext(
            InvestigationFinding finding,
            SignatureVerificationResult signature,
            bool elevateTrustFailures)
        {
            if (signature.TrustState == SignatureTrustState.InvalidSignature ||
                signature.TrustState == SignatureTrustState.Revoked)
            {
                finding.Children.Add(new InvestigationFinding
                {
                    Description = signature.Summary,
                    Severity = FindingSeverity.Alert
                });
                if (elevateTrustFailures)
                    finding.Severity = FindingSeverity.Alert;
            }
        }

        private static string NormalizeCorrelationKey(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return "unknown";

            string trimmed = value.Trim();
            int detailIndex = trimmed.IndexOf(" (", StringComparison.Ordinal);
            return detailIndex > 0 && trimmed.EndsWith(')')
                ? trimmed[..detailIndex].ToLowerInvariant()
                : trimmed.ToLowerInvariant();
        }

        private static bool IsNoise(string path)
        {
            string lower = path.ToLowerInvariant();
            string ext = Path.GetExtension(lower);

            if (MapToData._noiseExtensions.Contains(ext))
                return true;

            if (MapToData._noisePaths.Any(frag => lower.Contains(frag)))
                return true;

            try
            {
                if (File.Exists(path) && new FileInfo(path).Length == 0)
                    return true;
            }
            catch { }

            return false;
        }

        private static IEnumerable<string> EnumerateFilesWithinDepth(string rootDirectory, int depthLimit)
        {
            var pendingDirectories = new Queue<(string DirectoryPath, int Depth)>();
            pendingDirectories.Enqueue((rootDirectory, 0));

            while (pendingDirectories.Count > 0)
            {
                var (currentDirectory, depth) = pendingDirectories.Dequeue();

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(currentDirectory, "*", SearchOption.TopDirectoryOnly);
                }
                catch
                {
                    continue;
                }

                foreach (string file in files)
                    yield return file;

                if (depth >= depthLimit)
                    continue;

                IEnumerable<string> subDirectories;
                try
                {
                    subDirectories = Directory.EnumerateDirectories(currentDirectory, "*", SearchOption.TopDirectoryOnly);
                }
                catch
                {
                    continue;
                }

                foreach (string subDirectory in subDirectories)
                    pendingDirectories.Enqueue((subDirectory, depth + 1));
            }
        }
    }
}
