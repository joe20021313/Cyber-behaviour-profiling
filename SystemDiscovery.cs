using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

namespace Cyber_behaviour_profiling
{

    public enum FindingSeverity { Info, Warning, Alert }
    public enum SuspicionLevel  { None, Low, Medium, High }

    public sealed class InvestigationFinding
    {
        public string           Description { get; set; } = "";
        public FindingSeverity  Severity    { get; set; } = FindingSeverity.Info;
        public List<InvestigationFinding> Children { get; set; } = new();
    }

    public sealed class InvestigationResult
    {
        public List<InvestigationFinding> Findings                { get; set; } = new();
        public SuspicionLevel             OverallSuspicion        { get; set; } = SuspicionLevel.None;
        public bool                       ShouldInvestigateFurther { get; set; } = false;
        public int                        ScoreAdjustment         { get; set; } = 0;
    }

    public sealed class FileSnapshot
    {
        public string   FullPath      { get; set; } = "";
        public DateTime LastWriteUtc  { get; set; }
        public long     Size          { get; set; }
    }

    public sealed class DirectorySnapshot
    {
        public DateTime                         CapturedAtUtc { get; set; }
        public Dictionary<string, FileSnapshot> Files         { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    public sealed class SnapshotDiff
    {
        public List<FileSnapshot> NewFiles      { get; set; } = new();
        public List<FileSnapshot> ModifiedFiles { get; set; } = new();
        public List<string>       DeletedFiles  { get; set; } = new();
    }

    [SupportedOSPlatform("windows")]
    public static class SystemDiscovery
    {
        public static DirectorySnapshot TakeDirectorySnapshot(IEnumerable<string> directories)
        {
            var snapshot = new DirectorySnapshot { CapturedAtUtc = DateTime.UtcNow };

            foreach (string rawDir in directories)
            {
                string dir = Environment.ExpandEnvironmentVariables(rawDir);
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (string file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
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

                    foreach (string subDir in Directory.EnumerateDirectories(dir, "*", SearchOption.TopDirectoryOnly))
                    {
                        try
                        {
                            foreach (string file in Directory.EnumerateFiles(subDir, "*", SearchOption.TopDirectoryOnly))
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
                }
                catch (Exception ex)
                {
                    InvestigationLog.Write($"  Snapshot error for '{dir}': {ex.Message}");
                }
            }

            InvestigationLog.Write($"  Snapshot captured {snapshot.Files.Count} files");
            return snapshot;
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

            InvestigationLog.Write($"  New files: {diff.NewFiles.Count}");
            InvestigationLog.Write($"  Modified:  {diff.ModifiedFiles.Count}");
            InvestigationLog.Write($"  Deleted:   {diff.DeletedFiles.Count}");

            foreach (var file in diff.NewFiles)
            {
                if (IsNoise(file.FullPath)) continue;

                string ext  = Path.GetExtension(file.FullPath).ToLowerInvariant();
                string name = Path.GetFileName(file.FullPath).ToLowerInvariant();

                if (MapToData._executableExtensions.Contains(ext))
                {
                    bool isSigned = VerifyFileSignature(file.FullPath);
                    bool isMalwareArtifact = MapToData._malwareArtifacts.Contains(name);
                    bool inSensitiveDir = sensitiveDirs?.Any(d =>
                        file.FullPath.ToLowerInvariant().Contains(d.ToLowerInvariant())) == true;

                    var finding = new InvestigationFinding
                    {
                        Description = $"New executable dropped: {file.FullPath} " +
                                      $"(size: {file.Size:N0} bytes, signed: {isSigned})",
                        Severity = FindingSeverity.Alert
                    };

                    InvestigationLog.Write($"  [ALERT] New executable: {file.FullPath}");
                    InvestigationLog.Write($"          Size={file.Size}, Signed={isSigned}, " +
                                           $"MalwareArtifact={isMalwareArtifact}, SensitiveDir={inSensitiveDir}");

                    if (!isSigned)
                    {
                        finding.Children.Add(new InvestigationFinding
                        {
                            Description = "File is NOT digitally signed — elevated suspicion",
                            Severity = FindingSeverity.Alert
                        });
                        result.ScoreAdjustment += 15;
                    }

                    if (isMalwareArtifact)
                    {
                        finding.Children.Add(new InvestigationFinding
                        {
                            Description = $"Filename '{name}' matches a known malware tool",
                            Severity = FindingSeverity.Alert
                        });
                        result.ScoreAdjustment += 20;
                    }

                    if (inSensitiveDir)
                    {
                        finding.Children.Add(new InvestigationFinding
                        {
                            Description = "Dropped into a sensitive/credential directory",
                            Severity = FindingSeverity.Alert
                        });
                        result.ScoreAdjustment += 10;
                    }

                    if (!isSigned)
                        result.ShouldInvestigateFurther = true;

                    result.Findings.Add(finding);
                }
                else if (MapToData._malwareArtifacts.Contains(name))
                {
                    InvestigationLog.Write($"  [ALERT] Known malware artifact: {file.FullPath}");
                    result.Findings.Add(new InvestigationFinding
                    {
                        Description = $"Known malware artifact appeared: {file.FullPath}",
                        Severity = FindingSeverity.Alert
                    });
                    result.ScoreAdjustment += 15;
                }
                else if (sensitiveDirs?.Any(d =>
                    file.FullPath.ToLowerInvariant().Contains(d.ToLowerInvariant())) == true)
                {
                    InvestigationLog.Write($"  [INFO] New file in sensitive directory: {file.FullPath}");
                    result.Findings.Add(new InvestigationFinding
                    {
                        Description = $"New file in sensitive directory: {file.FullPath} ({file.Size:N0} bytes)",
                        Severity = FindingSeverity.Info
                    });
                }
            }

            foreach (var file in diff.ModifiedFiles)
            {
                if (IsNoise(file.FullPath)) continue;

                string ext = Path.GetExtension(file.FullPath).ToLowerInvariant();
                if (MapToData._executableExtensions.Contains(ext))
                {
                    bool isSigned = VerifyFileSignature(file.FullPath);
                    InvestigationLog.Write($"  [WARNING] Modified executable: {file.FullPath} (signed={isSigned})");

                    var finding = new InvestigationFinding
                    {
                        Description = $"Executable modified during monitoring: {file.FullPath} (signed: {isSigned})",
                        Severity = FindingSeverity.Warning
                    };

                    if (!isSigned)
                    {
                        finding.Severity = FindingSeverity.Alert;
                        result.ScoreAdjustment += 12;
                        finding.Children.Add(new InvestigationFinding
                        {
                            Description = "Modified executable has no valid signature",
                            Severity = FindingSeverity.Alert
                        });
                    }

                    result.Findings.Add(finding);
                }
            }

            foreach (string path in diff.DeletedFiles)
            {
                if (IsNoise(path)) continue;
                string ext = Path.GetExtension(path).ToLowerInvariant();
                if (MapToData._executableExtensions.Contains(ext))
                {
                    InvestigationLog.Write($"  [WARNING] Executable deleted: {path}");
                    result.Findings.Add(new InvestigationFinding
                    {
                        Description = $"Executable deleted (cleanup?): {path}",
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

            InvestigationLog.Write($"  Directory investigation complete: " +
                                   $"{alertCount} alerts, {warningCount} warnings, " +
                                   $"suspicion={result.OverallSuspicion}, " +
                                   $"scoreAdj={result.ScoreAdjustment}");

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
            InvestigationLog.Section("NETWORK EVENT INVESTIGATION");

            string destination = networkEvent.RawData ?? networkEvent.MatchedIndicator ?? "unknown";
            InvestigationLog.Write($"  Investigating network connection to: {destination}");
            InvestigationLog.Write($"  Event time: {networkEvent.Timestamp:HH:mm:ss.fff}");

            if (beforeSnapshot == null || afterSnapshot == null)
            {
                InvestigationLog.Write("  No directory snapshots available — skipping file correlation");
                return result;
            }

            var diff = CompareSnapshots(beforeSnapshot, afterSnapshot);

            var networkTime = networkEvent.Timestamp;
            var newFilesNearNetwork = diff.NewFiles
                .Where(f => Math.Abs((f.LastWriteUtc - networkTime.ToUniversalTime()).TotalSeconds) < 10)
                .ToList();

            if (newFilesNearNetwork.Count > 0)
            {
                InvestigationLog.Write($"  Found {newFilesNearNetwork.Count} new files within ±10s of network event");
            }

            foreach (var file in newFilesNearNetwork)
            {
                if (IsNoise(file.FullPath)) continue;

                string ext  = Path.GetExtension(file.FullPath).ToLowerInvariant();
                string name = Path.GetFileName(file.FullPath).ToLowerInvariant();

                if (MapToData._executableExtensions.Contains(ext))
                {
                    bool isSigned = VerifyFileSignature(file.FullPath);
                    InvestigationLog.Write($"  [ALERT] Executable appeared after network event: {file.FullPath} (signed={isSigned})");

                    var finding = new InvestigationFinding
                    {
                        Description = $"Executable appeared after connecting to {destination}: " +
                                      $"{file.FullPath} (signed: {isSigned})",
                        Severity = FindingSeverity.Alert
                    };

                    if (!isSigned)
                    {
                        finding.Children.Add(new InvestigationFinding
                        {
                            Description = "Downloaded executable is NOT signed — possible malware drop",
                            Severity = FindingSeverity.Alert
                        });
                        result.ScoreAdjustment += 18;
                    }
                    else
                    {
                        result.ScoreAdjustment += 5;
                    }

                    if (MapToData._malwareArtifacts.Contains(name))
                    {
                        finding.Children.Add(new InvestigationFinding
                        {
                            Description = $"Filename '{name}' matches known malware tool",
                            Severity = FindingSeverity.Alert
                        });
                        result.ScoreAdjustment += 20;
                    }

                    result.ShouldInvestigateFurther = true;
                    result.Findings.Add(finding);
                }
                else
                {
                    InvestigationLog.Write($"  [INFO] New file near network event: {file.FullPath}");
                    result.Findings.Add(new InvestigationFinding
                    {
                        Description = $"New file appeared after connecting to {destination}: " +
                                      $"{Path.GetFileName(file.FullPath)} ({file.Size:N0} bytes)",
                        Severity = FindingSeverity.Info
                    });
                }
            }

            var downloadDirs = GetDownloadDirectories();
            var droppedToDownloadDirs = diff.NewFiles
                .Where(f => downloadDirs.Any(d =>
                    f.FullPath.StartsWith(d, StringComparison.OrdinalIgnoreCase)))
                .Where(f => !IsNoise(f.FullPath))
                .ToList();

            if (droppedToDownloadDirs.Count > 0 && droppedToDownloadDirs.Count != newFilesNearNetwork.Count)
            {
                InvestigationLog.Write($"  {droppedToDownloadDirs.Count} new files in download/staging directories");
                foreach (var f in droppedToDownloadDirs.Take(5))
                {
                    string ext = Path.GetExtension(f.FullPath).ToLowerInvariant();
                    if (MapToData._executableExtensions.Contains(ext))
                    {
                        result.Findings.Add(new InvestigationFinding
                        {
                            Description = $"Executable in download directory: {f.FullPath}",
                            Severity = FindingSeverity.Warning
                        });
                    }
                }
            }

            if (result.Findings.Count == 0)
            {
                InvestigationLog.Write("  No suspicious file activity correlated with network event");
                result.OverallSuspicion = SuspicionLevel.None;
            }
            else
            {
                int alertCount = result.Findings.Count(f => f.Severity == FindingSeverity.Alert);
                result.OverallSuspicion = alertCount >= 1 ? SuspicionLevel.High :
                                          result.Findings.Any(f => f.Severity == FindingSeverity.Warning)
                                              ? SuspicionLevel.Low : SuspicionLevel.None;
            }

            InvestigationLog.Write($"  Network investigation complete: " +
                                   $"suspicion={result.OverallSuspicion}, scoreAdj={result.ScoreAdjustment}");
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
            var dirs = new List<string>(GetDownloadDirectories());

            if (sensitiveDirs != null)
            {
                string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

                foreach (string sd in sensitiveDirs)
                {
                    string expanded = sd.Replace("\\", Path.DirectorySeparatorChar.ToString());

                    string candidate1 = Path.Combine(localAppData, expanded.TrimStart(Path.DirectorySeparatorChar));
                    string candidate2 = Path.Combine(appData, expanded.TrimStart(Path.DirectorySeparatorChar));

                    if (Directory.Exists(candidate1)) dirs.Add(candidate1);
                    else if (Directory.Exists(candidate2)) dirs.Add(candidate2);
                }
            }

            dirs.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)));
            dirs.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)));

            return dirs.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        public static bool VerifyFileSignature(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return false;
#pragma warning disable SYSLIB0057
                var cert = X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
                if (cert == null) return false;

                using var cert2 = new X509Certificate2(cert);
                string subject = cert2.Subject ?? "";
                foreach (var part in subject.Split(','))
                {
                    string trimmed = part.Trim();
                    if (trimmed.StartsWith("O=", StringComparison.OrdinalIgnoreCase))
                    {
                        string org = trimmed.Substring(2).Trim().Trim('"');
                        if (!string.IsNullOrWhiteSpace(org)
                            && MapToData._trustedPublishers.Contains(org))
                            return true;
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
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
    }
}
