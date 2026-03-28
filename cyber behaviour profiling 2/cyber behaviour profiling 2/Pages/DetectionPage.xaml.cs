using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using Cyber_behaviour_profiling;

namespace cyber_behaviour_profiling_2.Pages
{

    public class ActivityTileVM
    {
        public string ActivityType { get; set; } = "";
        public string DisplayLabel { get; set; } = "";
        public int TotalCount { get; set; }
        public string CountLabel => TotalCount > 9999
            ? $"{TotalCount / 1000.0:0.#}K"
            : $"x{TotalCount}";
        public SolidColorBrush TileBrush { get; set; } = new(Colors.Gray);
        public Dictionary<string, DetailItemVM> UniqueDetails { get; set; } = new();
        public List<DetailItemVM> DetailList => UniqueDetails.Values
            .OrderByDescending(d => d.Count).ToList();

        public bool IsProcessTile { get; set; }
        public int ProcessId { get; set; }
        public List<TimelineEntryVM> ProcessTimeline { get; set; } = new();
    }

    public class DetailItemVM
    {
        public string ShortName { get; set; } = "";
        public string FullDetail { get; set; } = "";
        public int Count { get; set; }
        public string CountLabel => Count > 1 ? $"x{Count}" : "";
        public string FirstSeen { get; set; } = "";
        public string LastSeen { get; set; } = "";
        public string TimeDisplay => FirstSeen == LastSeen
            ? FirstSeen
            : $"{FirstSeen} - {LastSeen}";
        public SolidColorBrush ActivityBrush { get; set; } = new(Colors.Gray);
    }

    public class TimelineEntryVM
    {
        public string Time { get; set; } = "";
        public string Label { get; set; } = "";
        public string Detail { get; set; } = "";
        public int Count { get; set; } = 1;
        public string CountLabel => Count > 1 ? $"x{Count}" : "";
        public SolidColorBrush ActivityBrush { get; set; } = new(Colors.Gray);
        internal string ActivityType { get; set; } = "";
        internal string RawDetail { get; set; } = "";
        internal DateTime Timestamp { get; set; }

        public string ShortName => $"[{Label}]  {Detail}";
        public string FullDetail => RawDetail;
        public string TimeDisplay => Time;
    }

    public partial class DetectionPage : Page
    {
        private bool _isMonitoring;
        private LiveMonitoringSession? _monitoringSession;
        private string? _lastReportPath;
        private string? _lastMetadataPath;

        private readonly Dictionary<string, ActivityTileVM> _tileMap = new();
        private readonly List<ActivityTileVM> _tileList = new();
        private readonly List<TimelineEntryVM> _timeline = new();
        private readonly Dictionary<int, string> _spawnedProcesses = new();

        private readonly ConcurrentQueue<RawActivityUpdate> _activityQueue = new();
        private readonly DispatcherTimer _flushTimer;
        private bool _tilesDirty;

        private const int MaxTimelineEntries = 500;
        private const double BurstWindowSeconds = 3.0;

        public DetectionPage()
        {
            InitializeComponent();
            UpdateResultDisplay("READY", "Enter a process name and start monitoring.");
            Unloaded += DetectionPage_Unloaded;

            _flushTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
            _flushTimer.Tick += FlushActivities;
        }

        private void ProcessInput_TextChanged(object sender, TextChangedEventArgs e)
        {
            HintText.Visibility = string.IsNullOrEmpty(ProcessInput.Text)
                ? Visibility.Visible
                : Visibility.Collapsed;
        }

        private void DropZone_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
                DropZone.BorderBrush = (Brush)FindResource("AccentFillColorDefaultBrush");
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }
            e.Handled = true;
        }

        private void DropZone_DragLeave(object sender, DragEventArgs e)
        {
            DropZone.BorderBrush = (Brush)FindResource("ControlStrokeColorDefaultBrush");
        }

        private void DropZone_Drop(object sender, DragEventArgs e)
        {
            DropZone.BorderBrush = (Brush)FindResource("ControlStrokeColorDefaultBrush");
            if (e.Data.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0)
                ProcessInput.Text = Path.GetFileNameWithoutExtension(files[0]).ToLower();
        }

        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Executables (*.exe)|*.exe",
                Title = "Select process executable"
            };
            if (dlg.ShowDialog() == true)
                ProcessInput.Text = Path.GetFileNameWithoutExtension(dlg.FileName).ToLower();
        }

        private async void StartButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_isMonitoring)
                await StartMonitoringAsync();
            else
                await StopMonitoringAsync();
        }

        public void UpdateResultDisplay(string label, string? summary = null)
        {
            ScoreLabel.Text = label;

            Color badgeColor = label switch
            {
                "MONITORING"   => Color.FromRgb(0x29, 0x80, 0xB9),
                "MALICIOUS"    => Color.FromRgb(0xC0, 0x39, 0x2B),
                "SUSPICIOUS"   => Color.FromRgb(0xF3, 0x9C, 0x12),
                "INCONCLUSIVE" => Color.FromRgb(0x29, 0x80, 0xB9),
                _              => Color.FromRgb(0x27, 0xAE, 0x60)
            };

            SeverityLabel.Text = label;
            SeverityBadge.Background = new SolidColorBrush(Color.FromArgb(0x40,
                badgeColor.R, badgeColor.G, badgeColor.B));
            ResultSummaryText.Text = summary ?? string.Empty;
        }

        private void OnActivityObserved(RawActivityUpdate update)
        {
            _activityQueue.Enqueue(update);
        }

        private void FlushActivities(object? sender, EventArgs e)
        {
            int processed = 0;
            while (processed < 300 && _activityQueue.TryDequeue(out var a))
            {
                processed++;
                ProcessSingleActivity(a);
            }

            if (_tilesDirty)
            {
                _tilesDirty = false;
                EmptyEventsText.Visibility = Visibility.Collapsed;

                EventTiles.ItemsSource = null;
                EventTiles.ItemsSource = _tileList
                    .OrderByDescending(t => t.TotalCount)
                    .ToList();
            }

            if (_reportOpen)
                ReportList.ItemsSource = _timeline.AsEnumerable().Reverse().Take(200).ToList();
        }

        private void ProcessSingleActivity(RawActivityUpdate a)
        {
            _tilesDirty = true;
            string timeStr = a.Timestamp.ToString("HH:mm:ss");

            if (a.ActivityType == "Process")
                _spawnedProcesses[a.ProcessId] = a.ProcessName;

            bool isChildEvent = _spawnedProcesses.TryGetValue(a.ProcessId, out string? childName);

            if (isChildEvent)
            {
                string childKey = $"proc:{childName}:{a.ProcessId}";
                if (!_tileMap.TryGetValue(childKey, out var childTile))
                {
                    childTile = new ActivityTileVM
                    {
                        ActivityType = childKey,
                        DisplayLabel = childName,
                        TileBrush = new SolidColorBrush(Color.FromRgb(0xD3, 0x2F, 0x2F)),
                        IsProcessTile = true,
                        ProcessId = a.ProcessId,
                    };
                    _tileMap[childKey] = childTile;
                    _tileList.Add(childTile);
                }
                childTile.TotalCount++;
                childTile.ProcessTimeline.Add(new TimelineEntryVM
                {
                    Time = timeStr,
                    Label = a.ActivityType,
                    Detail = ShortenPath(a.Detail),
                    ActivityBrush = ToActivityBrush(a.ActivityType),
                    ActivityType = a.ActivityType,
                    RawDetail = a.Detail,
                    Timestamp = a.Timestamp
                });
            }
            else
            {
                if (!_tileMap.TryGetValue(a.ActivityType, out var tile))
                {
                    tile = new ActivityTileVM
                    {
                        ActivityType = a.ActivityType,
                        DisplayLabel = a.ActivityType,
                        TileBrush = ToActivityBrush(a.ActivityType),
                    };
                    _tileMap[a.ActivityType] = tile;
                    _tileList.Add(tile);
                }
                tile.TotalCount++;

                if (!tile.UniqueDetails.TryGetValue(a.Detail, out var detail))
                {
                    detail = new DetailItemVM
                    {
                        ShortName = ShortenPath(a.Detail),
                        FullDetail = a.Detail,
                        FirstSeen = timeStr,
                        ActivityBrush = tile.TileBrush,
                    };
                    tile.UniqueDetails[a.Detail] = detail;
                }
                detail.Count++;
                detail.LastSeen = timeStr;
            }

            string timelineDetail = isChildEvent
                ? $"{a.ProcessName} \u2192 {ShortenPath(a.Detail)}"
                : ShortenPath(a.Detail);

            if (_timeline.Count > 0)
            {
                var last = _timeline[^1];
                if (last.ActivityType == a.ActivityType &&
                    last.RawDetail == a.Detail &&
                    (a.Timestamp - last.Timestamp).TotalSeconds < BurstWindowSeconds)
                {
                    last.Count++;
                    last.Time = timeStr;
                    return;
                }
            }

            _timeline.Add(new TimelineEntryVM
            {
                Time = timeStr,
                Label = a.ActivityType,
                Detail = timelineDetail,
                ActivityBrush = ToActivityBrush(a.ActivityType),
                ActivityType = a.ActivityType,
                RawDetail = a.Detail,
                Timestamp = a.Timestamp
            });

            if (_timeline.Count > MaxTimelineEntries)
                _timeline.RemoveAt(0);
        }

        private void EventTile_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is ActivityTileVM tile)
            {
                if (tile.IsProcessTile)
                {
                    DetailTitle.Text = $"{tile.DisplayLabel} (PID {tile.ProcessId}) -- {tile.TotalCount:N0} events";
                    TimelineList.ItemsSource = tile.ProcessTimeline
                        .AsEnumerable().Reverse().Take(200).ToList();
                }
                else
                {
                    DetailTitle.Text = $"{tile.DisplayLabel} -- {tile.TotalCount:N0} total, {tile.UniqueDetails.Count:N0} unique";
                    TimelineList.ItemsSource = tile.DetailList;
                }
                DetailRowDef.Height = new GridLength(220);
            }
        }

        private void CloseDetail_Click(object sender, RoutedEventArgs e)
        {
            DetailRowDef.Height = new GridLength(0);
        }

        private bool _reportOpen;

        private void ReportHeader_Click(object sender, RoutedEventArgs e)
        {
            if (_reportOpen)
                CollapseReport();
            else
                ExpandReport();
        }

        private void GreyOverlay_MouseDown(object sender, MouseButtonEventArgs e)
            => CollapseReport();

        private void ExpandReport()
        {
            ReportList.ItemsSource = _timeline.AsEnumerable().Reverse().Take(200).ToList();
            GreyOverlay.Visibility = Visibility.Visible;
            ReportChevron.Text = "\u25B2";
            _reportOpen = true;

            var anim = new DoubleAnimation
            {
                To = 260,
                Duration = TimeSpan.FromMilliseconds(280),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            ReportCardContent.BeginAnimation(MaxHeightProperty, anim);
        }

        private void CollapseReport()
        {
            ReportChevron.Text = "\u25BC";
            _reportOpen = false;

            var anim = new DoubleAnimation
            {
                To = 0,
                Duration = TimeSpan.FromMilliseconds(220),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
            };
            anim.Completed += (_, _) => GreyOverlay.Visibility = Visibility.Collapsed;
            ReportCardContent.BeginAnimation(MaxHeightProperty, anim);
        }

        private void ClearAll()
        {
            _tileMap.Clear();
            _tileList.Clear();
            _timeline.Clear();
            _spawnedProcesses.Clear();
            _lastReportPath = null;
            while (_activityQueue.TryDequeue(out _)) { }
            EventTiles.ItemsSource = null;
            TimelineList.ItemsSource = null;
            ReportList.ItemsSource = null;
            EmptyEventsText.Visibility = Visibility.Visible;
            DetailRowDef.Height = new GridLength(0);
            DownloadReportButton.Visibility = Visibility.Collapsed;
        }

        private async Task StartMonitoringAsync()
        {
            string target = ProcessInput.Text.Trim();
            if (string.IsNullOrWhiteSpace(target))
            {
                MessageBox.Show("Enter a process name or browse for an executable first.",
                    "Process Required", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            string dataPath = Path.Combine(AppContext.BaseDirectory, "data.json");

            bool enablePsLogging = false;
            string psStatus = "";
            try
            {
                if (LiveMonitoringSession.IsScriptBlockLoggingEnabled())
                {
                    enablePsLogging = true;
                }
                else
                {
                    var answer = MessageBox.Show(
                        "PowerShell ScriptBlock logging is not enabled.\n\n" +
                        "Enable it now to capture PowerShell command content?\n\n" +
                        "This writes a policy registry key under HKLM and requires admin rights. " +
                        "Process spawns will still be monitored regardless.",
                        "Enable PowerShell Detection",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Question);

                    if (answer == MessageBoxResult.Yes)
                    {
                        LiveMonitoringSession.EnableScriptBlockLogging();
                        enablePsLogging = true;
                    }
                    else
                    {
                        psStatus = " | PowerShell script content: not monitored";
                    }
                }
            }
            catch
            {
                psStatus = " | PowerShell detection unavailable (requires admin)";
            }

            try
            {
                ClearAll();
                _monitoringSession?.Dispose();
                _monitoringSession = new LiveMonitoringSession();
                _monitoringSession.ActivityObserved += OnActivityObserved;
                _monitoringSession.Start(target, dataPath, enablePsLogging);

                _isMonitoring = true;
                _flushTimer.Start();
                ProcessInput.IsEnabled = false;
                StartButton.Content = "Stop";
                UpdateResultDisplay("MONITORING",
                    $"Watching '{Path.GetFileNameWithoutExtension(target).ToLowerInvariant()}' -- all activity shown live.{psStatus}");
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _flushTimer.Stop();
                _monitoringSession?.Dispose();
                _monitoringSession = null;
                UpdateResultDisplay("READY", "Enter a process name and start monitoring.");
                MessageBox.Show(ex.Message, "Unable to Start Monitoring",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task StopMonitoringAsync()
        {
            if (_monitoringSession == null) return;

            StartButton.IsEnabled = false;
            _flushTimer.Stop();

            while (_activityQueue.TryDequeue(out var a))
                ProcessSingleActivity(a);
            _tilesDirty = false;
            EventTiles.ItemsSource = _tileList.OrderByDescending(t => t.TotalCount).ToList();

            try
            {
                var session = _monitoringSession;
                var result = await Task.Run(session.Stop);
                session.ActivityObserved -= OnActivityObserved;
                session.Dispose();
                _monitoringSession = null;

                _isMonitoring = false;
                ProcessInput.IsEnabled = true;
                StartButton.Content = "Start";
                UpdateResultDisplay(result.OverallGrade, result.OverallStory);

                _lastReportPath = SaveReport(result);
                DownloadReportButton.Visibility = Visibility.Visible;

                _lastMetadataPath = SaveMetadata(result);
                DownloadMetadataButton.Visibility = Visibility.Visible;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Unable to Stop Monitoring",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                StartButton.IsEnabled = true;
            }
        }

        private void DetectionPage_Unloaded(object sender, RoutedEventArgs e)
        {
            _flushTimer.Stop();
            if (_monitoringSession == null) return;

            try
            {
                _monitoringSession.ActivityObserved -= OnActivityObserved;
                _monitoringSession.Dispose();
            }
            catch { }
            finally
            {
                _monitoringSession = null;
                _isMonitoring = false;
            }
        }

        private void DownloadReport_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_lastReportPath) || !File.Exists(_lastReportPath))
            {
                MessageBox.Show("No report available.", "Report", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Save Report",
                FileName = Path.GetFileName(_lastReportPath),
                Filter = "Text files (*.txt)|*.txt",
                DefaultExt = ".txt"
            };

            if (dlg.ShowDialog() == true)
            {
                File.Copy(_lastReportPath, dlg.FileName, overwrite: true);
                Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
            }
        }

        private string? SaveReport(MonitoringSessionResult result)
        {
            try
            {
                string reportsDir = Path.Combine(AppContext.BaseDirectory, "reports");
                Directory.CreateDirectory(reportsDir);

                string timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
                string fileName = $"{result.TargetProcess}_{timestamp}.txt";
                string filePath = Path.Combine(reportsDir, fileName);

                string reportText = GenerateReport(result);
                File.WriteAllText(filePath, reportText, Encoding.UTF8);
                return filePath;
            }
            catch
            {
                return null;
            }
        }

        private string? SaveMetadata(MonitoringSessionResult result)
        {
            try
            {
                string reportsDir = Path.Combine(AppContext.BaseDirectory, "reports");
                Directory.CreateDirectory(reportsDir);

                string timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
                string fileName = $"{result.TargetProcess}_{timestamp}_metadata.txt";
                string filePath = Path.Combine(reportsDir, fileName);

                string metadataText = MetadataExporter.Generate(result.MergedProfiles);
                File.WriteAllText(filePath, metadataText, Encoding.UTF8);
                return filePath;
            }
            catch
            {
                return null;
            }
        }

        private void DownloadMetadata_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_lastMetadataPath) || !File.Exists(_lastMetadataPath))
            {
                MessageBox.Show("No metadata available.", "Metadata", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Save Lifecycle Metadata",
                FileName = Path.GetFileName(_lastMetadataPath),
                Filter = "Text files (*.txt)|*.txt",
                DefaultExt = ".txt"
            };

            if (dlg.ShowDialog() == true)
            {
                File.Copy(_lastMetadataPath, dlg.FileName, overwrite: true);
                Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
            }
        }

        private string GenerateReport(MonitoringSessionResult result)
        {
            var sb = new StringBuilder();
            string line = new('═', 60);
            string thinLine = new('─', 60);

            sb.AppendLine(line);
            sb.AppendLine("  CYBER BEHAVIOUR PROFILING REPORT");
            sb.AppendLine(line);
            sb.AppendLine();
            sb.AppendLine($"  Date:     {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"  Target:   {result.TargetProcess}");
            sb.AppendLine($"  Grade:    {result.OverallGrade}");

            var top = result.Narratives.FirstOrDefault();
            if (top != null)
                sb.AppendLine($"  Duration: {top.TotalSeconds:F1} seconds");

            sb.AppendLine();

            sb.AppendLine(thinLine);
            sb.AppendLine("  VERDICT");
            sb.AppendLine(thinLine);
            sb.AppendLine();
            sb.AppendLine($"  {GetReportVerdictText(result.OverallGrade)}");
            sb.AppendLine();

            var nonSafe = result.Narratives
                .Where(n => n.Grade != "SAFE")
                .ToList();

            if (nonSafe.Count == 0)
            {
                sb.AppendLine("  No suspicious activity was observed during this session.");
                sb.AppendLine();
            }

            foreach (var narrative in nonSafe)
            {
                var section = new StringBuilder();
                bool hasContent = false;

                if (narrative.SpawnedCommands.Count > 0)
                {
                    section.AppendLine("  Processes launched:");
                    var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var (childName, cmdLine) in narrative.SpawnedCommands)
                    {
                        string label = DescribeCommand(childName, cmdLine);
                        if (seen.Add(label))
                            section.AppendLine($"    → {label}");
                    }
                    section.AppendLine();
                    hasContent = true;
                }

                if (narrative.DroppedFiles.Count > 0)
                {
                    section.AppendLine("  Files dropped:");
                    foreach (var path in narrative.DroppedFiles.Distinct(StringComparer.OrdinalIgnoreCase))
                        section.AppendLine($"    → {Path.GetFileName(path)}  [{path}]");
                    section.AppendLine();
                    hasContent = true;
                }

                var credSteps = narrative.Timeline
                    .Where(s => s.Tactic == "CredentialAccess")
                    .ToList();
                if (credSteps.Count > 0)
                {
                    section.AppendLine("  Credential files accessed:");
                    foreach (var s in DeduplicateSteps(credSteps))
                    {
                        section.AppendLine($"    → {s.Headline}");
                        if (!string.IsNullOrWhiteSpace(s.Detail) && s.Detail != s.Headline)
                            section.AppendLine($"      Path: {s.Detail}");
                    }
                    section.AppendLine();
                    hasContent = true;
                }

                var registrySteps = narrative.Timeline
                    .Where(s => s.Category == "Registry")
                    .ToList();
                if (registrySteps.Count > 0)
                {
                    section.AppendLine("  Registry keys modified:");
                    foreach (var s in DeduplicateSteps(registrySteps))
                        section.AppendLine($"    → {s.Headline}");
                    section.AppendLine();
                    hasContent = true;
                }

                var networkSteps = narrative.Timeline
                    .Where(s => s.Category == "Network")
                    .ToList();
                if (networkSteps.Count > 0)
                {
                    section.AppendLine("  Network connections:");
                    var seenNet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var s in networkSteps)
                    {
                        string dest = s.Detail ?? s.Headline;
                        if (seenNet.Add(dest))
                            section.AppendLine($"    → {dest}");
                    }
                    section.AppendLine();
                    hasContent = true;
                }

                var deleted = narrative.DeletedFiles
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Where(p => !IsNoisyDeletedFile(p))
                    .ToList();
                if (deleted.Count > 0)
                {
                    section.AppendLine($"  Files deleted ({deleted.Count} total):");
                    foreach (var path in deleted.Take(10))
                        section.AppendLine($"    → {Path.GetFileName(path)}  [{path}]");
                    if (deleted.Count > 10)
                        section.AppendLine($"    ... and {deleted.Count - 10} more files");
                    section.AppendLine();
                    hasContent = true;
                }

                if (narrative.AnomalyFindings.Count > 0)
                {
                    section.AppendLine("  Unusual activity:");
                    foreach (var a in narrative.AnomalyFindings)
                        section.AppendLine($"    → {SimplifyAnomaly(a)}");
                    section.AppendLine();
                    hasContent = true;
                }

                bool hasSelfDelete = narrative.DecisionReasons
                    .Any(r => r.Contains("Self-Deletion", StringComparison.OrdinalIgnoreCase));
                if (hasSelfDelete)
                {
                    section.AppendLine("  Self-deletion:");
                    section.AppendLine("    → The process attempted to delete its own files after running.");
                    section.AppendLine();
                    hasContent = true;
                }

                if (!hasContent) continue;

                sb.AppendLine(thinLine);
                sb.AppendLine($"  PROCESS — {narrative.ProcessName} (PID {narrative.ProcessId})");
                sb.AppendLine($"  {(narrative.IsSigned ? $"Verified (signed by {narrative.SignerName})" : "Not verified (no digital signature)")}");
                sb.AppendLine(thinLine);
                sb.AppendLine();
                sb.Append(section);
            }

            sb.AppendLine(line);
            sb.AppendLine("  END OF REPORT");
            sb.AppendLine(line);

            return sb.ToString();
        }

        private static string GetReportVerdictText(string grade) => grade switch
        {
            "MALICIOUS" => "Malicious behaviour confirmed.",
            "SUSPICIOUS" => "Suspicious behaviour detected.",
            "INCONCLUSIVE" => "Suspicious behaviour was observed, but the evidence was limited.",
            _ => "No malicious behaviour was confirmed."
        };

        private static string DescribeCommand(string childName, string cmdLine)
        {
            string lowerChild = childName.ToLowerInvariant();
            string lowerCmd   = (cmdLine ?? "").ToLowerInvariant();

            if (MapToData._blacklistedProcesses.Contains(lowerChild) ||
                MapToData._blacklistedProcesses.Contains(lowerChild + ".exe"))
                return $"{childName} — known malicious tool";

            var cmdMatch = MapToData.CommandRules
                .FirstOrDefault(r => lowerCmd.Contains(r.Pattern));
            if (cmdMatch != null && !string.IsNullOrEmpty(cmdMatch.Description))
                return $"{childName} — {cmdMatch.Description}";

            var lolMatch = MapToData.LolbinRules
                .FirstOrDefault(r => lowerChild.Contains(r.Pattern) || r.Pattern.Contains(lowerChild));
            if (lolMatch != null && !string.IsNullOrEmpty(lolMatch.Description))
                return $"{childName} — {lolMatch.Description}";

            var discMatch = MapToData.DiscoveryRules
                .FirstOrDefault(r => lowerChild.Contains(r.Pattern));
            if (discMatch != null && !string.IsNullOrEmpty(discMatch.Description))
                return $"{childName} — {discMatch.Description}";

            return string.IsNullOrWhiteSpace(cmdLine) ? childName : cmdLine;
        }

        private static string SimplifyAnomaly(string anomaly)
        {
            string lower = anomaly.ToLowerInvariant();
            if (lower.Contains("write rate"))
                return "Unusually high number of files written in a short time";
            if (lower.Contains("delete rate"))
                return "Unusually high number of files deleted in a short time";
            if (lower.Contains("event rate"))
                return "Unusually high amount of system activity in a short time";
            if (lower.Contains("network"))
                return "Unusually high number of network connections";
            return "Unusual activity pattern detected";
        }

        private static bool IsNoisyDeletedFile(string path)
        {
            string lower = path.ToLowerInvariant();
            if (lower.Contains("\\customdestinations\\") || lower.Contains("\\recent\\"))
                return true;
            if (lower.EndsWith(".tmp") && (lower.Contains("\\appdata\\") || lower.Contains("\\temp\\")))
                return true;
            return false;
        }

        private static List<NarrativeStep> DeduplicateSteps(List<NarrativeStep> steps)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var result = new List<NarrativeStep>();
            foreach (var s in steps)
            {
                if (seen.Add(s.Headline))
                    result.Add(s);
            }
            return result;
        }

        private static SolidColorBrush ToActivityBrush(string activityType) => activityType switch
        {
            "File Write" => new(Color.FromRgb(0x34, 0x98, 0xDB)),
            "File Open"  => new(Color.FromRgb(0x29, 0x80, 0xB9)),
            "File Read"  => new(Color.FromRgb(0x1A, 0xBC, 0x9C)),
            "File Delete" => new(Color.FromRgb(0xE6, 0x7E, 0x22)),
            "File Rename" => new(Color.FromRgb(0x95, 0xA5, 0xA6)),
            "Registry"    => new(Color.FromRgb(0x8E, 0x44, 0xAD)),
            "Network"     => new(Color.FromRgb(0xE7, 0x4C, 0x3C)),
            "DNS"         => new(Color.FromRgb(0xD3, 0x54, 0x00)),
            "Process"     => new(Color.FromRgb(0xC0, 0x39, 0x2B)),
            "Credential Access" => new(Color.FromRgb(0xF3, 0x9C, 0x12)),
            "PowerShell"        => new(Color.FromRgb(0x01, 0x63, 0x8A)),
            _ => new(Colors.Gray)
        };

        private static string ShortenPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;

            if (path.StartsWith("\\REGISTRY\\", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase))
            {
                var parts = path.Split('\\');
                return parts.Length > 2
                    ? "...\\" + string.Join("\\", parts[^2..])
                    : path;
            }

            if (path.Length > 60)
            {
                string? dir = Path.GetDirectoryName(path);
                string file = Path.GetFileName(path);
                if (dir != null && dir.Length > 30)
                {
                    var parts = dir.Split('\\');
                    string shortDir = parts.Length > 2
                        ? parts[0] + "\\...\\" + parts[^1]
                        : dir;
                    return shortDir + "\\" + file;
                }
            }

            return path;
        }
    }
}
