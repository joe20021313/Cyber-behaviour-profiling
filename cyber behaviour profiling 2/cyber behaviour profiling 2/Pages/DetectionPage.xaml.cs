using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
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
        public string OwnerProcess { get; set; } = "";
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
        private bool _weEnabledScriptBlockLogging;
        private LiveMonitoringSession? _monitoringSession;
        private string? _lastReportPath;
        private string? _lastMetadataPath;
        private MonitoringSessionResult? _lastResult;

        private readonly ObservableCollection<string> _selectedProcesses = new();

        private readonly Dictionary<string, ActivityTileVM> _tileMap = new();
        private readonly List<ActivityTileVM> _tileList = new();
        private readonly List<TimelineEntryVM> _timeline = new();
        private readonly Dictionary<int, string> _spawnedProcesses = new();

        private readonly ConcurrentQueue<RawActivityUpdate> _activityQueue = new();
        private readonly DispatcherTimer _flushTimer;
        private bool _tilesDirty;

        private const int ActivityFlushBatchSize = 300;
        private const int MaxTimelineEntries = 500;
        private const int RecentTimelinePreviewCount = 200;
        private const double BurstWindowSeconds = 3.0;
        private const int ReportFilePreviewCount = 10;

        public DetectionPage()
        {
            InitializeComponent();
            UpdateResultDisplay("READY", "Select processes and start monitoring.");
            Unloaded += DetectionPage_Unloaded;

            SelectedProcessList.ItemsSource = _selectedProcesses;
            RefreshProcessList();

            _flushTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
            _flushTimer.Tick += FlushActivities;
        }

        private void RefreshProcessList()
        {
            var processes = Process.GetProcesses()
                .Select(p => p.ProcessName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .ToList();

            ProcessDropdown.ItemsSource = processes;
        }

        private void AddSelectedProcess(string processName)
        {
            string normalizedName = Path.GetFileNameWithoutExtension(processName).ToLowerInvariant();
            if (!_selectedProcesses.Contains(normalizedName, StringComparer.OrdinalIgnoreCase))
                _selectedProcesses.Add(normalizedName);
        }

        private void RefreshProcessList_Click(object sender, RoutedEventArgs e)
        {
            RefreshProcessList();
        }

        private void ProcessDropdown_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            DropdownHint.Visibility = ProcessDropdown.SelectedItem != null
                ? Visibility.Collapsed
                : Visibility.Visible;
        }

        private void AddProcess_Click(object sender, RoutedEventArgs e)
        {
            if (ProcessDropdown.SelectedItem is not string selected) return;
            AddSelectedProcess(selected);
        }

        private void RemoveProcess_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string name)
                _selectedProcesses.Remove(name);
        }

        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Executables (*.exe)|*.exe",
                Title = "Select process executable(s)",
                Multiselect = true
            };
            if (dlg.ShowDialog() == true)
            {
                foreach (var file in dlg.FileNames)
                    AddSelectedProcess(file);
            }
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
            while (processed < ActivityFlushBatchSize && _activityQueue.TryDequeue(out var activity))
            {
                processed++;
                ProcessSingleActivity(activity);
            }

            if (_tilesDirty)
            {
                _tilesDirty = false;
                EmptyEventsText.Visibility = Visibility.Collapsed;
                RebuildGroupedTiles();
            }

            if (_reportOpen)
                ReportList.ItemsSource = GetRecentTimelineEntries(_timeline);
        }

        private void ProcessSingleActivity(RawActivityUpdate activity)
        {
            _tilesDirty = true;
            string timeText = activity.Timestamp.ToString("HH:mm:ss");

            TrackSpawnedProcess(activity);

            bool isSpawnedProcessEvent = _spawnedProcesses.TryGetValue(activity.ProcessId, out string? spawnedProcessName);
            string ownerProcess = ResolveOwnerProcess(activity);

            if (isSpawnedProcessEvent && !string.IsNullOrEmpty(spawnedProcessName))
                RecordSpawnedProcessActivity(activity, spawnedProcessName, ownerProcess, timeText);
            else
                RecordActivityDetail(activity, ownerProcess, timeText);

            AppendTimelineEntry(activity, timeText, isSpawnedProcessEvent);

            if (_timeline.Count > MaxTimelineEntries)
                _timeline.RemoveAt(0);
        }

        private void TrackSpawnedProcess(RawActivityUpdate activity)
        {
            if (activity.ActivityType == "Process")
                _spawnedProcesses[activity.ProcessId] = activity.ProcessName;
        }

        private static string ResolveOwnerProcess(RawActivityUpdate activity)
            => !string.IsNullOrEmpty(activity.TargetProcess) ? activity.TargetProcess : activity.ProcessName;

        private void RecordSpawnedProcessActivity(RawActivityUpdate activity, string spawnedProcessName,
            string ownerProcess, string timeText)
        {
            var tile = GetOrCreateSpawnedProcessTile(spawnedProcessName, activity.ProcessId, ownerProcess);
            tile.TotalCount++;
            tile.ProcessTimeline.Add(new TimelineEntryVM
            {
                Time = timeText,
                Label = activity.ActivityType,
                Detail = ShortenPath(activity.Detail),
                ActivityBrush = ToActivityBrush(activity.ActivityType),
                ActivityType = activity.ActivityType,
                RawDetail = activity.Detail,
                Timestamp = activity.Timestamp
            });
        }

        private ActivityTileVM GetOrCreateSpawnedProcessTile(string spawnedProcessName, int processId,
            string ownerProcess)
        {
            string tileKey = $"proc:{spawnedProcessName}:{processId}";
            if (_tileMap.TryGetValue(tileKey, out var tile))
                return tile;

            tile = new ActivityTileVM
            {
                ActivityType = tileKey,
                DisplayLabel = spawnedProcessName,
                OwnerProcess = ownerProcess,
                TileBrush = new SolidColorBrush(Color.FromRgb(0xD3, 0x2F, 0x2F)),
                IsProcessTile = true,
                ProcessId = processId,
            };
            _tileMap[tileKey] = tile;
            _tileList.Add(tile);
            return tile;
        }

        private void RecordActivityDetail(RawActivityUpdate activity, string ownerProcess, string timeText)
        {
            var tile = GetOrCreateActivityTile(ownerProcess, activity.ActivityType, activity.ProcessId);
            tile.TotalCount++;

            if (!tile.UniqueDetails.TryGetValue(activity.Detail, out var detail))
            {
                detail = new DetailItemVM
                {
                    ShortName = ShortenPath(activity.Detail),
                    FullDetail = activity.Detail,
                    FirstSeen = timeText,
                    ActivityBrush = tile.TileBrush,
                };
                tile.UniqueDetails[activity.Detail] = detail;
            }

            detail.Count++;
            detail.LastSeen = timeText;
        }

        private ActivityTileVM GetOrCreateActivityTile(string ownerProcess, string activityType, int processId)
        {
            string tileKey = $"{ownerProcess}:{activityType}";
            if (_tileMap.TryGetValue(tileKey, out var tile))
                return tile;

            tile = new ActivityTileVM
            {
                ActivityType = tileKey,
                DisplayLabel = activityType,
                OwnerProcess = ownerProcess,
                TileBrush = ToActivityBrush(activityType),
                ProcessId = processId,
            };
            _tileMap[tileKey] = tile;
            _tileList.Add(tile);
            return tile;
        }

        private void AppendTimelineEntry(RawActivityUpdate activity, string timeText, bool isSpawnedProcessEvent)
        {
            if (TryMergeTimelineBurst(activity, timeText))
                return;

            string detailText = isSpawnedProcessEvent
                ? $"{activity.ProcessName} \u2192 {ShortenPath(activity.Detail)}"
                : ShortenPath(activity.Detail);

            _timeline.Add(new TimelineEntryVM
            {
                Time = timeText,
                Label = activity.ActivityType,
                Detail = detailText,
                ActivityBrush = ToActivityBrush(activity.ActivityType),
                ActivityType = activity.ActivityType,
                RawDetail = activity.Detail,
                Timestamp = activity.Timestamp
            });
        }

        private bool TryMergeTimelineBurst(RawActivityUpdate activity, string timeText)
        {
            if (_timeline.Count == 0)
                return false;

            var last = _timeline[^1];
            if (last.ActivityType != activity.ActivityType ||
                last.RawDetail != activity.Detail ||
                (activity.Timestamp - last.Timestamp).TotalSeconds >= BurstWindowSeconds)
            {
                return false;
            }

            last.Count++;
            last.Time = timeText;
            return true;
        }

        private static List<TimelineEntryVM> GetRecentTimelineEntries(IEnumerable<TimelineEntryVM> entries)
            => entries.Reverse().Take(RecentTimelinePreviewCount).ToList();

        private void RebuildGroupedTiles()
        {
            TileContainer.Children.Clear();

            var grouped = _tileList
                .GroupBy(t => t.OwnerProcess, StringComparer.OrdinalIgnoreCase)
                .OrderBy(g => g.Key);

            foreach (var group in grouped)
            {
                var first = group.First();
                string headerText = first.ProcessId > 0
                    ? $"{group.Key.ToUpper()} (PID {first.ProcessId})"
                    : group.Key.ToUpper();

                var header = new TextBlock
                {
                    Text = headerText,
                    Style = (Style)FindResource("SectionLabel"),
                    Margin = new Thickness(0, 8, 0, 6),
                    FontSize = 12,
                };
                TileContainer.Children.Add(header);

                var wrap = new WrapPanel { Orientation = Orientation.Horizontal };
                foreach (var tile in group.OrderByDescending(t => t.TotalCount))
                    wrap.Children.Add(CreateTileButton(tile));
                TileContainer.Children.Add(wrap);
            }
        }

        private Button CreateTileButton(ActivityTileVM tile)
        {
            var countText = new TextBlock
            {
                FontSize = 10,
                Foreground = Brushes.White,
                FontWeight = FontWeights.SemiBold,
            };
            countText.SetBinding(TextBlock.TextProperty,
                new System.Windows.Data.Binding("CountLabel") { Source = tile });

            var badge = new Border
            {
                Background = tile.TileBrush,
                CornerRadius = new CornerRadius(3),
                Padding = new Thickness(5, 2, 5, 2),
                Margin = new Thickness(0, 0, 6, 0),
                Child = countText,
            };

            var label = new TextBlock
            {
                Text = tile.DisplayLabel,
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center,
                Foreground = (Brush)FindResource("TextFillColorPrimaryBrush"),
            };

            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Grid.SetRow(label, 0);
            var badgePanel = new StackPanel { Orientation = Orientation.Horizontal };
            badgePanel.Children.Add(badge);
            Grid.SetRow(badgePanel, 1);
            grid.Children.Add(label);
            grid.Children.Add(badgePanel);

            var border = new Border
            {
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12, 10, 12, 10),
                Width = 140,
                Height = 82,
                Background = (Brush)FindResource("ControlFillColorDefaultBrush"),
                BorderThickness = new Thickness(1),
                BorderBrush = (Brush)FindResource("ControlStrokeColorDefaultBrush"),
                Child = grid,
            };

            var btn = new Button
            {
                Style = (Style)FindResource("TileButton"),
                Tag = tile,
                Width = 140,
                Height = 82,
                Margin = new Thickness(0, 0, 10, 10),
                Cursor = Cursors.Hand,
                Content = border,
            };
            btn.Click += EventTile_Click;
            return btn;
        }

        private void EventTile_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is ActivityTileVM tile)
            {
                if (tile.IsProcessTile)
                {
                    DetailTitle.Text = $"{tile.DisplayLabel} (PID {tile.ProcessId}) -- {tile.TotalCount:N0} events";
                    TimelineList.ItemsSource = GetRecentTimelineEntries(tile.ProcessTimeline);
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
                CollapseReportPanel();
            else
                ExpandReportPanel();
        }

        private void GreyOverlay_MouseDown(object sender, MouseButtonEventArgs e)
            => CollapseReportPanel();

        private void ExpandReportPanel()
        {
            ReportList.ItemsSource = GetRecentTimelineEntries(_timeline);
            GreyOverlay.Visibility = Visibility.Visible;
            ReportChevron.Text = "\u25BC";
            _reportOpen = true;

            var anim = new DoubleAnimation
            {
                To = 260,
                Duration = TimeSpan.FromMilliseconds(280),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            ReportCardContent.BeginAnimation(MaxHeightProperty, anim);
        }

        private void CollapseReportPanel()
        {
            ReportChevron.Text = "\u25B2";
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
            _lastMetadataPath = null;
            _lastResult = null;
            while (_activityQueue.TryDequeue(out _)) { }
            TileContainer.Children.Clear();
            TimelineList.ItemsSource = null;
            ReportList.ItemsSource = null;
            EmptyEventsText.Visibility = Visibility.Visible;
            DetailRowDef.Height = new GridLength(0);
            ShowResultsButton.Visibility = Visibility.Collapsed;
        }

        private Task StartMonitoringAsync()
        {
            if (_selectedProcesses.Count == 0)
            {
                MessageBox.Show("Select at least one process to monitor.",
                    "Process Required", MessageBoxButton.OK, MessageBoxImage.Information);
                return Task.CompletedTask;
            }

            string dataPath = Path.Combine(AppContext.BaseDirectory, "data.json");
            bool enablePsLogging = PrepareScriptBlockLogging();

            try
            {
                ClearAll();
                _monitoringSession?.Dispose();
                _monitoringSession = new LiveMonitoringSession();
                _monitoringSession.ActivityObserved += OnActivityObserved;
                _monitoringSession.Start(_selectedProcesses.ToList(), dataPath, enablePsLogging);

                _flushTimer.Start();
                SetMonitoringUiState(isMonitoring: true);
                string targetNames = string.Join(", ", _selectedProcesses);
                UpdateResultDisplay("MONITORING", $"Watching {targetNames}");
            }
            catch (Exception ex)
            {
                _flushTimer.Stop();
                _monitoringSession?.Dispose();
                _monitoringSession = null;
                SetMonitoringUiState(isMonitoring: false);
                UpdateResultDisplay("READY", "Select processes and start monitoring.");
                MessageBox.Show(ex.Message, "Unable to Start Monitoring",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }

            return Task.CompletedTask;
        }

        private bool PrepareScriptBlockLogging()
        {
            try
            {
                if (LiveMonitoringSession.IsScriptBlockLoggingEnabled())
                    return true;

                var answer = MessageBox.Show(
                    "PowerShell ScriptBlock logging is not enabled.\n\n" +
                    "Enable it?\n\n" +
                    "This writes a policy registry key under HKLM and requires admin rights." +
                    "Process spawns will still be monitored regardless.",
                    "Enable PowerShell Detection",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (answer != MessageBoxResult.Yes)
                    return false;

                LiveMonitoringSession.EnableScriptBlockLogging();
                _weEnabledScriptBlockLogging = true;
                return true;
            }
            catch
            {
                return false;
            }
        }

        private void SetMonitoringUiState(bool isMonitoring)
        {
            _isMonitoring = isMonitoring;
            ProcessDropdown.IsEnabled = !isMonitoring;
            StartButton.Content = isMonitoring ? "Stop" : "Start";
        }

        private async Task StopMonitoringAsync()
        {
            if (_monitoringSession == null) return;

            StartButton.IsEnabled = false;
            _flushTimer.Stop();

            while (_activityQueue.TryDequeue(out var a))
                ProcessSingleActivity(a);
            _tilesDirty = false;
            RebuildGroupedTiles();

            try
            {
                var session = _monitoringSession;
                var result = await Task.Run(session.Stop);
                session.ActivityObserved -= OnActivityObserved;
                session.Dispose();
                _monitoringSession = null;

                RestoreScriptBlockLogging();

                SetMonitoringUiState(isMonitoring: false);
                UpdateResultDisplay(result.OverallGrade, GetReportVerdictText(result.OverallGrade));

                _lastResult = result;
                _lastReportPath = SaveReport(result);
                _lastMetadataPath = SaveMetadata(result);
                ShowResultsButton.Visibility = Visibility.Visible;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error",
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
            RestoreScriptBlockLogging();
            ReleaseMonitoringSession();
        }

        private void RestoreScriptBlockLogging()
        {
            if (!_weEnabledScriptBlockLogging)
                return;

            try
            {
                LiveMonitoringSession.DisableScriptBlockLogging();
            }
            catch
            {
            }
            finally
            {
                _weEnabledScriptBlockLogging = false;
            }
        }

        private void ReleaseMonitoringSession()
        {
            if (_monitoringSession == null)
                return;

            try
            {
                _monitoringSession.ActivityObserved -= OnActivityObserved;
                _monitoringSession.Dispose();
            }
            catch
            {
            }
            finally
            {
                _monitoringSession = null;
                SetMonitoringUiState(isMonitoring: false);
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
                FileName = Path.ChangeExtension(Path.GetFileName(_lastReportPath), "md"),
                Filter = "Markdown files (*.md)|*.md|Text files (*.txt)|*.txt",
                DefaultExt = ".md"
            };

            if (dlg.ShowDialog() == true)
            {
                File.Copy(_lastReportPath, dlg.FileName, overwrite: true);
                Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
            }
        }

        private string? SaveReport(MonitoringSessionResult result)
            => SaveResultArtifact(result, null, GenerateMarkdownReport);

        private string? SaveMetadata(MonitoringSessionResult result)
            => SaveResultArtifact(result, "metadata", r => MetadataExporter.Generate(r.MergedProfiles));

        private static string? SaveResultArtifact(MonitoringSessionResult result, string? suffix,
            Func<MonitoringSessionResult, string> contentFactory)
        {
            try
            {
                string reportsDir = EnsureReportsDirectory();
                string timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
                string safeName = string.Join("_", result.TargetProcesses);
                string fileName = string.IsNullOrEmpty(suffix)
                    ? $"{safeName}_{timestamp}.txt"
                    : $"{safeName}_{timestamp}_{suffix}.txt";
                string filePath = Path.Combine(reportsDir, fileName);

                File.WriteAllText(filePath, contentFactory(result), Encoding.UTF8);
                return filePath;
            }
            catch
            {
                return null;
            }
        }

        private static string EnsureReportsDirectory()
        {
            string reportsDir = Path.Combine(AppContext.BaseDirectory, "reports");
            Directory.CreateDirectory(reportsDir);
            return reportsDir;
        }

        private void ShowResults_Click(object sender, RoutedEventArgs e)
        {
            if (_lastResult == null) return;
            string markdown = GenerateMarkdownReport(_lastResult);
            var window = new ResultsWindow(markdown, _lastReportPath, _lastMetadataPath)
            {
                Owner = Window.GetWindow(this)
            };
            window.ShowDialog();
        }

        private static string GenerateMarkdownReport(MonitoringSessionResult result)
        {
            var sb = new StringBuilder();

            sb.AppendLine("# Cyber Behaviour Profiling Report");
            sb.AppendLine();
            sb.AppendLine($"**Date:** {DateTime.Now:yyyy-MM-dd HH:mm:ss}  ");
            foreach (var target in result.TargetProcesses)
                sb.AppendLine($"**Target:** {target}  ");
            sb.AppendLine($"**Overall Grade:** {result.OverallGrade}  ");
            sb.AppendLine();
            sb.AppendLine("---");
            sb.AppendLine();
            sb.AppendLine("## Verdict");
            sb.AppendLine();
            sb.AppendLine(GetReportVerdictText(result.OverallGrade));
            sb.AppendLine();

            var reportNarratives = result.Narratives
                .Where(n => !AttackNarrator.IsPlaceholderNarrative(n))
                .ToList();

            if (reportNarratives.Count == 0)
            {
                sb.AppendLine("> No monitored process activity was captured during the monitoring window.");
                sb.AppendLine();
            }

            foreach (var narrative in reportNarratives)
            {
                sb.AppendLine("---");
                sb.AppendLine();
                sb.AppendLine($"## {narrative.ProcessName} (PID {narrative.ProcessId}) — {narrative.Grade}");
                sb.AppendLine();
                bool hasRenderableContext = HasRenderableNarrativeContext(narrative);
                if (narrative.HasObservedTimeline || hasRenderableContext)
                {
                    string signatureSummary = AttackNarrator.ResolveSignatureSummary(narrative);
                    sb.AppendLine($"**Signature:** {signatureSummary}  ");
                    if (narrative.FirstSeen != DateTime.MinValue)
                        sb.AppendLine($"**Started:** {narrative.FirstSeen:yyyy-MM-dd HH:mm:ss}  ");
                    if (narrative.HasObservedTimeline)
                        sb.AppendLine($"**Duration:** {narrative.TotalSeconds:F1}s  ");
                    sb.AppendLine();

                    if (!narrative.HasObservedTimeline)
                    {
                        sb.AppendLine("> Direct ETW activity was not captured before this process exited, but launch or artifact context was preserved.");
                        sb.AppendLine();
                    }
                }
                else
                {
                    sb.AppendLine("> This process was launched during monitoring but exited before any activity could be captured.");
                    sb.AppendLine();
                }

                AppendBulletSection(sb, "### Launch Context", narrative.LaunchContext);

                if (narrative.SpawnedCommands.Count > 0)
                {
                    AppendBulletSection(sb, "### Processes Launched",
                        narrative.SpawnedCommands
                            .Select(spawn => AttackNarrator.DescribeSpawnedCommand(spawn.Name, spawn.CommandLine))
                            .Distinct(StringComparer.OrdinalIgnoreCase));
                }

                var registrySteps = narrative.Timeline
                    .Where(s => s.Category == "Registry").ToList();
                AppendBulletSection(sb, "### Registry Keys Accessed",
                    GetUniqueStepsByHeadline(registrySteps).Select(step => step.Headline));

                var networkSteps = narrative.Timeline
                    .Where(s => s.Category == "Network").ToList();
                AppendBulletSection(sb, "### Network Connections",
                    GetUniqueNetworkDestinations(networkSteps));

                AppendPathSection(sb, "### Runtime Artifacts Observed", narrative.RuntimeArtifactFiles);
                AppendPathSection(sb, "### Files Dropped", narrative.DroppedFiles);
                AppendLimitedPathSection(sb, "Files Deleted", narrative.DeletedFiles);
                AppendLimitedPathSection(sb, "Runtime Artifacts Deleted", narrative.DeletedRuntimeArtifactFiles);

                if (narrative.Grade == "SAFE")
                {
                    if (!narrative.IsSpawnedProcess)
                    {
                        AppendBulletSection(sb, "### Why considered safe", narrative.SafeReasons);
                        sb.AppendLine("> Note: This assessment is limited to what was observed during the monitoring window.");
                        sb.AppendLine();
                    }
                    continue;
                }
                AppendBulletSection(sb, "### Detection Signals", narrative.DecisionReasons);
            }

            return sb.ToString();
        }

        private static string GetReportVerdictText(string grade) => grade switch
        {
            "MALICIOUS" => "Malicious behaviour confirmed.",
            "SUSPICIOUS" => "Suspicious behaviour detected.",
            "INCONCLUSIVE" => "Suspicious behaviour was observed, but the evidence was limited.",
            _ => "No malicious behaviour was confirmed."
        };

        private static bool HasRenderableNarrativeContext(AttackNarrative narrative)
        {
            if (narrative.LaunchContext.Count > 0 ||
                narrative.SpawnedCommands.Count > 0 ||
                narrative.RuntimeArtifactFiles.Count > 0 ||
                narrative.DroppedFiles.Count > 0 ||
                narrative.DeletedFiles.Any(path => !IsNoisyDeletedFile(path)) ||
                narrative.DeletedRuntimeArtifactFiles.Any(path => !IsNoisyDeletedFile(path)))
            {
                return true;
            }

            return narrative.Timeline.Any(step => step.Category is "Registry" or "Network");
        }

        private static void AppendBulletSection(StringBuilder builder, string heading, IEnumerable<string> items)
        {
            var lines = items.Where(line => !string.IsNullOrWhiteSpace(line)).ToList();
            if (lines.Count == 0)
                return;

            builder.AppendLine(heading);
            builder.AppendLine();
            foreach (var line in lines)
                builder.AppendLine($"- {line}");
            builder.AppendLine();
        }

        private static void AppendPathSection(StringBuilder builder, string heading, IEnumerable<string> paths)
        {
            var uniquePaths = paths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (uniquePaths.Count == 0)
                return;

            builder.AppendLine(heading);
            builder.AppendLine();
            foreach (var path in uniquePaths)
                builder.AppendLine(FormatObservedPath(path));
            builder.AppendLine();
        }

        private static void AppendLimitedPathSection(StringBuilder builder, string heading, IEnumerable<string> paths)
        {
            var uniquePaths = paths
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Where(path => !IsNoisyDeletedFile(path))
                .ToList();
            if (uniquePaths.Count == 0)
                return;

            builder.AppendLine($"### {heading} ({uniquePaths.Count} total)");
            builder.AppendLine();
            foreach (var path in uniquePaths.Take(ReportFilePreviewCount))
                builder.AppendLine(FormatObservedPath(path));
            if (uniquePaths.Count > ReportFilePreviewCount)
                builder.AppendLine($"- *...and {uniquePaths.Count - ReportFilePreviewCount} more*");
            builder.AppendLine();
        }

        private static IEnumerable<string> GetUniqueNetworkDestinations(IEnumerable<NarrativeStep> steps)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var step in steps)
            {
                string destination = step.Detail ?? step.Headline;
                if (seen.Add(destination))
                    yield return destination;
            }
        }

        private static string FormatObservedPath(string path)
            => $"- `{Path.GetFileName(path)}`  —  {path}";

        private static bool IsNoisyDeletedFile(string path)
        {
            string lower = path.ToLowerInvariant();
            if (lower.Contains("\\customdestinations\\") || lower.Contains("\\recent\\"))
                return true;
            if (lower.EndsWith(".tmp") && (lower.Contains("\\appdata\\") || lower.Contains("\\temp\\")))
                return true;
            return false;
        }

        private static List<NarrativeStep> GetUniqueStepsByHeadline(IEnumerable<NarrativeStep> steps)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var result = new List<NarrativeStep>();
            foreach (var step in steps)
            {
                if (seen.Add(step.Headline))
                    result.Add(step);
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
