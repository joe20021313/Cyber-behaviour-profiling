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

        private readonly ObservableCollection<string> _selectedProcesses = new(); // selected processes to update

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

            string normalized = Path.GetFileNameWithoutExtension(selected).ToLowerInvariant();
            if (!_selectedProcesses.Contains(normalized, StringComparer.OrdinalIgnoreCase))
                _selectedProcesses.Add(normalized);
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
                {
                    string name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    if (!_selectedProcesses.Contains(name, StringComparer.OrdinalIgnoreCase))
                        _selectedProcesses.Add(name);
                }
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
            while (processed < 300 && _activityQueue.TryDequeue(out var a))
            {
                processed++;
                ProcessSingleActivity(a);
            }

            if (_tilesDirty)
            {
                _tilesDirty = false;
                EmptyEventsText.Visibility = Visibility.Collapsed;
                RebuildGroupedTiles();
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

            string ownerProcess = !string.IsNullOrEmpty(a.TargetProcess) ? a.TargetProcess : a.ProcessName;
            if (isChildEvent && childName != null)
            {
               
                string childKey = $"proc:{childName}:{a.ProcessId}";
                if (!_tileMap.TryGetValue(childKey, out var childTile))
                {
                    childTile = new ActivityTileVM
                    {
                        ActivityType = childKey,
                        DisplayLabel = childName,
                        OwnerProcess = ownerProcess,
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
                string tileKey = $"{ownerProcess}:{a.ActivityType}";
                if (!_tileMap.TryGetValue(tileKey, out var tile))
                {
                    tile = new ActivityTileVM
                    {
                        ActivityType = tileKey,
                        DisplayLabel = a.ActivityType,
                        OwnerProcess = ownerProcess,
                        TileBrush = ToActivityBrush(a.ActivityType),
                        ProcessId = a.ProcessId,
                    };
                    _tileMap[tileKey] = tile;
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
            } // a

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

        private void CollapseReport() //change name
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
            while (_activityQueue.TryDequeue(out _)) { }
            TileContainer.Children.Clear();
            TimelineList.ItemsSource = null;
            ReportList.ItemsSource = null;
            EmptyEventsText.Visibility = Visibility.Visible;
            DetailRowDef.Height = new GridLength(0);
            ShowResultsButton.Visibility = Visibility.Collapsed;
        }

        private async Task StartMonitoringAsync()
        {
            if (_selectedProcesses.Count == 0)
            {
                MessageBox.Show("Select at least one process to monitor.",
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
                        "Enable it?\n\n" +
                        "This writes a policy registry key under HKLM and requires admin rights." +
                        "Process spawns will still be monitored regardless.",
                        "Enable PowerShell Detection",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Question);

                    if (answer == MessageBoxResult.Yes)
                    {
                        LiveMonitoringSession.EnableScriptBlockLogging();
                        enablePsLogging = true;
                        _weEnabledScriptBlockLogging = true;
                    }
                    else
                    {
                        psStatus = "Powershell conmmands will not be monitored";
                    }
                }
            }
            catch
            {
                psStatus = "Powershell conmmands will not be monitored";
            }

            try
            {
                ClearAll();
                _monitoringSession?.Dispose();
                _monitoringSession = new LiveMonitoringSession();
                _monitoringSession.ActivityObserved += OnActivityObserved;
                _monitoringSession.Start(_selectedProcesses.ToList(), dataPath, enablePsLogging);

                _isMonitoring = true;
                _flushTimer.Start();
                ProcessDropdown.IsEnabled = false;
                StartButton.Content = "Stop";
                string targetNames = string.Join(", ", _selectedProcesses);
                UpdateResultDisplay("MONITORING",
                    $"Watching {targetNames}");
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _flushTimer.Stop();
                _monitoringSession?.Dispose();
                _monitoringSession = null;
                UpdateResultDisplay("READY", "Select processes and start monitoring.");
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
            RebuildGroupedTiles();

            try
            {
                var session = _monitoringSession;
                var result = await Task.Run(session.Stop);
                session.ActivityObserved -= OnActivityObserved;
                session.Dispose();
                _monitoringSession = null;

                if (_weEnabledScriptBlockLogging)
                {
                    LiveMonitoringSession.DisableScriptBlockLogging();
                    _weEnabledScriptBlockLogging = false;
                }

                _isMonitoring = false;
                ProcessDropdown.IsEnabled = true;
                StartButton.Content = "Start";
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

            if (_weEnabledScriptBlockLogging)
            {
                try { LiveMonitoringSession.DisableScriptBlockLogging(); } catch { }
                _weEnabledScriptBlockLogging = false;
            }

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
        {
            try
            {
                string reportsDir = Path.Combine(AppContext.BaseDirectory, "reports");
                Directory.CreateDirectory(reportsDir);

                string timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
                string safeName = string.Join("_", result.TargetProcesses);
                string fileName = $"{safeName}_{timestamp}.md";
                string filePath = Path.Combine(reportsDir, fileName);

                string reportText = GenerateMarkdownReport(result);
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
                string safeName = string.Join("_", result.TargetProcesses);
                string fileName = $"{safeName}_{timestamp}_metadata.txt";
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

            foreach (var narrative in result.Narratives)
            {
                sb.AppendLine("---");
                sb.AppendLine();
                sb.AppendLine($"## {narrative.ProcessName} (PID {narrative.ProcessId}) — {narrative.Grade}");
                sb.AppendLine();
                sb.AppendLine($"**Signature:** {(narrative.IsSigned ? $"Verified — signed by {narrative.SignerName}" : "Not verified (no digital signature)")}  ");
                sb.AppendLine($"**Started:** {narrative.FirstSeen:yyyy-MM-dd HH:mm:ss}  ");
                sb.AppendLine($"**Duration:** {narrative.TotalSeconds:F1}s  ");
                sb.AppendLine();

                if (narrative.Grade == "SAFE")
                {
                    if (narrative.SafeReasons.Count > 0)
                    {
                        sb.AppendLine("### Why considered safe");
                        sb.AppendLine();
                        foreach (var reason in narrative.SafeReasons)
                            sb.AppendLine($"- {reason}");
                        sb.AppendLine();
                    }
                    sb.AppendLine("> Note: This assessment is limited to what was observed during the monitoring window.");
                    sb.AppendLine();
                    continue;
                }

                if (narrative.SpawnedCommands.Count > 0)
                {
                    sb.AppendLine("### Processes Launched");
                    sb.AppendLine();
                    var seen = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var spawn in narrative.SpawnedCommands)
                    {
                        string label = DescribeCommand(spawn.Name, spawn.CommandLine);
                        if (seen.Add(label))
                            sb.AppendLine($"- {label}");
                    }
                    sb.AppendLine();
                }

                var credSteps = narrative.Timeline
                    .Where(s => s.Tactic == "CredentialAccess").ToList();
                if (credSteps.Count > 0)
                {
                    sb.AppendLine("### Credential Access");
                    sb.AppendLine();
                    foreach (var s in DeduplicateSteps(credSteps))
                    {
                        string detail = !string.IsNullOrWhiteSpace(s.Detail) && s.Detail != s.Headline
                            ? $"{s.Headline} — `{s.Detail}`"
                            : s.Headline;
                        sb.AppendLine($"- {detail}");
                    }
                    sb.AppendLine();
                }

                var registrySteps = narrative.Timeline
                    .Where(s => s.Category == "Registry").ToList();
                if (registrySteps.Count > 0)
                {
                    sb.AppendLine("### Registry Keys Accessed");
                    sb.AppendLine();
                    foreach (var s in DeduplicateSteps(registrySteps))
                        sb.AppendLine($"- {s.Headline}");
                    sb.AppendLine();
                }

                var networkSteps = narrative.Timeline
                    .Where(s => s.Category == "Network").ToList();
                if (networkSteps.Count > 0)
                {
                    sb.AppendLine("### Network Connections");
                    sb.AppendLine();
                    var seenNet = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var s in networkSteps)
                    {
                        string dest = s.Detail ?? s.Headline;
                        if (seenNet.Add(dest))
                            sb.AppendLine($"- {dest}");
                    }
                    sb.AppendLine();
                }

                if (narrative.DroppedFiles.Count > 0)
                {
                    sb.AppendLine("### Files Dropped");
                    sb.AppendLine();
                    foreach (var path in narrative.DroppedFiles.Distinct(StringComparer.OrdinalIgnoreCase))
                        sb.AppendLine($"- `{Path.GetFileName(path)}`  —  {path}");
                    sb.AppendLine();
                }

                var deleted = narrative.DeletedFiles
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Where(p => !IsNoisyDeletedFile(p))
                    .ToList();
                if (deleted.Count > 0)
                {
                    sb.AppendLine($"### Files Deleted ({deleted.Count} total)");
                    sb.AppendLine();
                    foreach (var path in deleted.Take(10))
                        sb.AppendLine($"- `{Path.GetFileName(path)}`  —  {path}");
                    if (deleted.Count > 10)
                        sb.AppendLine($"- *...and {deleted.Count - 10} more*");
                    sb.AppendLine();
                }

                if (narrative.AnomalyFindings.Count > 0)
                {
                    sb.AppendLine("### Anomalies Detected");
                    sb.AppendLine();
                    foreach (var a in narrative.AnomalyFindings)
                        sb.AppendLine($"- {SimplifyAnomaly(a)}");
                    sb.AppendLine();
                }

                if (narrative.DecisionReasons.Count > 0)
                {
                    sb.AppendLine("### Detection Signals");
                    sb.AppendLine();
                    foreach (var r in narrative.DecisionReasons)
                        sb.AppendLine($"- {r}");
                    sb.AppendLine();
                }
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

        private static bool IsNoisyDeletedFile(string path)//review later
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

        private static string ShortenPath(string path) // add a button to expand full path in details view
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
