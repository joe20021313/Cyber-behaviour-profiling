using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Cyber_behaviour_profiling;

namespace cyber_behaviour_profiling_2.Pages
{
    public partial class BaselinesPage : Page
    {
        private string BaselinePath => MapToData.ResolveBaselinePath(DataPath);

        private string DataPath => Path.Combine(AppContext.BaseDirectory, "data.json");

        private DispatcherTimer _pulseTimer;
        private DispatcherTimer _recordTimer;
        private bool _dotVisible = true;

        private enum RecordState { Idle, Recording, Done, Error }
        private RecordState _state = RecordState.Idle;

        private LiveMonitoringSession? _tempSession;
        private string _targetProcess = "";
        private ProcessBaseline? _capturedBaseline;
        private List<string> _processItems = new();
        private readonly Dictionary<int, int> _recordingStartPerPid = new();
        private int _lastMeaningfulSnapshotCount;
        private DateTime _lastMeaningfulProgressAt;

        private static readonly TimeSpan SnapshotStallAutoCaptureWindow = TimeSpan.FromSeconds(5);
        private static readonly string[] BaselineMetricNames =
        {
            "Filtered Write Rate",
            "Filtered Delete Rate",
            "Payload Write Rate",
            "Sensitive Access Rate"
        };

        public BaselinesPage()
        {
            InitializeComponent();
            RefreshProcessList();
            RefreshBaselineList();
            BaselinePathLabel.Text = $"Saved to: {BaselinePath}";

            _pulseTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(600) };
            _pulseTimer.Tick += (s, e) =>
            {
                _dotVisible = !_dotVisible;
                StatusDot.Opacity = _dotVisible ? 1.0 : 0.3;
            };

            _recordTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _recordTimer.Tick += RecordTimer_Tick;
        }

        private void RefreshProcessList()
        {
            var current = ProcessDropdown.SelectedItem as string;

            var running = Process.GetProcesses()
                .Select(p => p.ProcessName)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .ToList();

            _processItems.Clear();
            foreach (var name in running)
                _processItems.Add(name);

            ProcessDropdown.ItemsSource = null;
            ProcessDropdown.ItemsSource = _processItems;

            if (current != null && _processItems.Any(n => n.Equals(current, StringComparison.OrdinalIgnoreCase)))
                ProcessDropdown.SelectedItem = _processItems.First(n => n.Equals(current, StringComparison.OrdinalIgnoreCase));

            UpdateHintVisibility();
        }

        private void UpdateHintVisibility()
        {
            DropdownHint.Visibility = ProcessDropdown.SelectedItem == null
                ? Visibility.Visible
                : Visibility.Collapsed;
        }

        private void ProcessDropdown_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateHintVisibility();
        }

        private void RefreshProcessList_Click(object sender, RoutedEventArgs e)
        {
            RefreshProcessList();
        }

        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Executables (*.exe)|*.exe",
                Title = "Select target executable"
            };
            if (dlg.ShowDialog() == true)
            {
                string name = Path.GetFileNameWithoutExtension(dlg.FileName);
                if (!_processItems.Any(n => n.Equals(name, StringComparison.OrdinalIgnoreCase)))
                {
                    _processItems.Insert(0, name);
                    ProcessDropdown.ItemsSource = null;
                    ProcessDropdown.ItemsSource = _processItems;
                }
                ProcessDropdown.SelectedItem = _processItems.First(n => n.Equals(name, StringComparison.OrdinalIgnoreCase));
                UpdateHintVisibility();
            }
        }

        private void StartStop_Click(object sender, RoutedEventArgs e)
        {
            if (_state == RecordState.Idle || _state == RecordState.Error)
            {
                _targetProcess = (ProcessDropdown.SelectedItem as string)?.Trim().ToLower() ?? "";
                if (string.IsNullOrEmpty(_targetProcess))
                {
                    SetError("Please select a process from the list.");
                    return;
                }
                if (!_targetProcess.EndsWith(".exe")) _targetProcess += ".exe";
                _capturedBaseline = null;
                _recordingStartPerPid.Clear();
                _lastMeaningfulSnapshotCount = 0;
                _lastMeaningfulProgressAt = DateTime.Now;

                string nameNoExt = Path.GetFileNameWithoutExtension(_targetProcess);

                if (LiveMonitoringSession.ActiveInstance == null)
                {
                    foreach (int pid in MapToData.ActiveProfiles.Keys.ToList())
                    {
                        if (MapToData.ActiveProfiles.TryGetValue(pid, out var p) &&
                            Path.GetFileNameWithoutExtension(p.ProcessName ?? "")
                                .Equals(nameNoExt, StringComparison.OrdinalIgnoreCase))
                            MapToData.ActiveProfiles.TryRemove(pid, out _);
                    }
                }

                var matchingProfiles = FindAllMatchingProfiles(nameNoExt);
                foreach (var p in matchingProfiles)
                    _recordingStartPerPid[p.ProcessId] = GetSnapshotCount(p);

                bool alreadyMonitored = LiveMonitoringSession.ActiveInstance != null &&
                    matchingProfiles.Count > 0;

                if (!alreadyMonitored)
                {
                    try
                    {
                        _tempSession = new LiveMonitoringSession();
                        _tempSession.StartForBaseline(new List<string> { _targetProcess }, DataPath);
                    }
                    catch (Exception ex)
                    {
                        SetError($"Failed to monitor process: {ex.Message}");
                        return;
                    }
                }

                SetState(RecordState.Recording);
            }
            else if (_state == RecordState.Recording)
            {
                StopAndCaptureIfPossible();
            }
        }

        private void CancelBaseline_Click(object sender, RoutedEventArgs e)
        {
            CancelRecording();
        }

        private void CancelRecording()
        {
            StopTempSession();
            SetState(RecordState.Idle);
        }

        private void StopTempSession()
        {
            if (_tempSession != null)
            {
                try { _tempSession.StopBaseline(); } catch { }
                _tempSession = null;
            }
        }

        private const int ThinBaselineThreshold = 20;

        private bool TryCaptureFromProfiles(List<ProcessProfile> profiles, int snapshotCount, string reason)
        {
            if (snapshotCount < AnomalyDetector.MinVectorsRequired)
                return false;

            _capturedBaseline = AnomalyDetector.CaptureBaseline(profiles, _recordingStartPerPid);

            if (_capturedBaseline == null)
                return false;

            string metricSummary = BuildBaselineMetricSummary(_capturedBaseline);

            StopTempSession();
            SetState(RecordState.Done);

            StatusText.Text = _capturedBaseline.Snapshots.Length < ThinBaselineThreshold
                ? $"Heads up — only {_capturedBaseline.Snapshots.Length} data points captured. A longer recording gives better accuracy.\n{reason}. Click Save to keep it.\n\n{metricSummary}"
                : $"{reason}. {_capturedBaseline.Snapshots.Length} data points captured. Click Save to keep it.\n\n{metricSummary}";

            return true;
        }

        private void StopAndCaptureIfPossible()
        {
            string key = Path.GetFileNameWithoutExtension(_targetProcess);
            var matchingProfiles = FindAllMatchingProfiles(key);
            if (matchingProfiles.Count == 0)
            {
                CancelRecording();
                return;
            }

            int snapshotCount = GetAggregateDeltaSnapshotCount(matchingProfiles);

            if (TryCaptureFromProfiles(matchingProfiles, snapshotCount, "Stopped recording"))
                return;

            StopTempSession();
            SetError($"Not enough data yet — got {snapshotCount} of {AnomalyDetector.MinVectorsRequired} required data points. Try letting the process run a bit longer.");
        }

        private void RecordTimer_Tick(object? sender, EventArgs e)
        {
            if (_state != RecordState.Recording) return;

            string key = Path.GetFileNameWithoutExtension(_targetProcess);
            var matchingProfiles = FindAllMatchingProfiles(key);

            if (matchingProfiles.Count == 0)
            {
                StatusText.Text = $"Waiting for {_targetProcess} to do something...";
                return;
            }

            foreach (var p in matchingProfiles)
                _recordingStartPerPid.TryAdd(p.ProcessId, 0);

            int snapshotCount = GetAggregateDeltaSnapshotCount(matchingProfiles);
            int target = AnomalyDetector.MaxSnapshots;

            if (snapshotCount > _lastMeaningfulSnapshotCount)
            {
                _lastMeaningfulSnapshotCount = snapshotCount;
                _lastMeaningfulProgressAt = DateTime.Now;
            }

            if (snapshotCount >= target)
            {
                if (TryCaptureFromProfiles(
                    matchingProfiles,
                    snapshotCount,
                    "Target vector count reached"))
                    return;
            }

            bool processGone = Process.GetProcessesByName(key).Length == 0;
            if (processGone && snapshotCount >= AnomalyDetector.MinVectorsRequired)
            {
                if (TryCaptureFromProfiles(
                    matchingProfiles,
                    snapshotCount,
                    "Process exited"))
                    return;
            }

            bool stalled =
                snapshotCount >= AnomalyDetector.MinVectorsRequired &&
                DateTime.Now - _lastMeaningfulProgressAt >= SnapshotStallAutoCaptureWindow;
            if (stalled)
            {
                if (TryCaptureFromProfiles(
                    matchingProfiles,
                    snapshotCount,
                    $"No new snapshot vectors for {SnapshotStallAutoCaptureWindow.TotalSeconds:0}s"))
                    return;
            }

            string exitHint = processGone
                ? $" Process has exited — need {Math.Max(0, AnomalyDetector.MinVectorsRequired - snapshotCount)} more data points to finish."
                : $" Stops automatically when the process exits or goes idle for {SnapshotStallAutoCaptureWindow.TotalSeconds:0}s.";
            StatusText.Text = $"Watching {_targetProcess}... {snapshotCount} of {target} data points collected.{exitHint}";
        }

        private static List<ProcessProfile> FindAllMatchingProfiles(string processNameNoExt)
        {
            return MapToData.ActiveProfiles.Values
                .Where(p => Path.GetFileNameWithoutExtension(p.ProcessName ?? "")
                    .Equals(processNameNoExt, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        private int GetAggregateDeltaSnapshotCount(IEnumerable<ProcessProfile> profiles)
        {
            int total = 0;
            foreach (var p in profiles)
            {
                int current = GetSnapshotCount(p);
                int start = _recordingStartPerPid.TryGetValue(p.ProcessId, out var s) ? s : 0;
                total += Math.Max(0, current - start);
            }
            return total;
        }

        private static int GetSnapshotCount(ProcessProfile? profile)
        {
            if (profile == null)
                return 0;

            lock (profile.KnnStateLock)
                return profile.AnomalyHistory.Count;
        }

        private static string BuildBaselineMetricSummary(ProcessBaseline baseline)
        {
            var snapshots = baseline.Snapshots ?? Array.Empty<double[]>();
            if (snapshots.Length == 0)
                return "No metric data available.";

            int dimensions = Math.Min(
                BaselineMetricNames.Length,
                snapshots.Where(s => s != null).Select(s => s.Length).DefaultIfEmpty(0).Max());
            if (dimensions == 0)
                return "No metric data available.";

            var ranges = new List<string>();
            var zeroOnly = new List<string>();

            for (int i = 0; i < dimensions; i++)
            {
                var values = snapshots
                    .Where(s => s != null && s.Length > i)
                    .Select(s => s[i])
                    .OrderBy(v => v)
                    .ToList();
                if (values.Count == 0)
                    continue;

                double min = values[0];
                double max = values[^1];
                double p95 = values[(int)Math.Floor(values.Count * 0.95)];
                ranges.Add($"{BaselineMetricNames[i]} {min:F1}–{p95:F1}/s (max {max:F1})");

                if (max <= 0.0)
                    zeroOnly.Add(BaselineMetricNames[i]);
            }

            if (ranges.Count == 0)
                return "No metric data available.";

            string summary = $"{snapshots.Length} data points. Activity ranges (p95): {string.Join(", ", ranges)}.";
            if (zeroOnly.Count > 0)
                summary += $"\nNo activity was seen for: {string.Join(", ", zeroOnly)}. Consider recording while the app is actually doing something.";

            var writeValues = snapshots
                .Where(s => s != null && s.Length > 0)
                .Select(s => s[0])
                .OrderBy(v => v)
                .ToList();
            if (writeValues.Count >= 4)
            {
                var gaps = Enumerable.Range(0, writeValues.Count - 1)
                    .Select(j => writeValues[j + 1] - writeValues[j])
                    .ToList();
                double maxGap    = gaps.Max();
                double medianGap = gaps.OrderBy(g => g).ElementAt(gaps.Count / 2);
                if (maxGap > 2.0 * medianGap + 0.5)
                    summary += "\nActivity varied quite a bit during recording — that's fine, but worth knowing.";
            }

            return summary;
        }

        private void SetState(RecordState state)
        {
            _state = state;
            switch (_state)
            {
                case RecordState.Idle:
                    ProcessDropdown.IsEnabled = true;
                    BrowseBtn.IsEnabled = true;
                    RefreshBtn.IsEnabled = true;
                    StartStopBtn.IsEnabled = true;
                    StartStopBtn.Content = "Start Recording";
                    RecordProgress.Visibility = Visibility.Collapsed;
                    StatusText.Text = "Pick a process from the list and hit Start Recording.";
                    SetDotColor("#EF4444");
                    _pulseTimer.Stop();
                    _recordTimer.Stop();
                    SaveBaselineBtn.IsEnabled = false;
                    CancelBtn.Visibility = Visibility.Collapsed;
                    break;

                case RecordState.Recording:
                    ProcessDropdown.IsEnabled = false;
                    BrowseBtn.IsEnabled = false;
                    RefreshBtn.IsEnabled = false;
                    StartStopBtn.Content = "Stop";
                    RecordProgress.Visibility = Visibility.Visible;
                    StatusText.Text = "Getting ready...";
                    SetDotColor("#F59E0B");
                    _pulseTimer.Start();
                    _recordTimer.Start();
                    CancelBtn.Visibility = Visibility.Visible;
                    break;

                case RecordState.Done:
                    StartStopBtn.Content = "Done";
                    StartStopBtn.IsEnabled = false;
                    RecordProgress.Visibility = Visibility.Collapsed;
                    StatusText.Text = $"✓ {_capturedBaseline?.Snapshots.Length} data points captured. Click Save to store the baseline.";
                    SetDotColor("#10B981");
                    _pulseTimer.Stop();
                    _recordTimer.Stop();
                    StatusDot.Opacity = 1.0;
                    SaveBaselineBtn.IsEnabled = true;
                    CancelBtn.Visibility = Visibility.Visible;
                    break;

                case RecordState.Error:
                    StartStopBtn.Content = "Start Recording";
                    ProcessDropdown.IsEnabled = true;
                    BrowseBtn.IsEnabled = true;
                    RefreshBtn.IsEnabled = true;
                    RecordProgress.Visibility = Visibility.Collapsed;
                    SetDotColor("#EF4444");
                    _pulseTimer.Stop();
                    _recordTimer.Stop();
                    CancelBtn.Visibility = Visibility.Collapsed;
                    break;
            }
        }

        private void SetError(string error)
        {
            SetState(RecordState.Error);
            StatusText.Text = error;
        }

        private void SetDotColor(string hex)
        {
            StatusDot.Fill = (Brush)new BrushConverter().ConvertFromString(hex)!;
        }

        private void SaveBaseline_Click(object sender, RoutedEventArgs e)
        {
            if (_capturedBaseline == null)
            {
                SetError("Please record a baseline before saving.");
                return;
            }

            try
            {
                string key = Path.GetFileNameWithoutExtension(_targetProcess);
                _capturedBaseline.Source = "user";
                string savePath = BaselinePath;

                MapToData.SaveBaseline(key, _capturedBaseline, savePath);
                BaselinePathLabel.Text = $"Saved to: {savePath}";

                bool found = AnomalyDetector.AllBaselines.TryGetValue(key, out var saved);
                int vectors = found ? saved!.Snapshots.Length : 0;
                string metricSummary = found
                    ? BuildBaselineMetricSummary(saved!)
                    : BuildBaselineMetricSummary(_capturedBaseline);

                SetState(RecordState.Idle);
                RefreshBaselineList();

                StatusText.Text = found
                    ? $"Baseline saved for '{key}' — {vectors} data points stored.\n\n{metricSummary}"
                    : $"Saved, but couldn't confirm '{key}' loaded correctly. Try restarting the app.";
            }
            catch (Exception ex)
            {
                SetError($"Failed to save baseline: {ex.Message}");
            }
        }

        private void RefreshBaselineList()
        {
            BaselineListPanel.Children.Clear();

            var baselines = AnomalyDetector.AllBaselines;
            if (baselines.Count == 0)
            {
                EmptyStatePanel.Visibility = Visibility.Visible;
                return;
            }
            EmptyStatePanel.Visibility = Visibility.Collapsed;

            foreach (var kvp in baselines.OrderBy(b => b.Key).Where(b => b.Value.Source == "user"))
            {
                string processName = kvp.Key;
                var baseline = kvp.Value;

                var card = new Border
                {
                    CornerRadius = new CornerRadius(8),
                    Padding = new Thickness(14, 12, 14, 12),
                    Margin = new Thickness(0, 0, 0, 6),
                    Background = (Brush)FindResource("ControlFillColorDefaultBrush"),
                    BorderBrush = (Brush)FindResource("ControlStrokeColorDefaultBrush"),
                    BorderThickness = new Thickness(1)
                };

                var grid = new Grid();
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var nameStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
                var nameText = new TextBlock
                {
                    Text = processName,
                    FontSize = 15,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = (Brush)FindResource("TextFillColorPrimaryBrush")
                };

                nameStack.Children.Add(nameText);

                if (!string.IsNullOrWhiteSpace(baseline.RecordedAt))
                {
                    nameStack.Children.Add(new TextBlock
                    {
                        Text = $"Recorded: {baseline.RecordedAt}",
                        FontSize = 10,
                        Margin = new Thickness(0, 2, 0, 0),
                        Foreground = (Brush)FindResource("TextFillColorSecondaryBrush")
                    });
                }


                Grid.SetColumn(nameStack, 0);
                grid.Children.Add(nameStack);

                var countStack = new StackPanel
                {
                    VerticalAlignment = VerticalAlignment.Center,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    Margin = new Thickness(16, 0, 16, 0)
                };
                countStack.Children.Add(new TextBlock
                {
                    Text = baseline.Snapshots.Length.ToString(),
                    FontSize = 18,
                    FontWeight = FontWeights.Bold,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    Foreground = (Brush)FindResource("TextFillColorPrimaryBrush")
                });
                countStack.Children.Add(new TextBlock
                {
                    Text = "vectors",
                    FontSize = 10,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    Foreground = (Brush)FindResource("TextFillColorSecondaryBrush")
                });
                Grid.SetColumn(countStack, 1);
                grid.Children.Add(countStack);

                if (baseline.Source == "user")
                {
                    var deleteBtn = new Button
                    {
                        Content = "Delete",
                        Tag = processName,
                        VerticalAlignment = VerticalAlignment.Center,
                        Foreground = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)),
                        Background = Brushes.Transparent,
                        BorderThickness = new Thickness(1),
                        BorderBrush = new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C)),
                        Padding = new Thickness(10, 4, 10, 4),
                        Cursor = System.Windows.Input.Cursors.Hand
                    };
                    deleteBtn.Click += DeleteBaseline_Click;
                    Grid.SetColumn(deleteBtn, 3);
                    grid.Children.Add(deleteBtn);
                }

                card.Child = grid;
                BaselineListPanel.Children.Add(card);
            }
        }

        private void DeleteBaseline_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string processName)
            {
                try
                {
                    MapToData.DeleteBaseline(processName, BaselinePath);
                    RefreshBaselineList();
                }
                catch (Exception ex)
                {
                    SetError($"Failed to delete: {ex.Message}");
                }
            }
        }
    }
}
