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
        private int _recordingStartSnapshotCount;
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
            var processes = Process.GetProcesses()
                .Select(p => p.ProcessName + ".exe")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .ToList();

            ProcessDropdown.ItemsSource = processes;
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
                ProcessDropdown.Text = Path.GetFileName(dlg.FileName);
                DropdownHint.Visibility = Visibility.Collapsed;
            }
        }

        private void StartStop_Click(object sender, RoutedEventArgs e)
        {
            if (_state == RecordState.Idle || _state == RecordState.Error)
            {
                _targetProcess = ProcessDropdown.Text?.Trim().ToLower() ?? "";
                if (string.IsNullOrEmpty(_targetProcess))
                {
                    SetError("Please select a process to monitor.");
                    return;
                }
                if (!_targetProcess.EndsWith(".exe")) _targetProcess += ".exe";

                DropdownHint.Visibility = Visibility.Collapsed;
                _capturedBaseline = null;
                _recordingStartSnapshotCount = 0;
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

                ProcessProfile? currentProfile = FindLatestProfile(nameNoExt);
                _recordingStartSnapshotCount = GetSnapshotCount(currentProfile);

                bool alreadyMonitored = LiveMonitoringSession.ActiveInstance != null &&
                    currentProfile != null;

                if (!alreadyMonitored)
                {
                    try
                    {
                        _tempSession = new LiveMonitoringSession();
                        _tempSession.StartForBaseline(new List<string> { _targetProcess }, DataPath);
                    }
                    catch (Exception ex)
                    {
                        SetError($"Could not start trace: {ex.Message}");
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

        private bool TryCaptureFromProfile(ProcessProfile profile, int meaningfulCount, string reason)
        {
            if (meaningfulCount < AnomalyDetector.MinVectorsRequired)
                return false;

            _capturedBaseline = AnomalyDetector.CaptureBaseline(
                profile,
                _recordingStartSnapshotCount,
                meaningfulOnly: true);

            if (_capturedBaseline == null)
                return false;

            string metricSummary = BuildBaselineMetricSummary(_capturedBaseline);

            StopTempSession();
            StatusText.Text =
                $"{reason} — captured {meaningfulCount} vectors from this recording window. Enter a name and Save.\n{metricSummary}";
            SetState(RecordState.Done);
            return true;
        }

        private void StopAndCaptureIfPossible()
        {
            string key = Path.GetFileNameWithoutExtension(_targetProcess);
            var matchingProfile = FindLatestProfile(key);
            if (matchingProfile == null)
            {
                CancelRecording();
                return;
            }

            int meaningfulCount = AnomalyDetector.CountMeaningfulSnapshots(
                matchingProfile,
                _recordingStartSnapshotCount);

            if (TryCaptureFromProfile(matchingProfile, meaningfulCount, "Stopped recording"))
                return;

            StopTempSession();
            SetError(
                $"Not enough vectors to save ({meaningfulCount}/{AnomalyDetector.MinVectorsRequired}). " +
                "Run the process a bit longer or generate more activity.");
        }

        private void RecordTimer_Tick(object? sender, EventArgs e)
        {
            if (_state != RecordState.Recording) return;

            string key = Path.GetFileNameWithoutExtension(_targetProcess);
            var matchingProfile = MapToData.ActiveProfiles.Values
                .Where(p => Path.GetFileNameWithoutExtension(p.ProcessName ?? "").Equals(key, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(p => p.FirstSeen)
                .FirstOrDefault();

            if (matchingProfile == null)
            {

                StatusText.Text = $"Waiting for {_targetProcess} to start generating activity...";
                return;
            }

            int count  = matchingProfile.AnomalyHistory.Count;
            int target = AnomalyDetector.MaxSnapshots;

            int meaningfulCount = AnomalyDetector.CountMeaningfulSnapshots(
                matchingProfile,
                _recordingStartSnapshotCount);

            if (meaningfulCount > _lastMeaningfulSnapshotCount)
            {
                _lastMeaningfulSnapshotCount = meaningfulCount;
                _lastMeaningfulProgressAt = DateTime.Now;
            }

            if (meaningfulCount >= target)
            {
                if (TryCaptureFromProfile(
                    matchingProfile,
                    meaningfulCount,
                    "Target vector count reached"))
                    return;
            }

            bool processGone = Process.GetProcessesByName(key).Length == 0;
            if (processGone && meaningfulCount >= AnomalyDetector.MinVectorsRequired)
            {
                if (TryCaptureFromProfile(
                    matchingProfile,
                    meaningfulCount,
                    "Process exited"))
                    return;
            }

            bool stalled =
                meaningfulCount >= AnomalyDetector.MinVectorsRequired &&
                DateTime.Now - _lastMeaningfulProgressAt >= SnapshotStallAutoCaptureWindow;
            if (stalled)
            {
                if (TryCaptureFromProfile(
                    matchingProfile,
                    meaningfulCount,
                    $"No new snapshot vectors for {SnapshotStallAutoCaptureWindow.TotalSeconds:0}s"))
                    return;
            }

            string exitHint = processGone
                ? $" (process exited — need {Math.Max(0, AnomalyDetector.MinVectorsRequired - meaningfulCount)} more vectors)"
                : "";
            StatusText.Text =
                $"Gathering KNN snapshot vectors (this recording): {meaningfulCount}/{target} " +
                $"(total observed: {count}) — auto-save on exit or after {SnapshotStallAutoCaptureWindow.TotalSeconds:0}s with no new vectors.{exitHint}";
        }

        private static ProcessProfile? FindLatestProfile(string processNameNoExt)
        {
            return MapToData.ActiveProfiles.Values
                .Where(p => Path.GetFileNameWithoutExtension(p.ProcessName ?? "")
                    .Equals(processNameNoExt, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(p => p.FirstSeen)
                .FirstOrDefault();
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
                return "Metric ranges unavailable.";

            int dimensions = Math.Min(
                BaselineMetricNames.Length,
                snapshots.Where(s => s != null).Select(s => s.Length).DefaultIfEmpty(0).Max());
            if (dimensions == 0)
                return "Metric ranges unavailable.";

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
                return "Metric ranges unavailable.";

            string summary = $"Vectors: {snapshots.Length}. Ranges (p95): {string.Join(", ", ranges)}.";
            if (zeroOnly.Count > 0)
                summary += $"\nWarning — zero-only metrics: {string.Join(", ", zeroOnly)}.";

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
                    summary += "\nMulti-modal baseline detected (e.g. idle + active phases) — this is expected for session recordings.";
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
                    StatusText.Text = "Select a process or browse, then click Start.";
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
                    StatusText.Text = "Starting monitoring traces...";
                    SetDotColor("#F59E0B");
                    _pulseTimer.Start();
                    _recordTimer.Start();
                    CancelBtn.Visibility = Visibility.Visible;
                    break;

                case RecordState.Done:
                    StartStopBtn.Content = "Done";
                    StartStopBtn.IsEnabled = false;
                    RecordProgress.Visibility = Visibility.Collapsed;
                    StatusText.Text = $"✓ Captured {_capturedBaseline?.Snapshots.Length} reference vectors — click Save.";
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
                SetError("No baseline was captured yet.");
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
                    ? $"Saved baseline '{key}' with {vectors} vectors to {savePath}.\n{metricSummary}"
                    : $"Baseline save completed but '{key}' was not present after reload. Please retry.";
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

            foreach (var kvp in baselines.OrderBy(b => b.Key))
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
                var sourceTag = new Border
                {
                    CornerRadius = new CornerRadius(3),
                    Padding = new Thickness(6, 1, 6, 1),
                    Margin = new Thickness(0, 4, 0, 0),
                    HorizontalAlignment = HorizontalAlignment.Left,
                    Background = baseline.Source == "user"
                        ? new SolidColorBrush(Color.FromArgb(0x40, 0x6C, 0x63, 0xFF))
                        : new SolidColorBrush(Color.FromArgb(0x30, 0x88, 0x88, 0x88))
                };
                sourceTag.Child = new TextBlock
                {
                    Text = baseline.Source == "user" ? "user recorded" : "built-in",
                    FontSize = 10,
                    Foreground = baseline.Source == "user"
                        ? new SolidColorBrush(Color.FromRgb(0x6C, 0x63, 0xFF))
                        : (Brush)FindResource("TextFillColorSecondaryBrush")
                };
                nameStack.Children.Add(nameText);
                nameStack.Children.Add(sourceTag);
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
