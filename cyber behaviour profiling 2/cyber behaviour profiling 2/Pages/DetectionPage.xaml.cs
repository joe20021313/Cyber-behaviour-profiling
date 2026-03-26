using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace cyber_behaviour_profiling_2.Pages
{

    public class EventTileViewModel
    {
        public string EventType { get; set; } = "";
        public string Category { get; set; } = "";
        public string ShortCategory { get; set; } = "";
        public int Count { get; set; } = 0;
        public string CountLabel => $"×{Count}";
        public SolidColorBrush CategoryBrush { get; set; } = new(Colors.Gray);
        public List<TimelineItemViewModel> Events { get; set; } = new();
    }

    public class TimelineItemViewModel
    {
        public string Time { get; set; } = "";
        public string Raw { get; set; } = "";
    }

    public partial class DetectionPage : Page
    {
        private const int MaxDisplayScore = 300;

        private bool _isMonitoring = false;
        private int _currentScore = 0;

        private readonly Dictionary<string, EventTileViewModel> _tileMap = new();
        private readonly List<EventTileViewModel> _tileList = new();

        public DetectionPage()
        {
            InitializeComponent();

            UpdateScoreDisplay(150);
            AddEvent("FileWrite",      "credential_file_access",  @"C:\Users\User\AppData\Local\Google\Chrome\User Data\Default\Login Data", DateTime.Now.AddSeconds(-30));
            AddEvent("FileWrite",      "credential_file_access",  @"C:\Users\User\AppData\Local\Google\Chrome\User Data\Default\Cookies",    DateTime.Now.AddSeconds(-28));
            AddEvent("Registry",       "registry_persistence",    @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\updater",             DateTime.Now.AddSeconds(-25));
            AddEvent("NetworkConnect", "network_c2",               "api.telegram.org (149.154.167.220)",                                      DateTime.Now.AddSeconds(-20));
            AddEvent("DNS_Query",      "dns_c2",                   "pastebin.com",                                                            DateTime.Now.AddSeconds(-18));
            AddEvent("ProcessSpawn",   "process_lolbin",           "powershell.exe",                                                          DateTime.Now.AddSeconds(-15));
            AddEvent("FileWrite",      "credential_file_access",  @"C:\Users\User\AppData\Roaming\Mozilla\Firefox\Profiles\key4.db",          DateTime.Now.AddSeconds(-10));
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

        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            _isMonitoring = !_isMonitoring;
            StartButton.Content = _isMonitoring ? "Stop" : "Start";

            if (_isMonitoring)
            {
                ClearAll();
            }
            else
            {
            }
        }

        public void UpdateScoreDisplay(int score, string grade = null)
        {
            _currentScore = score;
            ScoreLabel.Text = score.ToString();

            string severity;
            Color badgeColor;

            if (grade != null)
            {
                severity = grade;
                badgeColor = grade switch
                {
                    "MALICIOUS"    => Color.FromRgb(0xC0, 0x39, 0x2B),
                    "SUSPICIOUS"   => Color.FromRgb(0xF3, 0x9C, 0x12),
                    "INCONCLUSIVE" => Color.FromRgb(0x29, 0x80, 0xB9),
                    _              => Color.FromRgb(0x27, 0xAE, 0x60)
                };
            }
            else
            {
                if (score >= 200) { severity = "CRITICAL"; badgeColor = Color.FromRgb(0xC0, 0x39, 0x2B); }
                else if (score >= 120) { severity = "HIGH"; badgeColor = Color.FromRgb(0xE7, 0x4C, 0x3C); }
                else if (score >= 60) { severity = "MEDIUM"; badgeColor = Color.FromRgb(0xF3, 0x9C, 0x12); }
                else if (score >= 20) { severity = "LOW"; badgeColor = Color.FromRgb(0xF1, 0xC4, 0x0F); }
                else { severity = "BENIGN"; badgeColor = Color.FromRgb(0x27, 0xAE, 0x60); }
            }

            SeverityLabel.Text = severity;
            SeverityBadge.Background = new SolidColorBrush(Color.FromArgb(0x40,
                badgeColor.R, badgeColor.G, badgeColor.B));

            RefreshScoreBar();
        }

        private void ScoreBarContainer_SizeChanged(object sender, SizeChangedEventArgs e)
            => RefreshScoreBar();

        private void RefreshScoreBar()
        {
            double pct = Math.Clamp(_currentScore / (double)MaxDisplayScore, 0, 1);
            double width = ScoreBarContainer.ActualWidth * pct;
            ScoreClip.Rect = new Rect(0, 0, width, 14);
        }

        public void AddEvent(string eventType, string category, string rawData, DateTime timestamp)
        {
            Dispatcher.Invoke(() =>
            {
                EmptyEventsText.Visibility = Visibility.Collapsed;

                string key = $"{eventType}|{category}";
                if (!_tileMap.TryGetValue(key, out var tile))
                {
                    tile = new EventTileViewModel
                    {
                        EventType = eventType,
                        Category = category,
                        ShortCategory = ToShortLabel(category),
                        CategoryBrush = ToCategoryBrush(category),
                        Count = 0
                    };
                    _tileMap[key] = tile;
                    _tileList.Add(tile);
                }

                tile.Count++;
                tile.Events.Add(new TimelineItemViewModel
                {
                    Time = timestamp.ToString("HH:mm:ss"),
                    Raw = rawData
                });

                EventTiles.ItemsSource = null;
                EventTiles.ItemsSource = _tileList
                    .OrderByDescending(t => t.Count)
                    .ToList();
            });
        }

        private void EventTile_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is EventTileViewModel tile)
            {
                DetailTitle.Text = $"TIMELINE — {tile.EventType}";
                TimelineList.ItemsSource = tile.Events
                    .OrderBy(ev => ev.Time)
                    .ToList();
                DetailRowDef.Height = new GridLength(220);
            }
        }

        private void CloseDetail_Click(object sender, RoutedEventArgs e)
        {
            DetailRowDef.Height = new GridLength(0);
        }

        private bool _reportOpen = false;

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
            ReportList.ItemsSource = _tileList.OrderByDescending(t => t.Count).ToList();
            GreyOverlay.Visibility = Visibility.Visible;
            ReportChevron.Text = "▲";
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
            ReportChevron.Text = "▼";
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
            EventTiles.ItemsSource = null;
            TimelineList.ItemsSource = null;
            EmptyEventsText.Visibility = Visibility.Visible;
            DetailRowDef.Height = new GridLength(0);
            UpdateScoreDisplay(0);
        }

        private static string ToShortLabel(string category) => category switch
        {
            "registry_persistence"
                or "file_persistence" => "PERSIST",
            "registry_defense_evasion"
                or "file_defense_evasion"
                or "process_defense_evasion" => "DEF·EVA",
            "registry_privilege_escalation" => "PRIV·ESC",
            "registry_credential_access"
                or "credential_file_access"
                or "dpapi_decrypt" => "CRED",
            "collection" => "COLLECT",
            "context_signal" => "SIGNAL",
            "network_c2" => "C2",
            "dns_c2" => "DNS·C2",
            "process_lolbin" => "LOLBIN",
            "process_accessibility" => "ACCESS",
            "process_discovery" => "DISCOV",
            "process_blacklisted" => "MALWARE",
            _ => category.Length > 8
                     ? category[..8].ToUpperInvariant()
                     : category.ToUpperInvariant()
        };

        private static SolidColorBrush ToCategoryBrush(string category) => category switch
        {
            "registry_persistence"
                or "file_persistence" => new(Color.FromRgb(0x34, 0x98, 0xDB)),
            "registry_defense_evasion"
                or "file_defense_evasion"
                or "process_defense_evasion" => new(Color.FromRgb(0x16, 0xA0, 0x85)),
            "registry_privilege_escalation" => new(Color.FromRgb(0x8E, 0x44, 0xAD)),
            "registry_credential_access"
                or "credential_file_access"
                or "dpapi_decrypt" => new(Color.FromRgb(0x9B, 0x59, 0xB6)),
            "collection" => new(Color.FromRgb(0xF3, 0x9C, 0x12)),
            "context_signal" => new(Color.FromRgb(0x7F, 0x8C, 0x8D)),
            "network_c2" => new(Color.FromRgb(0xE6, 0x7E, 0x22)),
            "dns_c2" => new(Color.FromRgb(0xD3, 0x54, 0x00)),
            "process_lolbin" => new(Color.FromRgb(0xE7, 0x4C, 0x3C)),
            "process_accessibility"
                or "process_blacklisted" => new(Color.FromRgb(0xC0, 0x39, 0x2B)),
            "process_discovery" => new(Color.FromRgb(0x27, 0xAE, 0x60)),
            _ => new(Colors.Gray)
        };
    }
}