using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace cyber_behaviour_profiling_2.Pages
{
    public class ReportItemVM
    {
        public string FileName { get; set; } = "";
        public string FilePath { get; set; } = "";
        public string DateDisplay { get; set; } = "";
        public string Target { get; set; } = "";
        public string Grade { get; set; } = "";
        public SolidColorBrush GradeBrush { get; set; } = new(Colors.Gray);
    }

    public partial class ReportsPage : Page
    {
        private static readonly string ReportsDir =
            Path.Combine(AppContext.BaseDirectory, "reports");

        public ReportsPage()
        {
            InitializeComponent();
            LoadReports();
        }

        private void LoadReports()
        {
            if (!Directory.Exists(ReportsDir))
            {
                SetEmptyState();
                return;
            }

            var files = Directory.GetFiles(ReportsDir, "*.txt")
                .OrderByDescending(f => File.GetCreationTime(f))
                .ToList();

            if (files.Count == 0)
            {
                SetEmptyState();
                return;
            }

            EmptyText.Visibility = Visibility.Collapsed;

            ReportsList.ItemsSource = files.Select(CreateReportItem).ToList();
        }

        private void SetEmptyState()
        {
            ReportsList.ItemsSource = null;
            EmptyText.Visibility = Visibility.Visible;
        }

        private static ReportItemVM CreateReportItem(string path)
        {
            var info = new FileInfo(path);
            var summary = TryReadReportSummary(path);

            return new ReportItemVM
            {
                FileName = info.Name,
                FilePath = path,
                DateDisplay = info.CreationTime.ToString("yyyy-MM-dd HH:mm"),
                Target = summary.Target,
                Grade = summary.Grade,
                GradeBrush = GradeToBrush(summary.Grade)
            };
        }

        private static (string Target, string Grade) TryReadReportSummary(string path)
        {
            string target = "";
            string grade = "";

            try
            {
                using var reader = new StreamReader(path);
                for (int i = 0; i < 10; i++)
                {
                    string? line = reader.ReadLine();
                    if (line == null)
                        break;

                    string trimmed = line.TrimStart();
                    if (trimmed.StartsWith("Target:"))
                        target = trimmed.Split(':', 2)[1].Trim();
                    else if (trimmed.StartsWith("Grade:"))
                        grade = trimmed.Split(':', 2)[1].Trim();
                }
            }
            catch
            {
            }

            return (target, grade);
        }

        private void ReportItem_Click(object sender, MouseButtonEventArgs e)
        {
            if (sender is FrameworkElement el && el.Tag is string path && File.Exists(path))
                Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }

        private void DeleteReport_Click(object sender, RoutedEventArgs e)
        {
            if (sender is FrameworkElement el && el.Tag is string path)
            {
                var answer = MessageBox.Show(
                    $"Delete report?\n{Path.GetFileName(path)}",
                    "Confirm Delete",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (answer == MessageBoxResult.Yes)
                {
                    TryDeleteReport(path);
                    LoadReports();
                }
            }
        }

        private static void TryDeleteReport(string path)
        {
            try
            {
                File.Delete(path);
            }
            catch
            {
            }
        }

        private void Refresh_Click(object sender, RoutedEventArgs e)
        {
            LoadReports();
        }

        private void OpenFolder_Click(object sender, RoutedEventArgs e)
        {
            Directory.CreateDirectory(ReportsDir);
            Process.Start(new ProcessStartInfo(ReportsDir) { UseShellExecute = true });
        }

        private static SolidColorBrush GradeToBrush(string grade) => grade switch
        {
            "MALICIOUS"    => new(Color.FromRgb(0xC0, 0x39, 0x2B)),
            "SUSPICIOUS"   => new(Color.FromRgb(0xF3, 0x9C, 0x12)),
            "INCONCLUSIVE" => new(Color.FromRgb(0x29, 0x80, 0xB9)),
            _              => new(Color.FromRgb(0x27, 0xAE, 0x60))
        };
    }
}
