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
                ReportsList.ItemsSource = null;
                EmptyText.Visibility = Visibility.Visible;
                return;
            }

            var files = Directory.GetFiles(ReportsDir, "*.txt")
                .OrderByDescending(f => File.GetCreationTime(f))
                .ToList();

            if (files.Count == 0)
            {
                ReportsList.ItemsSource = null;
                EmptyText.Visibility = Visibility.Visible;
                return;
            }

            EmptyText.Visibility = Visibility.Collapsed;

            var items = new List<ReportItemVM>();
            foreach (var path in files)
            {
                var info = new FileInfo(path);
                string target = "";
                string grade = "";

                try
                {
                    using var reader = new StreamReader(path);
                    for (int i = 0; i < 10; i++)
                    {
                        string? line = reader.ReadLine();
                        if (line == null) break;
                        if (line.TrimStart().StartsWith("Target:"))
                            target = line.Split(':', 2)[1].Trim();
                        else if (line.TrimStart().StartsWith("Grade:"))
                            grade = line.Split(':', 2)[1].Trim();
                    }
                }
                catch { }

                items.Add(new ReportItemVM
                {
                    FileName = info.Name,
                    FilePath = path,
                    DateDisplay = info.CreationTime.ToString("yyyy-MM-dd HH:mm"),
                    Target = target,
                    Grade = grade,
                    GradeBrush = GradeToBrush(grade)
                });
            }

            ReportsList.ItemsSource = items;
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
                    try { File.Delete(path); } catch { }
                    LoadReports();
                }
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
