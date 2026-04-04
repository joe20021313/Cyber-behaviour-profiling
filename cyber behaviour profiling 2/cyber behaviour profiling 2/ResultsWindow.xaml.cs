using System;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using Wpf.Ui.Controls;

namespace cyber_behaviour_profiling_2
{
    public partial class ResultsWindow : FluentWindow
    {
        private readonly string? _reportPath;
        private readonly string? _metadataPath;

        public ResultsWindow(string markdownText, string? reportPath, string? metadataPath)
        {
            InitializeComponent();
            _reportPath = reportPath;
            _metadataPath = metadataPath;

            ReportViewer.Document = ParseMarkdown(markdownText);

            DownloadReportButton.IsEnabled = !string.IsNullOrEmpty(reportPath) && File.Exists(reportPath);
            DownloadMetadataButton.IsEnabled = !string.IsNullOrEmpty(metadataPath) && File.Exists(metadataPath);
        }

        private static FlowDocument ParseMarkdown(string text)
        {
            var doc = new FlowDocument
            {
                FontFamily = new FontFamily("Segoe UI"),
                FontSize = 13,
                LineHeight = 1,
                PagePadding = new Thickness(0)
            };

            bool inCodeBlock = false;
            var codeLines = new System.Collections.Generic.List<string>();

            foreach (var rawLine in text.Split('\n'))
            {
                string line = rawLine.TrimEnd('\r');

                // Fenced code block
                if (line.TrimStart().StartsWith("```"))
                {
                    if (inCodeBlock)
                    {
                        // Emit code block
                        var codePara = new Paragraph
                        {
                            Background = new SolidColorBrush(Color.FromArgb(0x18, 0x88, 0x88, 0x88)),
                            Padding = new Thickness(10, 6, 10, 6),
                            Margin = new Thickness(0, 4, 0, 4),
                            FontFamily = new FontFamily("Consolas"),
                            FontSize = 12
                        };
                        codePara.Inlines.Add(new Run(string.Join("\n", codeLines)));
                        doc.Blocks.Add(codePara);
                        codeLines.Clear();
                        inCodeBlock = false;
                    }
                    else
                    {
                        inCodeBlock = true;
                    }
                    continue;
                }

                if (inCodeBlock)
                {
                    codeLines.Add(line);
                    continue;
                }

                // H1
                if (line.StartsWith("# "))
                {
                    var p = new Paragraph
                    {
                        FontSize = 22,
                        FontWeight = FontWeights.Bold,
                        Margin = new Thickness(0, 16, 0, 4)
                    };
                    AddInlines(p, line[2..]);
                    doc.Blocks.Add(p);
                    continue;
                }

                // H2
                if (line.StartsWith("## "))
                {
                    var p = new Paragraph
                    {
                        FontSize = 16,
                        FontWeight = FontWeights.SemiBold,
                        Margin = new Thickness(0, 14, 0, 3)
                    };
                    AddInlines(p, line[3..]);
                    doc.Blocks.Add(p);
                    // Thin rule under H2
                    doc.Blocks.Add(new BlockUIContainer(new System.Windows.Controls.Separator
                    {
                        Margin = new Thickness(0, 1, 0, 6),
                        Opacity = 0.3
                    }));
                    continue;
                }

                // H3
                if (line.StartsWith("### "))
                {
                    var p = new Paragraph
                    {
                        FontSize = 13,
                        FontWeight = FontWeights.SemiBold,
                        Foreground = new SolidColorBrush(Color.FromRgb(0x29, 0x80, 0xB9)),
                        Margin = new Thickness(0, 10, 0, 2)
                    };
                    AddInlines(p, line[4..]);
                    doc.Blocks.Add(p);
                    continue;
                }

                // Horizontal rule
                if (line.TrimStart().StartsWith("---"))
                {
                    doc.Blocks.Add(new BlockUIContainer(new System.Windows.Controls.Separator
                    {
                        Margin = new Thickness(0, 8, 0, 8)
                    }));
                    continue;
                }

                // Blockquote
                if (line.StartsWith("> "))
                {
                    var p = new Paragraph
                    {
                        FontStyle = FontStyles.Italic,
                        Foreground = new SolidColorBrush(Color.FromArgb(0xAA, 0x88, 0x88, 0x88)),
                        Margin = new Thickness(16, 2, 0, 2)
                    };
                    AddInlines(p, line[2..]);
                    doc.Blocks.Add(p);
                    continue;
                }

                // Bullet
                if (line.StartsWith("- ") || line.StartsWith("* "))
                {
                    var p = new Paragraph
                    {
                        Margin = new Thickness(16, 1, 0, 1),
                        TextIndent = -12
                    };
                    p.Inlines.Add(new Run("• "));
                    AddInlines(p, line[2..]);
                    doc.Blocks.Add(p);
                    continue;
                }

                // Blank line
                if (string.IsNullOrWhiteSpace(line))
                {
                    doc.Blocks.Add(new Paragraph { Margin = new Thickness(0, 2, 0, 2) });
                    continue;
                }

                // Normal paragraph
                {
                    var p = new Paragraph { Margin = new Thickness(0, 1, 0, 1) };
                    AddInlines(p, line);
                    doc.Blocks.Add(p);
                }
            }

            return doc;
        }

        private static void AddInlines(Paragraph p, string text)
        {
            // Process **bold** and `code` spans
            var pattern = new Regex(@"\*\*(.+?)\*\*|`([^`]+)`");
            int lastIndex = 0;

            foreach (Match match in pattern.Matches(text))
            {
                if (match.Index > lastIndex)
                    p.Inlines.Add(new Run(text[lastIndex..match.Index]));

                if (match.Groups[1].Success)
                {
                    // **bold**
                    p.Inlines.Add(new Bold(new Run(match.Groups[1].Value)));
                }
                else if (match.Groups[2].Success)
                {
                    // `code`
                    p.Inlines.Add(new Run(match.Groups[2].Value)
                    {
                        FontFamily = new FontFamily("Consolas"),
                        FontSize = 12,
                        Background = new SolidColorBrush(Color.FromArgb(0x20, 0x88, 0x88, 0x88))
                    });
                }

                lastIndex = match.Index + match.Length;
            }

            if (lastIndex < text.Length)
                p.Inlines.Add(new Run(text[lastIndex..]));
        }

        private void DownloadReport_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_reportPath) || !File.Exists(_reportPath))
            {
                System.Windows.MessageBox.Show("Report file not found.", "Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
                return;
            }

            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Save Report",
                FileName = Path.GetFileName(_reportPath),
                Filter = "Text files (*.txt)|*.txt",
                DefaultExt = ".txt"
            };

            if (dlg.ShowDialog() == true)
            {
                File.Copy(_reportPath, dlg.FileName, overwrite: true);
                Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
            }
        }

        private void DownloadMetadata_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_metadataPath) || !File.Exists(_metadataPath))
            {
                System.Windows.MessageBox.Show("Metadata file not found.", "Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
                return;
            }

            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Save Lifecycle Metadata",
                FileName = Path.GetFileName(_metadataPath),
                Filter = "Text files (*.txt)|*.txt",
                DefaultExt = ".txt"
            };

            if (dlg.ShowDialog() == true)
            {
                File.Copy(_metadataPath, dlg.FileName, overwrite: true);
                Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
            }
        }
    }
}
