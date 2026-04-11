using System;
using System.Collections.Generic;
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
        private static readonly Regex InlineMarkdownPattern = new(@"\*\*(.+?)\*\*|`([^`]+)`", RegexOptions.Compiled);

        public ResultsWindow(string markdownText, string? reportPath, string? metadataPath)
        {
            InitializeComponent();
            _reportPath = reportPath;
            _metadataPath = metadataPath;

            ReportViewer.Document = ParseMarkdown(markdownText);

            DownloadReportButton.IsEnabled = !string.IsNullOrEmpty(_reportPath) && File.Exists(_reportPath);
            DownloadMetadataButton.IsEnabled = !string.IsNullOrEmpty(_metadataPath) && File.Exists(_metadataPath);
        }

        private static FlowDocument ParseMarkdown(string text)
        {
            var document = new FlowDocument
            {
                FontFamily = new FontFamily("Segoe UI"),
                FontSize = 13,
                LineHeight = 1,
                PagePadding = new Thickness(0)
            };

            bool inCodeBlock = false;
            var codeLines = new List<string>();

            foreach (var rawLine in text.Split('\n'))
            {
                string line = rawLine.TrimEnd('\r');

                if (line.TrimStart().StartsWith("```"))
                {
                    if (inCodeBlock)
                    {
                        document.Blocks.Add(CreateCodeBlock(codeLines));
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

                if (TryAddHeading(document, line, "# ", 22, FontWeights.Bold,
                    new Thickness(0, 16, 0, 4)))
                    continue;

                if (TryAddHeading(document, line, "## ", 16, FontWeights.SemiBold,
                    new Thickness(0, 14, 0, 3), addSeparator: true))
                    continue;

                if (TryAddHeading(document, line, "### ", 13, FontWeights.SemiBold,
                    new Thickness(0, 10, 0, 2),
                    new SolidColorBrush(Color.FromRgb(0x29, 0x80, 0xB9))))
                    continue;

                if (line.TrimStart().StartsWith("---"))
                {
                    document.Blocks.Add(CreateSeparator(new Thickness(0, 8, 0, 8)));
                    continue;
                }

                if (line.StartsWith("> "))
                {
                    document.Blocks.Add(CreateParagraph(line[2..], new Thickness(16, 2, 0, 2),
                        fontStyle: FontStyles.Italic,
                        foreground: new SolidColorBrush(Color.FromArgb(0xAA, 0x88, 0x88, 0x88))));
                    continue;
                }

                if (line.StartsWith("- ") || line.StartsWith("* "))
                {
                    document.Blocks.Add(CreateBulletParagraph(line[2..]));
                    continue;
                }

                if (string.IsNullOrWhiteSpace(line))
                {
                    document.Blocks.Add(new Paragraph { Margin = new Thickness(0, 2, 0, 2) });
                    continue;
                }

                document.Blocks.Add(CreateParagraph(line, new Thickness(0, 1, 0, 1)));
            }

            return document;
        }

        private static bool TryAddHeading(FlowDocument document, string line, string prefix, double fontSize,
            FontWeight fontWeight, Thickness margin, Brush? foreground = null, bool addSeparator = false)
        {
            if (!line.StartsWith(prefix))
                return false;

            document.Blocks.Add(CreateParagraph(line[prefix.Length..], margin, fontSize, fontWeight, foreground));
            if (addSeparator)
                document.Blocks.Add(CreateSeparator(new Thickness(0, 1, 0, 6), 0.3));
            return true;
        }

        private static Paragraph CreateParagraph(string text, Thickness margin, double fontSize = 13,
            FontWeight? fontWeight = null, Brush? foreground = null, FontStyle? fontStyle = null)
        {
            var paragraph = new Paragraph
            {
                Margin = margin,
                FontSize = fontSize,
                FontWeight = fontWeight ?? FontWeights.Normal,
                FontStyle = fontStyle ?? FontStyles.Normal
            };

            if (foreground != null)
                paragraph.Foreground = foreground;

            AddInlineMarkdown(paragraph, text);
            return paragraph;
        }

        private static Paragraph CreateBulletParagraph(string text)
        {
            var paragraph = new Paragraph
            {
                Margin = new Thickness(16, 1, 0, 1),
                TextIndent = -12
            };
            paragraph.Inlines.Add(new Run("• "));
            AddInlineMarkdown(paragraph, text);
            return paragraph;
        }

        private static Paragraph CreateCodeBlock(IEnumerable<string> codeLines)
        {
            var paragraph = new Paragraph
            {
                Background = new SolidColorBrush(Color.FromArgb(0x18, 0x88, 0x88, 0x88)),
                Padding = new Thickness(10, 6, 10, 6),
                Margin = new Thickness(0, 4, 0, 4),
                FontFamily = new FontFamily("Consolas"),
                FontSize = 12
            };
            paragraph.Inlines.Add(new Run(string.Join("\n", codeLines)));
            return paragraph;
        }

        private static BlockUIContainer CreateSeparator(Thickness margin, double opacity = 1.0)
            => new(new System.Windows.Controls.Separator { Margin = margin, Opacity = opacity });

        private static void AddInlineMarkdown(Paragraph paragraph, string text)
        {
            int lastIndex = 0;

            foreach (Match match in InlineMarkdownPattern.Matches(text))
            {
                if (match.Index > lastIndex)
                    paragraph.Inlines.Add(new Run(text[lastIndex..match.Index]));

                if (match.Groups[1].Success)
                {
                    paragraph.Inlines.Add(new Bold(new Run(match.Groups[1].Value)));
                }
                else if (match.Groups[2].Success)
                {
                    paragraph.Inlines.Add(new Run(match.Groups[2].Value)
                    {
                        FontFamily = new FontFamily("Consolas"),
                        FontSize = 12,
                        Background = new SolidColorBrush(Color.FromArgb(0x20, 0x88, 0x88, 0x88))
                    });
                }

                lastIndex = match.Index + match.Length;
            }

            if (lastIndex < text.Length)
                paragraph.Inlines.Add(new Run(text[lastIndex..]));
        }

        private void DownloadReport_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_reportPath) || !File.Exists(_reportPath))
            {
                System.Windows.MessageBox.Show(
                    "Report file not found.",
                    "Error",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Warning);
                return;
            }

            SaveExistingFile(_reportPath, "Save Report");
        }

        private void DownloadMetadata_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_metadataPath) || !File.Exists(_metadataPath))
            {
                System.Windows.MessageBox.Show(
                    "Metadata file not found.",
                    "Error",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Warning);
                return;
            }

            SaveExistingFile(_metadataPath, "Save Lifecycle Metadata");
        }

        private static void SaveExistingFile(string sourcePath, string title)
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = title,
                FileName = Path.GetFileName(sourcePath),
                Filter = "Text files (*.txt)|*.txt",
                DefaultExt = ".txt"
            };

            if (dlg.ShowDialog() != true)
                return;

            File.Copy(sourcePath, dlg.FileName, overwrite: true);
            Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
        }
    }
}
