using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace cyber_behaviour_profiling_2.Pages
{
    public partial class RulesPage : Page
    {
        private static readonly (string Name, Color Color)[] EventTypes =
        {
            ("ProcessSpawn",    Color.FromRgb(0xE7, 0x4C, 0x3C)),
            ("FileWrite",       Color.FromRgb(0x9B, 0x59, 0xB6)),
            ("Registry",        Color.FromRgb(0x34, 0x98, 0xDB)),
            ("NetworkConnect",  Color.FromRgb(0xE6, 0x7E, 0x22)),
            ("DNS_Query",       Color.FromRgb(0xD3, 0x54, 0x00)),
            ("Any",             Color.FromRgb(0x7F, 0x8C, 0x8D)),
        };

        private string _selectedType = "ProcessSpawn";
        private readonly List<CustomRule> _rules = new();

        public RulesPage()
        {
            InitializeComponent();
            BuildTypeChips();
            RebuildGroupPanel();
        }

        private void BuildTypeChips()
        {
            TypeChips.Children.Clear();
            foreach (var (name, color) in EventTypes)
            {
                var chip = new Border
                {
                    CornerRadius    = new CornerRadius(16),
                    Padding         = new Thickness(12, 4, 12, 4),
                    Margin          = new Thickness(0, 0, 6, 6),
                    Background      = new SolidColorBrush(name == _selectedType
                                          ? color
                                          : Color.FromArgb(0x30, color.R, color.G, color.B)),
                    BorderThickness = new Thickness(1),
                    BorderBrush     = new SolidColorBrush(color),
                    Cursor          = System.Windows.Input.Cursors.Hand,
                    Tag             = name
                };

                chip.MouseLeftButtonUp += (_, _) =>
                {
                    _selectedType = name;
                    BuildTypeChips();
                };

                chip.Child = new TextBlock
                {
                    Text       = name,
                    FontSize   = 11,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = new SolidColorBrush(name == _selectedType ? Colors.White : color)
                };

                TypeChips.Children.Add(chip);
            }
        }

        private void AddRule_Click(object sender, RoutedEventArgs e)
        {
            string keyword = RuleKeyword.Text.Trim();
            string message = RuleMessage.Text.Trim();

            if (string.IsNullOrEmpty(keyword) || string.IsNullOrEmpty(message))
            {
                MessageBox.Show("Please enter both a keyword and a message.", "Missing fields",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _rules.Add(new CustomRule
            {
                EventType = _selectedType,
                Keyword   = keyword,
                Message   = message
            });

            RuleKeyword.Clear();
            RuleMessage.Clear();
            RebuildGroupPanel();
        }

        private void RebuildGroupPanel()
        {
            RulesGroupPanel.Children.Clear();

            foreach (var (typeName, typeColor) in EventTypes)
            {
                var group = _rules.Where(r => r.EventType == typeName).ToList();

                var headerBorder = new Border
                {
                    CornerRadius    = new CornerRadius(10, 10, 0, 0),
                    Padding         = new Thickness(14, 10, 14, 10),
                    Background      = new SolidColorBrush(Color.FromArgb(0xCC, typeColor.R, typeColor.G, typeColor.B)),
                    BorderThickness = new Thickness(1, 1, 1, 0),
                    BorderBrush     = new SolidColorBrush(typeColor),
                    Margin          = new Thickness(0, 0, 0, 0)
                };

                var headerStack = new StackPanel { Orientation = Orientation.Horizontal };
                headerStack.Children.Add(new TextBlock
                {
                    Text       = typeName,
                    FontSize   = 12,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = Brushes.White,
                    VerticalAlignment = VerticalAlignment.Center
                });
                headerStack.Children.Add(new Border
                {
                    Background      = new SolidColorBrush(Color.FromArgb(0x50, 255, 255, 255)),
                    CornerRadius    = new CornerRadius(10),
                    Padding         = new Thickness(7, 1, 7, 1),
                    Margin          = new Thickness(8, 0, 0, 0),
                    VerticalAlignment = VerticalAlignment.Center,
                    Child = new TextBlock
                    {
                        Text       = group.Count.ToString(),
                        FontSize   = 10,
                        FontWeight = FontWeights.Bold,
                        Foreground = Brushes.White
                    }
                });

                headerBorder.Child = headerStack;

                var bodyBorder = new Border
                {
                    CornerRadius    = new CornerRadius(0, 0, 10, 10),
                    Padding         = new Thickness(0),
                    Background      = new SolidColorBrush(Color.FromArgb(0x18, typeColor.R, typeColor.G, typeColor.B)),
                    BorderThickness = new Thickness(1, 0, 1, 1),
                    BorderBrush     = new SolidColorBrush(typeColor),
                    Margin          = new Thickness(0, 0, 0, 12)
                };

                var bodyStack = new StackPanel { Margin = new Thickness(12, 8, 12, 8) };

                if (group.Count == 0)
                {
                    bodyStack.Children.Add(new TextBlock
                    {
                        Text       = "No rules yet.",
                        FontSize   = 11,
                        Foreground = new SolidColorBrush(Color.FromArgb(0x88, 255, 255, 255)),
                        Margin     = new Thickness(0, 2, 0, 2)
                    });
                }
                else
                {
                    foreach (var rule in group)
                    {
                        var row = new Border
                        {
                            CornerRadius    = new CornerRadius(6),
                            Padding         = new Thickness(10, 6, 10, 6),
                            Margin          = new Thickness(0, 0, 0, 6),
                            Background      = new SolidColorBrush(Color.FromArgb(0x22, 255, 255, 255)),
                            BorderThickness = new Thickness(1),
                            BorderBrush     = new SolidColorBrush(Color.FromArgb(0x30, 255, 255, 255))
                        };

                        var rowGrid = new Grid();
                        rowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                        rowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                        rowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                        var kwText = new TextBlock
                        {
                            Text       = rule.Keyword,
                            FontSize   = 11,
                            FontWeight = FontWeights.SemiBold,
                            Foreground = Brushes.White,
                            VerticalAlignment = VerticalAlignment.Center,
                            Margin     = new Thickness(0, 0, 8, 0)
                        };
                        Grid.SetColumn(kwText, 0);

                        var msgText = new TextBlock
                        {
                            Text          = rule.Message,
                            FontSize      = 11,
                            Foreground    = new SolidColorBrush(Color.FromArgb(0xCC, 255, 255, 255)),
                            TextTrimming  = TextTrimming.CharacterEllipsis,
                            VerticalAlignment = VerticalAlignment.Center
                        };
                        Grid.SetColumn(msgText, 1);

                        var removeBtn = new Button
                        {
                            Content         = "✕",
                            Background      = Brushes.Transparent,
                            BorderThickness = new Thickness(0),
                            Foreground      = new SolidColorBrush(Color.FromArgb(0xAA, 255, 255, 255)),
                            FontSize        = 11,
                            Padding         = new Thickness(6, 2, 6, 2),
                            Cursor          = System.Windows.Input.Cursors.Hand,
                            Tag             = rule
                        };
                        removeBtn.Click += RemoveRule_Click;
                        Grid.SetColumn(removeBtn, 2);

                        rowGrid.Children.Add(kwText);
                        rowGrid.Children.Add(msgText);
                        rowGrid.Children.Add(removeBtn);
                        row.Child = rowGrid;
                        bodyStack.Children.Add(row);
                    }
                }

                bodyBorder.Child = bodyStack;

                var wrapper = new StackPanel();
                wrapper.Children.Add(headerBorder);
                wrapper.Children.Add(bodyBorder);
                RulesGroupPanel.Children.Add(wrapper);
            }
        }

        private void RemoveRule_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is CustomRule rule)
            {
                _rules.Remove(rule);
                RebuildGroupPanel();
            }
        }

        public IReadOnlyList<CustomRule> GetCustomRules() => _rules;
    }
}
