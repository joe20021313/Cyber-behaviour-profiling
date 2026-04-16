using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using Cyber_behaviour_profiling;
using Wpf.Ui.Controls;

namespace cyber_behaviour_profiling_2
{
    public partial class MainWindow : FluentWindow
    {
        public MainWindow()
        {
            InitializeComponent();
            string dataPath = System.IO.Path.Combine(AppContext.BaseDirectory, "data.json");
            MapToData.LoadBaselines(MapToData.ResolveBaselinePath(dataPath));
            MainFrame.Navigate(new Pages.DetectionPage());
        }

        private void NavView_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            if (FindNavigationItem(e.OriginalSource) is not NavigationViewItem item ||
                item.Tag is not string tag)
            {
                return;
            }

            NavigateToSection(tag);
        }

        private static NavigationViewItem? FindNavigationItem(object source)
        {
            for (DependencyObject? current = source as DependencyObject; current != null;
                 current = VisualTreeHelper.GetParent(current))
            {
                if (current is NavigationViewItem item)
                    return item;
            }

            return null;
        }

        private void NavigateToSection(string tag)
        {
            switch (tag)
            {
                case "Dashboard":
                    MainFrame.Navigate(new Pages.DetectionPage());
                    break;
                case "Baselines":
                    MainFrame.Navigate(new Pages.BaselinesPage());
                    break;
                case "Reports":
                    MainFrame.Navigate(new Pages.ReportsPage());
                    break;
                case "Settings":
                    MainFrame.Navigate(new Pages.SettingsPage());
                    break;
            }
        }
    }
}