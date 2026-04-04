using System.Windows;
using System.Windows.Controls;
using Cyber_behaviour_profiling;

namespace cyber_behaviour_profiling_2.Pages
{
    public partial class SettingsPage : Page
    {
        public SettingsPage()
        {
            InitializeComponent();
            RefreshLoggingStatus();
        }

        private void EnableLogging_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                LiveMonitoringSession.EnableScriptBlockLogging();
                RefreshLoggingStatus();
            }
            catch
            {
                MessageBox.Show("Failed to enable logging. Make sure the application is running as administrator.",
                    "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void DisableLogging_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                LiveMonitoringSession.DisableScriptBlockLogging();
                RefreshLoggingStatus();
            }
            catch
            {
                MessageBox.Show("Failed to disable logging. Make sure the application is running as administrator.",
                    "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void RefreshLoggingStatus()
        {
            bool enabled = LiveMonitoringSession.IsScriptBlockLoggingEnabled();
            LoggingStatusText.Text = enabled ? "Status: Enabled" : "Status: Disabled";
            LoggingStatusText.Foreground = enabled
                ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x27, 0xAE, 0x60))
                : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xE7, 0x4C, 0x3C));
        }
    }
}
