using System.Windows;
using System.Windows.Controls;

namespace cyber_behaviour_profiling_2.Pages
{
    public partial class SettingsPage : Page
    {
        public SettingsPage()
        {
            InitializeComponent();
        }

        private void BtnSaveDetection_Click(object sender, RoutedEventArgs e)
        {
            bool enabled = ChkEnableDetection.IsChecked == true;
            string method = (CmbMethod.SelectedItem as ComboBoxItem)?.Content as string ?? "Heuristic";
            int sensitivity = (int)SldSensitivity.Value;

            System.Diagnostics.Debug.WriteLine($"Save detection: enabled={enabled}, method={method}, sensitivity={sensitivity}");
            MessageBox.Show("Detection settings saved (debug).", "Saved", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}