using System.Windows.Controls;

namespace cyber_behaviour_profiling_2.Pages
{
    public partial class SettingsPage : Page
    {
        public SettingsPage()
        {
            InitializeComponent();
        }

        private void BtnSaveDetection_Click(object sender, System.Windows.RoutedEventArgs e)
        {
            bool enabled = ChkEnableDetection.IsChecked == true;
            string method = (CmbMethod.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content as string ?? "Heuristic";
            int sensitivity = (int)SldSensitivity.Value;

            System.Diagnostics.Debug.WriteLine($"Save detection: enabled={enabled}, method={method}, sensitivity={sensitivity}");
            System.Windows.MessageBox.Show("Detection settings saved (debug).", "Saved", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
        }
    }
}