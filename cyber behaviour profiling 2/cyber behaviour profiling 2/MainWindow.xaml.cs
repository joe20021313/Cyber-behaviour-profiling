using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Wpf.Ui.Controls;
namespace cyber_behaviour_profiling_2
{

    public partial class MainWindow : FluentWindow
    {
        public MainWindow()
        {
            InitializeComponent();
            MainFrame.Navigate(new Pages.DetectionPage());
        }

        private void NavView_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            DependencyObject source = e.OriginalSource as DependencyObject;
            while (source != null && !(source is Wpf.Ui.Controls.NavigationViewItem))
            {
                source = VisualTreeHelper.GetParent(source);
            }

            if (source is Wpf.Ui.Controls.NavigationViewItem item)
            {
                if (item.Tag is string tag)
                {
                    switch (tag)
                    {
                        case "Dashboard":
                            MainFrame.Navigate(new Pages.DetectionPage());
                            break;
                        case "Rules":
                            MainFrame.Navigate(new Pages.RulesPage());
                            break;
                        case "Settings":
                            MainFrame.Navigate(new Pages.SettingsPage());
                            break;
                    }
                }
            }
        }
    }
}