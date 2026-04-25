using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.ServiceProcess;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Cyber_behaviour_profiling;

namespace cyber_behaviour_profiling_2.Pages
{
    public partial class SettingsPage : Page
    {
        private static readonly SolidColorBrush GreenBrush  = new(Color.FromRgb(0x27, 0xAE, 0x60));
        private static readonly SolidColorBrush OrangeBrush = new(Color.FromRgb(0xE6, 0x7E, 0x22));
        private static readonly SolidColorBrush RedBrush    = new(Color.FromRgb(0xE7, 0x4C, 0x3C));
        private static readonly SolidColorBrush GreyBrush   = new(Color.FromRgb(0x95, 0xA5, 0xA6));

        public SettingsPage()
        {
            InitializeComponent();
            RefreshLoggingStatus();
            _ = RefreshSysmonStatusAsync();
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
            LoggingStatusText.Text       = enabled ? "Status: Enabled" : "Status: Disabled";
            LoggingStatusText.Foreground = enabled ? GreenBrush : RedBrush;
        }

        private void RefreshSysmon_Click(object sender, RoutedEventArgs e)
            => _ = RefreshSysmonStatusAsync();

        private async void ApplySysmonConfig_Click(object sender, RoutedEventArgs e)
        {
            string sysmonExe = FindSysmonExe();
            string configPath = Path.Combine(AppContext.BaseDirectory, "sysmon-profiler.xml");

            if (!File.Exists(configPath))
            {
                MessageBox.Show("sysmon-profiler.xml not found next to the application.\nPlease run Setup-Sysmon.ps1 manually.",
                    "Config not found", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (string.IsNullOrEmpty(sysmonExe))
            {
                MessageBox.Show("Sysmon executable not found.\nRun Setup-Sysmon.ps1 to install and configure Sysmon automatically.",
                    "Sysmon not installed", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                ApplySysmonConfigButton.IsEnabled = false;
                var psi = new ProcessStartInfo
                {
                    FileName        = sysmonExe,
                    Arguments       = $"-c \"{configPath}\" -accepteula",
                    Verb            = "runas",
                    UseShellExecute = true,
                    WindowStyle     = ProcessWindowStyle.Hidden
                };
                var proc = Process.Start(psi)!;
                await Task.Run(() => proc.WaitForExit());
                await RefreshSysmonStatusAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to apply config: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            finally
            {
                ApplySysmonConfigButton.IsEnabled = true;
            }
        }

        private async Task RefreshSysmonStatusAsync()
        {
            SetSysmonPending();
            var status = await Task.Run(GetSysmonStatus);
            ApplySysmonStatus(status);
        }

        private void SetSysmonPending()
        {
            SysmonServiceStatus.Text       = "Checking…";
            SysmonServiceStatus.Foreground = GreyBrush;
            SysmonEv10Status.Text          = "—";
            SysmonEv10Status.Foreground    = GreyBrush;
            SysmonEv8Status.Text           = "—";
            SysmonEv8Status.Foreground     = GreyBrush;
            SysmonEv25Status.Text          = "—";
            SysmonEv25Status.Foreground    = GreyBrush;
        }

        private record SysmonStatus(
            bool ServiceInstalled,
            bool ServiceRunning,
            string ServiceName,
            bool Ev10Active,
            bool Ev8Active,
            bool Ev25Active);

        private static SysmonStatus GetSysmonStatus()
        {
            ServiceController? svc = null;
            foreach (var name in new[] { "Sysmon64", "Sysmon" })
            {
                try { svc = new ServiceController(name); _ = svc.Status; break; }
                catch { svc = null; }
            }

            bool installed = svc != null;
            bool running   = svc?.Status == ServiceControllerStatus.Running;
            string svcName = svc?.ServiceName ?? "";

            if (!running)
                return new SysmonStatus(installed, false, svcName, false, false, false);

            const string log = "Microsoft-Windows-Sysmon/Operational";
            bool ev10 = HasEvents(log, 10);
            bool ev8  = HasEvents(log, 8);
            bool ev25 = HasEvents(log, 25);

            return new SysmonStatus(installed, true, svcName, ev10, ev8, ev25);
        }

        private static bool HasEvents(string logName, int eventId)
        {
            try
            {
                var query  = new EventLogQuery(logName, PathType.LogName,
                    $"*[System[EventID={eventId}]]");
                using var reader = new EventLogReader(query);
                return reader.ReadEvent() != null;
            }
            catch { return false; }
        }

        private void ApplySysmonStatus(SysmonStatus s)
        {
            if (!s.ServiceInstalled)
            {
                SysmonServiceStatus.Text       = "Not Installed";
                SysmonServiceStatus.Foreground = RedBrush;
                SetEventRow(SysmonEv10Status, null, "Requires Sysmon");
                SetEventRow(SysmonEv8Status,  null, "Requires Sysmon");
                SetEventRow(SysmonEv25Status, null, "Requires Sysmon");
                return;
            }

            if (!s.ServiceRunning)
            {
                SysmonServiceStatus.Text       = $"Stopped  ({s.ServiceName})";
                SysmonServiceStatus.Foreground = RedBrush;
                SetEventRow(SysmonEv10Status, null, "Service stopped");
                SetEventRow(SysmonEv8Status,  null, "Service stopped");
                SetEventRow(SysmonEv25Status, null, "Service stopped");
                return;
            }

            SysmonServiceStatus.Text       = $"Running  ({s.ServiceName})";
            SysmonServiceStatus.Foreground = GreenBrush;

            // EventID 10 fires constantly (svchost→lsass); if no events exist the rule is not applied.
            SetEventRow(SysmonEv10Status, s.Ev10Active,
                s.Ev10Active ? "Active" : "Rule not applied — click Apply Profiler Config");

            // EventID 8 fires only on injection; absence means no events yet, not misconfigured.
            SetEventRow(SysmonEv8Status, s.Ev8Active || s.Ev10Active,
                s.Ev8Active ? "Active" : s.Ev10Active ? "Ready (no events yet)" : "Rule not applied");

            // EventID 25 is very rare; treat same as EventID 8.
            SetEventRow(SysmonEv25Status, s.Ev25Active || s.Ev10Active,
                s.Ev25Active ? "Active" : s.Ev10Active ? "Ready (no events yet)" : "Rule not applied");
        }

        private void SetEventRow(TextBlock block, bool? ok, string label)
        {
            block.Text       = label;
            block.Foreground = ok switch { true => GreenBrush, false => RedBrush, null => OrangeBrush };
        }

        private static string FindSysmonExe()
        {
            foreach (var name in new[] { "Sysmon64.exe", "Sysmon.exe" })
            {
                string sys32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), name);
                if (File.Exists(sys32)) return sys32;
                string win = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), name);
                if (File.Exists(win)) return win;
            }
            return "";
        }
    }
}
