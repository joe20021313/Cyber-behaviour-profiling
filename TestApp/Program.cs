using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace TestApp;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("=== Behavior Test Application ===");
        Console.WriteLine("This app generates various behaviors for monitoring.");
        Console.WriteLine();

        bool running = true;
        while (running)
        {
            Console.WriteLine("\nChoose an action:");
            Console.WriteLine("1. File Operations (Create/Write/Read/Delete)");
            Console.WriteLine("2. Registry Operations (Create/Write/Delete)");
            Console.WriteLine("3. Network Activity (HTTP Request)");
            Console.WriteLine("4. Spawn Child Process (notepad)");
            Console.WriteLine("5. Write to AppData (Suspicious Path)");
            Console.WriteLine("6. Execute PowerShell Command");
            Console.WriteLine("7. Write to Registry Run Key (Persistence)");
            Console.WriteLine("8. DNS Query Test");
            Console.WriteLine("9. All Actions (Full Test)");
            Console.WriteLine("0. Exit");
            Console.Write("\nEnter choice: ");

            var choice = Console.ReadLine();

            try
            {
                switch (choice)
                {
                    case "1":
                        TestFileOperations();
                        break;
                    case "2":
                        TestRegistryOperations();
                        break;
                    case "3":
                        await TestNetworkActivity();
                        break;
                    case "4":
                        TestChildProcess();
                        break;
                    case "5":
                        TestSuspiciousFileWrite();
                        break;
                    case "6":
                        TestPowerShellExecution();
                        break;
                    case "7":
                        TestRegistryPersistence();
                        break;
                    case "8":
                        await TestDnsQuery();
                        break;
                    case "9":
                        await RunFullTest();
                        break;
                    case "0":
                        running = false;
                        break;
                    default:
                        Console.WriteLine("Invalid choice.");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        Console.WriteLine("\nExiting...");
    }

    static void TestFileOperations()
    {
        Console.WriteLine("\n[TEST] File Operations");
        string testFile = Path.Combine(Path.GetTempPath(), "test_file.txt");

        Console.WriteLine($"Creating file: {testFile}");
        File.WriteAllText(testFile, "This is a test file created at " + DateTime.Now);
        Console.WriteLine("✓ File created and written");

        Console.WriteLine("Reading file...");
        string content = File.ReadAllText(testFile);
        Console.WriteLine($"✓ File read ({content.Length} chars)");

        Console.WriteLine("Appending to file...");
        File.AppendAllText(testFile, "\nAppended line.");
        Console.WriteLine("✓ File appended");

        Console.WriteLine("Deleting file...");
        File.Delete(testFile);
        Console.WriteLine("✓ File deleted");
    }

    static void TestRegistryOperations()
    {
        Console.WriteLine("\n[TEST] Registry Operations");
        string keyPath = @"Software\TestApp";

        try
        {
            Console.WriteLine($"Creating registry key: HKCU\\{keyPath}");
            using (var key = Registry.CurrentUser.CreateSubKey(keyPath))
            {
                Console.WriteLine("✓ Registry key created");

                Console.WriteLine("Writing registry value...");
                key?.SetValue("TestValue", "Hello from TestApp at " + DateTime.Now);
                Console.WriteLine("✓ Registry value written");

                Console.WriteLine("Reading registry value...");
                var value = key?.GetValue("TestValue");
                Console.WriteLine($"✓ Registry value read: {value}");
            }

            Console.WriteLine("Deleting registry key...");
            Registry.CurrentUser.DeleteSubKey(keyPath);
            Console.WriteLine("✓ Registry key deleted");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Registry operation failed: {ex.Message}");
        }
    }

    static async Task TestNetworkActivity()
    {
        Console.WriteLine("\n[TEST] Network Activity");
        using var client = new HttpClient();

        try
        {
            Console.WriteLine("Making HTTP request to https://www.google.com");
            var response = await client.GetAsync("https://www.google.com");
            Console.WriteLine($"✓ HTTP request completed: {response.StatusCode}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Network request failed: {ex.Message}");
        }
    }

    static void TestChildProcess()
    {
        Console.WriteLine("\n[TEST] Spawning Child Process");
        try
        {
            Console.WriteLine("Spawning notepad.exe...");
            var process = Process.Start("notepad.exe");
            Console.WriteLine($"✓ Child process spawned (PID: {process?.Id})");
            Console.WriteLine("Note: Close notepad manually.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to spawn child process: {ex.Message}");
        }
    }

    static void TestSuspiciousFileWrite()
    {
        Console.WriteLine("\n[TEST] Suspicious File Write (AppData)");
        string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string suspiciousFile = Path.Combine(appDataPath, "suspicious_script.txt");

        try
        {
            Console.WriteLine($"Writing to AppData: {suspiciousFile}");
            File.WriteAllText(suspiciousFile, "This simulates malware dropping a payload.");
            Console.WriteLine("✓ Suspicious file written to AppData");

            Console.WriteLine("Deleting file...");
            File.Delete(suspiciousFile);
            Console.WriteLine("✓ File cleaned up");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed: {ex.Message}");
        }
    }

    static void TestPowerShellExecution()
    {
        Console.WriteLine("\n[TEST] PowerShell Execution");
        try
        {
            Console.WriteLine("Executing PowerShell command: Get-Date");
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-Command \"Get-Date\"",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            string output = process?.StandardOutput.ReadToEnd() ?? "";
            process?.WaitForExit();

            Console.WriteLine($"✓ PowerShell executed: {output.Trim()}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"PowerShell execution failed: {ex.Message}");
        }
    }

    static void TestRegistryPersistence()
    {
        Console.WriteLine("\n[TEST] Registry Persistence (Run Key)");
        string runKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";

        try
        {
            Console.WriteLine($"Writing to Run key (simulates persistence)...");
            using var key = Registry.CurrentUser.OpenSubKey(runKeyPath, writable: true);
            key?.SetValue("TestApp_Persistence", "C:\\Windows\\System32\\calc.exe");
            Console.WriteLine("✓ Run key written (persistence attempt)");

            Console.WriteLine("Cleaning up...");
            key?.DeleteValue("TestApp_Persistence", throwOnMissingValue: false);
            Console.WriteLine("✓ Run key removed");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Registry persistence test failed: {ex.Message}");
        }
    }

    static async Task TestDnsQuery()
    {
        Console.WriteLine("\n[TEST] DNS Query");
        using var client = new HttpClient();

        string[] testDomains = {
            "https://www.google.com",
            "https://www.microsoft.com",
            "https://github.com"
        };

        foreach (var domain in testDomains)
        {
            try
            {
                Console.WriteLine($"Querying: {domain}");
                await client.GetAsync(domain);
                Console.WriteLine($"✓ DNS query completed");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DNS query failed: {ex.Message}");
            }
        }
    }

    static async Task RunFullTest()
    {
        Console.WriteLine("\n[TEST] Running Full Test Suite");
        Console.WriteLine("This will execute all test actions in sequence.\n");

        TestFileOperations();
        await Task.Delay(1000);

        TestRegistryOperations();
        await Task.Delay(1000);

        await TestNetworkActivity();
        await Task.Delay(1000);

        TestSuspiciousFileWrite();
        await Task.Delay(1000);

        TestPowerShellExecution();
        await Task.Delay(1000);

        TestRegistryPersistence();
        await Task.Delay(1000);

        await TestDnsQuery();
        await Task.Delay(1000);

        TestChildProcess();

        Console.WriteLine("\n✓ Full test suite completed!");
    }
}
