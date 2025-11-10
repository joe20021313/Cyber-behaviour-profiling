# Cyber Behaviour Profiling - WMI Process Monitor

A C++ program that uses Windows Management Instrumentation (WMI) to query and display all running processes for the current user.

## Features

- Queries all running processes on Windows using WMI
- Filters processes by current logged-in user
- Groups processes by name and shows all PIDs
- Demonstrates COM/WMI programming in C++

## Requirements

- Windows OS
- MinGW-w64 (g++ compiler)
- Required Windows libraries (included with MinGW):
  - `ole32` - COM runtime
  - `oleaut32` - OLE automation
  - `wbemuuid` - WMI interface definitions

## Compilation

```powershell
g++ hello.cpp -o main -lole32 -loleaut32 -lwbemuuid
```

## Running

```powershell
.\main.exe
```

## Output Example

```
=== WMI Process Query Demo ===

Found 49 different process names running under your account:

Process: chrome.exe (PIDs: 1234, 5678, 9012)
Process: Code.exe (PIDs: 3456, 7890)
Process: notepad.exe (PIDs: 1111)
...
```

## How It Works

1. **Initialize COM** - Set up Component Object Model runtime
2. **Create WMI Locator** - Get access to WMI services
3. **Connect to ROOT\CIMV2** - Connect to WMI namespace containing system info
4. **Set Security** - Configure authentication/authorization
5. **Execute WQL Query** - Run `SELECT * FROM Win32_Process`
6. **Process Results** - Filter by current user and group by process name
7. **Cleanup** - Release COM objects and uninitialize

## Code Structure

- `main()` - Entry point, calls the query function and displays results
- `GetAllRunningProcessesForCurrentUser()` - Main WMI query logic
- `GetProcessUserName()` - Helper to get the username of a process owner

## Documentation

See [WMI_EXPLANATION.md](./WMI_EXPLANATION.md) for a detailed explanation of the code, especially if you're coming from JavaScript.

## Why These Libraries?

- **`-lole32`** - Provides `CoInitializeEx()`, `CoCreateInstance()`, and other core COM functions
- **`-loleaut32`** - Provides `SysAllocString()`, `SysFreeString()`, `VariantClear()` for string/variant handling
- **`-lwbemuuid`** - Provides WMI GUIDs like `CLSID_WbemLocator`, `IID_IWbemServices`

Without these libraries, you'll get "undefined reference" linker errors.

## Troubleshooting

### Compilation Errors

If you get "undefined reference" errors:
- Make sure you include all three libraries: `-lole32 -loleaut32 -lwbemuuid`
- Check that MinGW-w64 is properly installed
- Libraries must come AFTER the source file in the compile command

### Runtime Errors

If the program fails to run:
- Ensure you're running on Windows (WMI is Windows-only)
- Run with administrator privileges if needed
- Check that WMI service is running: `services.msc` → "Windows Management Instrumentation"

## Learning Resources

- **WMI Classes Reference:** [Microsoft Docs - Win32 Provider](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-provider)
- **WQL Syntax:** [WMI Query Language](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wql-sql-for-wmi)
- **COM Programming:** [Component Object Model](https://learn.microsoft.com/en-us/windows/win32/com/component-object-model--com--portal)

## License

MIT License - Feel free to use and modify as needed.
