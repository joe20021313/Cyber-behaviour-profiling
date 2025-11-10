#include <iostream>
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <unordered_map> // For std::unordered_map
#include <vector>        // For std::vector
#include <tchar.h>       // For TCHAR macros

using namespace std;

// Forward declarations
std::wstring GetProcessUserName(DWORD dwProcessId);
std::unordered_map<std::wstring, std::vector<DWORD>> GetAllRunningProcessesForCurrentUser();

// Main function - entry point of the program
int main() {
    cout << "=== WMI Process Query Demo ===" << endl << endl;
    
    // Call the function that gets all processes for current user
    auto processMap = GetAllRunningProcessesForCurrentUser();
    
    // Display results
    if (processMap.empty()) {
        cout << "No processes found or an error occurred." << endl;
    } else {
        cout << "Found " << processMap.size() << " different process names running under your account:" << endl << endl;
        
        for (const auto& entry : processMap) {
            // Convert wide string to regular string for display
            wstring processName = entry.first;
            wcout << L"Process: " << processName << L" (PIDs: ";
            
            // Show all process IDs for this process name
            for (size_t i = 0; i < entry.second.size(); i++) {
                wcout << entry.second[i];
                if (i < entry.second.size() - 1) wcout << L", ";
            }
            wcout << L")" << endl;
        }
    }
    
    return 0;
}

// Get the username of the process owner
std::wstring GetProcessUserName(DWORD dwProcessId)
{
    // Open a handle to the process (like getting a reference to it)
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
    if (processHandle != NULL)
    {
        HANDLE tokenHandle;
        // Get the security token of the process (contains user info)
        if (OpenProcessToken(processHandle, TOKEN_READ, &tokenHandle))
        {
            TOKEN_USER tokenUser;
            ZeroMemory(&tokenUser, sizeof(TOKEN_USER));
            DWORD tokenUserLength = 0;

            PTOKEN_USER pTokenUser;
            // First call to get the required buffer size
            GetTokenInformation(tokenHandle, TokenUser, NULL, 0, &tokenUserLength);
            pTokenUser = (PTOKEN_USER) new BYTE[tokenUserLength];

            // Second call to actually get the token information
            if (GetTokenInformation(tokenHandle, TokenUser, pTokenUser, tokenUserLength, &tokenUserLength))
            {
                // Convert SID (Security Identifier) to username
                wchar_t szUserName[_MAX_PATH];
                DWORD dwUserNameLength = _MAX_PATH;
                wchar_t szDomainName[_MAX_PATH];
                DWORD dwDomainNameLength = _MAX_PATH;
                SID_NAME_USE sidNameUse;
                
                LookupAccountSidW(NULL, pTokenUser->User.Sid, szUserName, &dwUserNameLength, 
                                szDomainName, &dwDomainNameLength, &sidNameUse);
                
                delete[] pTokenUser; // Free allocated memory
                CloseHandle(tokenHandle);
                CloseHandle(processHandle);
                return std::wstring(szUserName);
            }
            delete[] pTokenUser;
            CloseHandle(tokenHandle);
        }
        CloseHandle(processHandle);
    }

    return std::wstring(); // Return empty string if failed
}

std::unordered_map<std::wstring, std::vector<DWORD>> GetAllRunningProcessesForCurrentUser()
{
    std::unordered_map<std::wstring, std::vector<DWORD>> processHash;

    HRESULT hres;

    // Step 1: Initialize COM (Component Object Model) library
    // Think of this like setting up a connection to Windows services
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        cout << "Failed to initialize COM library" << endl;
        return processHash; // Return empty map
    }

    // Using a do-while(false) pattern for easy error handling with break
    // Similar to try-catch in JavaScript, but we break out on errors
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    IEnumWbemClassObject *pEnumerator = NULL;
    
    do {
        // Step 2: Create WMI locator object
        // WMI = Windows Management Instrumentation (think of it as Windows API for system info)
        hres = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            (LPVOID *)&pLoc
        );
        
        if (FAILED(hres))
        {
            cout << "Failed to create IWbemLocator object" << endl;
            break;
        }

        // Step 3: Connect to WMI namespace
        // ROOT\\CIMV2 is like a database that contains info about Windows processes, services, etc.
        BSTR bstrNamespace = SysAllocString(L"ROOT\\CIMV2");
        hres = pLoc->ConnectServer(
            bstrNamespace,             // WMI namespace (like a database name)
            NULL,                      // User name (NULL = current user)
            NULL,                      // Password (NULL = current user)
            0,                         // Locale
            0,                         // Security flags (use 0 instead of NULL)
            0,                         // Authority
            0,                         // Context object 
            &pSvc                      // Pointer to IWbemServices proxy (our connection)
        );
        SysFreeString(bstrNamespace);

        if (FAILED(hres))
        {
            cout << "Could not connect to WMI namespace" << endl;
            break;
        }

        // Step 4: Set security levels on the proxy
        // This is required for WMI queries to work properly (security handshake)
        hres = CoSetProxyBlanket(
            pSvc,                        // The proxy to set
            RPC_C_AUTHN_WINNT,           // Authentication service
            RPC_C_AUTHZ_NONE,            // Authorization service
            NULL,                        // Server principal name 
            RPC_C_AUTHN_LEVEL_CALL,      // Authentication level
            RPC_C_IMP_LEVEL_IMPERSONATE, // Impersonation level
            NULL,                        // Client identity
            EOAC_NONE                    // Proxy capabilities 
        );

        if (FAILED(hres))
        {
            cout << "Could not set proxy blanket" << endl;
            break;
        }

        // Step 5: Execute WQL query to get all processes
        // WQL = WMI Query Language (similar to SQL but for Windows system info)
        // This is like: SELECT * FROM processes_table in a database
        BSTR bstrWQL = SysAllocString(L"WQL");
        BSTR bstrQuery = SysAllocString(L"SELECT * FROM Win32_Process");
        hres = pSvc->ExecQuery(
            bstrWQL,                                        // Query language (use L prefix for wide string)
            bstrQuery,                                      // The actual query
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, // Flags for performance
            NULL,
            &pEnumerator  // Result set (like a cursor in database)
        );
        SysFreeString(bstrWQL);
        SysFreeString(bstrQuery);

        if (FAILED(hres))
        {
            cout << "Query for processes failed" << endl;
            break;
        }

        // Step 6: Loop through query results
        // Similar to iterating through database rows or array of objects in JavaScript
        IWbemClassObject *pclsObj = NULL;
        while (pEnumerator)
        {
            ULONG uReturn = 0;
            
            // Get next item from enumerator (like iterator.next() in JS)
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

            if (0 == uReturn)  // No more items
            {
                break;
            }

            // Get properties from the WMI object
            VARIANT vtProp;   // Will hold process name
            VARIANT vtProp2;  // Will hold process ID

            // Get "Name" property (e.g., "chrome.exe", "notepad.exe")
            hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
            
            // Get "ProcessId" property (the PID number)
            hr = pclsObj->Get(L"ProcessId", 0, &vtProp2, NULL, NULL);

            // Get the username who owns this process
            auto userName = GetProcessUserName(vtProp2.intVal);

            // Get current logged-in user name
            wchar_t szActiveUserName[_MAX_PATH];
            DWORD dwActiveUserNameLength = _MAX_PATH;
            GetUserNameW(szActiveUserName, &dwActiveUserNameLength);

            // Only add to our map if this process belongs to current user
            if (wcscmp(userName.c_str(), szActiveUserName) == 0)
            {
                // Add to hash map: processName -> [array of PIDs]
                // Like: { "chrome.exe": [1234, 5678], "notepad.exe": [9012] }
                processHash[vtProp.bstrVal].push_back(vtProp2.intVal);
            }

            // Clean up variants (free memory)
            VariantClear(&vtProp2);
            VariantClear(&vtProp);

            // Release this object before getting next one
            pclsObj->Release();
            pclsObj = NULL;
        }
    } while (false);

    // Cleanup: Release all COM objects (like closing database connections)
    if (pEnumerator)
        pEnumerator->Release();
    if (pSvc)
        pSvc->Release();
    if (pLoc)
        pLoc->Release();

    // Uninitialize COM
    CoUninitialize();

    return processHash;
}
