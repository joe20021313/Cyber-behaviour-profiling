#include <iostream>
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>

using namespace std; // a way to avoid std:: every single time you use cout

int main() {
    // Initialize COM
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        cout << "Failed to initialize COM library. Error code = 0x" 
             << hex << hres << endl;
        return 1;
    }

    cout << "Hello, WMI++!" << endl;
    
    // Uninitialize COM
    CoUninitialize();
    return 0;
}