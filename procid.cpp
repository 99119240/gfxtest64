#include <iostream>
#include <windows.h>

int main()
{
    const char* exeName = "GFXTest64.exe";

    // Find the process ID by the executable name
    DWORD gfxTestProcessId = GetProcessIdByName(exeName);

    if (gfxTestProcessId != 0)
    {
        std::cout << "Process ID of " << exeName << ": " << gfxTestProcessId << std::endl;

        // Open a handle to the kernel driver (replace "TestDriver" with your actual driver name)
        HANDLE hDriver = CreateFile(L"\\\\.\\TestDriver", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (hDriver != INVALID_HANDLE_VALUE)
        {
            // Send the process ID to the kernel driver
            DWORD bytesReturned;
            DeviceIoControl(hDriver, IOCTL_CUSTOM_SET_PROCID, &gfxTestProcessId, sizeof(gfxTestProcessId), nullptr, 0, &bytesReturned, nullptr);

            // Close the handle to the driver
            CloseHandle(hDriver);
        }
        else
        {
            std::cerr << "Failed to open the driver." << std::endl;
        }
    }
    else
    {
        std::cerr << exeName << " not found." << std::endl;
    }

    return 0;
}
