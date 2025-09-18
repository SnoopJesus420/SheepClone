#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

// Enable Token Privileges
BOOL EnablePrivilege()
{   
    LPCSTR privilegeName = L"SeDebugPrivilege";
    HANDLE tokenHandle;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    // Open process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle))
    {
        printf("\t [!] OpenProcessToken Failed! %d \n", GetLastError());
        return FALSE;
    }
    printf("[i] Got Token handle: %p", tokenHandle);

    // Lookup privilege value
    if (!LookupPrivilegeValueA(NULL, privilegeName, &luid))
    {   
        printf("\t [!] LookupPrivilegeValueA Failed! %d \n", GetLastError());
        CloseHandle(tokenHandle);
        return FALSE;
    }

    // Set up privilege structure
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    printf("[+] Adjusting token privileges...");
    // Adjust token privileges
    if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tp, 0, NULL, NULL))
    {   
        printf("\t [!] AdjustTokenPrivileges Failed! %d", GetLastError());
        CloseHandle(tokenHandle);
        return FALSE;
    }

    // Check for not all assigned error
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        CloseHandle(tokenHandle);
        return FALSE;
    }

    CloseHandle(tokenHandle);
    return TRUE;
}

int main() {

    printf("[i] Checking token privileges.. \n");
    if (!EnablePrivilege()) {
        printf("\t [!] EnablePrivilege Failed!!! \n");
    }
    printf("[i] You've been privileged wigger :) \n");

    return 0;
	
}