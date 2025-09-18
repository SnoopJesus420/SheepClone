#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

// Check if a privilege is already enabled
BOOL IsPrivilegeEnabled(LPCWSTR privilegeName)
{
    HANDLE tokenHandle = NULL;
    DWORD bufferSize = 0;
    PTOKEN_PRIVILEGES privileges = NULL;
    BOOL found = FALSE;

    // Open process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
    {
        printf("\t[!] OpenProcessToken failed in IsPrivilegeEnabled! Error: %lu\n", GetLastError());
        return FALSE;
    }

    // Get required buffer size
    GetTokenInformation(tokenHandle, TokenPrivileges, NULL, 0, &bufferSize);
    privileges = (PTOKEN_PRIVILEGES)malloc(bufferSize);
    if (!privileges)
    {
        printf("\t[!] Memory allocation failed\n");
        CloseHandle(tokenHandle);
        return FALSE;
    }

    // Get privilege information
    if (!GetTokenInformation(tokenHandle, TokenPrivileges, privileges, bufferSize, &bufferSize))
    {
        printf("\t[!] GetTokenInformation failed! Error: %lu\n", GetLastError());
        free(privileges);
        CloseHandle(tokenHandle);
        return FALSE;
    }

    // Check for the privilege
    for (DWORD i = 0; i < privileges->PrivilegeCount; i++)
    {
        WCHAR name[256];
        DWORD nameSize = sizeof(name) / sizeof(WCHAR);
        if (LookupPrivilegeNameW(NULL, &privileges->Privileges[i].Luid, name, &nameSize))
        {
            if (_wcsicmp(name, privilegeName) == 0)
            {
                found = TRUE;
                if (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
                {
                    wprintf(L"\t[i] Privilege '%s' is already enabled (Attributes: 0x%lx)\n", privilegeName, privileges->Privileges[i].Attributes);
                    free(privileges);
                    CloseHandle(tokenHandle);
                    return TRUE;
                }
                break;
            }
        }
    }

    free(privileges);
    CloseHandle(tokenHandle);
    if (!found)
    {
        wprintf(L"\t[!] Privilege '%s' not found in process token\n", privilegeName);
        return FALSE;
    }
    return FALSE;
}

// Enable Token Privileges
BOOL EnablePrivilege()
{
    LPCWSTR privilegeName = L"SeDebugPrivilege";
    HANDLE tokenHandle;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    // Check if privilege is already enabled
    if (IsPrivilegeEnabled(privilegeName))
    {
        wprintf(L"\t[i] No need to enable '%s'; it is already enabled\n", privilegeName);
        return TRUE;
    }

    // Open process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle))
    {
        printf("\t[!] OpenProcessToken Failed! Error: %lu\n", GetLastError());
        return FALSE;
    }
    printf("\t[i] Got Token handle: %p\n", tokenHandle);

    // Lookup privilege value
    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid))
    {
        wprintf(L"\t[!] LookupPrivilegeValueW Failed for '%s'! Error: %lu\n", privilegeName, GetLastError());
        CloseHandle(tokenHandle);
        return FALSE;
    }

    // Set up privilege structure
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    printf("\t[i] Adjusting token privileges...\n");
    // Adjust token privileges
    if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tp, 0, NULL, NULL))
    {
        printf("\t[!] AdjustTokenPrivileges Failed! Error: %lu\n", GetLastError());
        CloseHandle(tokenHandle);
        return FALSE;
    }

    // Check for not all assigned error
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("\t[!] Privilege not held by process token! Error: %lu\n", GetLastError());
        CloseHandle(tokenHandle);
        return FALSE;
    }

    CloseHandle(tokenHandle);
    wprintf(L"\t[i] Successfully enabled '%s'\n", privilegeName);
    return TRUE;
}

int main()
{
    wprintf(L"[i] Checking token privileges...\n");
    if (!EnablePrivilege())
    {
        wprintf(L"\t[!] EnablePrivilege Failed!!!\n");
        return 1;
    }
    wprintf(L"[i] Privilege operation completed\n");
    return 0;
}