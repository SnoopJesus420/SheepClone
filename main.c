#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

// Define STATUS_SUCCESS if not already defined
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

// Define NTSTATUS if not already defined
#ifndef NTSTATUS
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
#endif

// Define NTAPI if not already defined
#ifndef NTAPI
#define NTAPI __stdcall
#endif

// Define UNICODE_STRING structure
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// Define CLIENT_ID structure
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// Define OBJECT_ATTRIBUTES structure
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// Define NtOpenProcess function pointer type
typedef NTSTATUS (NTAPI *PNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

// Global function pointer for NtOpenProcess
static PNtOpenProcess pNtOpenProcess = NULL;


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

// Load NtOpenProcess function from ntdll.dll
BOOL LoadNtOpenProcess() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL) {
        printf("\t[!] Failed to get handle to ntdll.dll! Error: %lu\n", GetLastError());
        return FALSE;
    }
    
    pNtOpenProcess = (PNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
    if (pNtOpenProcess == NULL) {
        printf("\t[!] Failed to get address of NtOpenProcess! Error: %lu\n", GetLastError());
        return FALSE;
    }
    printf("\t[i] Successfully loaded NtOpenProcess from ntdll.dll\n");
    return TRUE;
}

// Find Process Function
DWORD FindProcess(DWORD pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("\t [!] Failed to create snapshot! Error Code: %u\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32 pe32 = { sizeof(pe32) };
    DWORD foundPid = 0;

    if (Process32First(snapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                foundPid = pid;
                break;
            }
        } while (Process32Next(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return foundPid;
}


// Function to open a handle to the target process
NTSTATUS OpenProcessByPID(DWORD pid, PHANDLE hProcess) {
    OBJECT_ATTRIBUTES parentProcessObjectAttributes;
    CLIENT_ID parentProcessClientId;
    NTSTATUS ntStatus;

    // Initialize OBJECT_ATTRIBUTES manually
    parentProcessObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    parentProcessObjectAttributes.RootDirectory = NULL;
    parentProcessObjectAttributes.ObjectName = NULL;
    parentProcessObjectAttributes.Attributes = 0;
    parentProcessObjectAttributes.SecurityDescriptor = NULL;
    parentProcessObjectAttributes.SecurityQualityOfService = NULL;

    // Initialize CLIENT_ID
    parentProcessClientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    parentProcessClientId.UniqueThread = NULL;

    // Open handle to target process
    ntStatus = pNtOpenProcess(
        hProcess,
        PROCESS_CREATE_PROCESS,
        &parentProcessObjectAttributes,
        &parentProcessClientId
    );
    
    return ntStatus;
}


int main(int argc, char *argv[]) {
    // Variable Initalization
    DWORD processToClonePid = 0;
    HANDLE hParentProcess = NULL;
    NTSTATUS NtStatus;
    char* endptr;

    // Check arguments
    if (argc != 3 || (argc > 0 && argv[0] == "-h")) {
        printf("Usage: %s <PID> <PATH_TO_DUMP>\n", argv[0]);
        return 1;
    }

    // Validate PID Parameter Input
    processToClonePid = strtol(argv[1], &endptr, 10);
    if (endptr == argv[1] || *endptr != '\0') {
        printf("\t [!] Invalid PID format! Please provide a PID number!");
        return 1;
    } 
    if (processToClonePid <= 0) {
        printf("\t [!] PID must be a positive number!");
        return 1;
    }

    // Find Process
    if (FindProcess(processToClonePid) == 0) {
        printf("\t [!] Target Process with PID %u Not Found!\n", processToClonePid);
        return 1;
    }
    printf("[+] Process with PID %u found!\n", processToClonePid);
    printf("\n");

    // Load NtOpenProcess function
    printf("[i] Loading NtOpenProcess function...\n");
    if (!LoadNtOpenProcess()) {
        printf("\t[!] Failed to load NtOpenProcess function!\n");
        return 1;
    }

    // Checking token privileges
    wprintf(L"[i] Checking token privileges...\n");
    if (!EnablePrivilege())
    {
        wprintf(L"\t[!] EnablePrivilege Failed!!!\n");
        return 1;
    }
    wprintf(L"[i] Privilege operation completed\n");


    NtStatus = OpenProcessByPID(processToClonePid, &hParentProcess);
    if (hParentProcess == NULL || NtStatus != STATUS_SUCCESS) {
        printf("\t [!] Failed to open target process! NTSTATUS: 0x%08X\n", NtStatus);
        return 1;
    }
    printf("[i] Target process opened; handle: 0x%p\n", hParentProcess);

    return 0;
}