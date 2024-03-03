#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <psapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shlwapi.lib")

typedef NTSTATUS(NTAPI* fNtGetNextProcess)(
    _In_ HANDLE ph,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Flags,
    _Out_ PHANDLE Newph
    );

int listModulesOfProcess(int pid) {
    HANDLE ph;
    MEMORY_BASIC_INFORMATION mbi;
    char* base = NULL;

    ph = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (ph == NULL)
        return -1;

    printf("modules found:\n");
    printf("name\t\t\t base address\n");
    printf("=================================================================================\n");

    while (VirtualQueryEx(ph, base, &mbi, sizeof(mbi)) == sizeof(MEMORY_BASIC_INFORMATION)) {
        char szModName[MAX_PATH];

        if ((mbi.AllocationBase == mbi.BaseAddress) && (mbi.AllocationBase != NULL)) {
            if (GetModuleFileNameExA(ph, (HMODULE)mbi.AllocationBase, (LPSTR)szModName, sizeof(szModName) / sizeof(TCHAR)))
                printf("%#25s\t\t%#10llx\n", szModName, (unsigned long long)mbi.AllocationBase);
        }
        base += mbi.RegionSize;
    }

    CloseHandle(ph);
    return 0;
}

int main(int argc, char* argv[]) {
    int pid = atoi(argv[1]);
    printf("%s%d\n", pid > 0 ? "process found at pid = " : "process not found. pid = ", pid);
    if (pid != 0)
        listModulesOfProcess(pid);
    return 0;
}