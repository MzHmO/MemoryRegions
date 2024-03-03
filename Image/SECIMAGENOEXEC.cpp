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