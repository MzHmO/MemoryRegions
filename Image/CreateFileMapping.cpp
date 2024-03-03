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