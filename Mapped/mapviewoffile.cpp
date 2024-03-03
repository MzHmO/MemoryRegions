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