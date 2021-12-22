#define _CRT_SECURE_NO_WARNINGS
#include "windows.h"
#include "tchar.h"
#include "string.h"
#include <stdio.h>
#include <atlbase.h>
#include <TlHelp32.h>

DWORD PID = 0;
uintptr_t address = NULL;

class FileHandler
{
    private:
        FILE *file;

    public:
        FileHandler(const char *fileName, const char *flag) 
        {
            file = fopen(fileName, flag);
        }

        ~FileHandler() 
        {
            fclose(file);
        }

        FILE* GetFilePtr() 
        { 
            return file; 
        };
};


typedef DWORD64 *LPDWORD64;
HMODULE g_hMod = NULL;
HANDLE hFileDmp = 0;
HANDLE hFileJson = 0;
char NewSha256[64];
int HandleCounter = 0;


typedef BOOL(WINAPI *pfnDeviceIoControl)
(
    _In_ HANDLE hDevice,
    _In_ DWORD dwIoControlCode,
    _In_opt_ LPVOID lpInBuffer,
    _In_ DWORD nInBufferSize,
    _Out_opt_ LPVOID lpOutBuffer,
    _In_ DWORD nOutBufferSize,
    _Out_opt_ LPDWORD lpBytesReturned,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
);

BOOL WINAPI MyDeviceIoControl
(
    _In_ HANDLE hDevice,
    _In_ DWORD dwIoControlCode,
    _In_opt_ LPVOID lpInBuffer,
    _In_ DWORD nInBufferSize,
    _Out_opt_ LPVOID lpOutBuffer,
    _In_ DWORD nOutBufferSize,
    _Out_opt_ LPDWORD lpBytesReturned,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
);

//to get offset addr_pfnDeviceIoControl - pfnDeviceIoControl
LPBYTE addr_pfnDeviceIoControl = NULL;
BYTE DeviceIoControlBuf[5] = { 0, };
// e9 + (점프도착 - 점프시작-5)

void DeviceIoControlHook()
{
    BYTE DeviceIoControlBuf[5] = { 0xe9, };
    // Get Offset by calculate Address( e9 + JMP <destination> -JMP <start> - 5)
    *(LPDWORD)(DeviceIoControlBuf + 1) = (DWORD)((LPBYTE)
    MyDeviceIoControl - addr_pfnDeviceIoControl - 5);

    //page ReadWrite authority change temporary
    DWORD OldProtect, OldProtect2;
    VirtualProtect(addr_pfnDeviceIoControl, 5, PAGE_READWRITE, &OldProtect);

    //change Address which jump to myWriteFile
    memcpy(addr_pfnDeviceIoControl, DeviceIoControlBuf, 5);

    //change original authority
    VirtualProtect(addr_pfnDeviceIoControl, 5, OldProtect, &OldProtect2);
    return;
}

void DeviceIoControlUnHook()
{
    DWORD OldProtect, OldProtect2;
    VirtualProtect(addr_pfnDeviceIoControl, 5, PAGE_READWRITE, &OldProtect);
    memcpy(addr_pfnDeviceIoControl, DeviceIoControlBuf, 5);
    VirtualProtect(addr_pfnDeviceIoControl, 5, OldProtect, &OldProtect2);
    return;
}

BOOL WINAPI MyDeviceIoControl
(
    _In_ HANDLE hDevice,
    _In_ DWORD dwIoControlCode,
    _In_opt_ LPVOID lpInBuffer,
    _In_ DWORD nInBufferSize,
    _Out_opt_ LPVOID lpOutBuffer,
    _In_ DWORD nOutBufferSize,
    _Out_opt_ LPDWORD lpBytesReturned,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
)

{
    DeviceIoControlUnHook();
    OutputDebugString(_T("(MyDeviceIoControl) : "));
    BOOL ret = DeviceIoControl
    (
        hDevice,
        dwIoControlCode,
        lpInBuffer,
        nInBufferSize,
        lpOutBuffer,
        nOutBufferSize,
        lpBytesReturned,
        lpOverlapped
    );

    DeviceIoControlHook();
    //Control code to move driver //second time It work!
    if (dwIoControlCode == 0x22C002)
    {
        LPCWSTR lpFileName = (LPWSTR)((char*)
        lpOutBuffer + 124); // .dmp file name
        OutputDebugString(_T("(Program Name) : "));
        OutputDebugStringW(lpFileName);
        HANDLE hFile = CreateFile(lpFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile == INVALID_HANDLE_VALUE)
        {
            OutputDebugString(_T("Could not open File!\n"));
        }

        else
            OutputDebugString(_T("Success open File!\n"));

        HANDLE hMapFile = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL); // data on memory

        if (hMapFile == NULL)
        {
            OutputDebugString(_T("\nCould not create map of file \n"));
        }

        DWORD fileHighSize = 0;
        DWORD fileLowSize = GetFileSize(hFile, &fileHighSize);

        _int64 fileSize = fileHighSize;
        fileSize <<= 32; // filesize Set 0x1[][][][] + 0xffff = 0x1ffff
        fileSize |= fileLowSize;
        PBYTE pbFile = (PBYTE)MapViewOfFile(hMapFile, (DWORD)FILE_MAP_ALL_ACCESS, 0, 0, 0);
        int error = GetLastError();
        _tprintf(_T("GetLastError : %d \n"), error);

        if (pbFile == NULL)
        {
            OutputDebugString(_T("Could not map view of file \n"));
        }

        _tprintf(_T("\nBaseAddress: 0x%p\n"), address);
        _tprintf(_T("pbfile : %p, HighSize: %x, LowSize: %x \n"), &pbFile, fileHighSize, fileLowSize);

        PBYTE Mystring[1024] = { 0, };
        PBYTE Mystring2[1024] = { 0, };
        memset(&Mystring, 'A', sizeof(Mystring));
        memcpy(&(pbFile[1024]), Mystring, sizeof(Mystring));
        UnmapViewOfFile(pbFile);
        CloseHandle(hMapFile);
        CloseHandle(hFile);
    }

    return ret;
}

uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
{
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    printf("1. Get Last Error : %d\n", GetLastError());

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        printf("2. Get Last Error : %d\n", GetLastError());
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                printf("3. Get Last Error : %d\n", GetLastError());
                if (!_wcsicmp(modEntry.szModule, modName))
                {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    printf("5. Get Last Error : %d\n", GetLastError());
                    break;
                }

            } while (Module32Next(hSnap, &modEntry));
        }
    }

    CloseHandle(hSnap);

    return modBaseAddr;
}


DWORD FindProcessID(LPCTSTR szProcessName)
{
    DWORD dwPID = 0xFFFFFFFF;
    HANDLE hSnapShot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 pe;

    //GET the snapshot of the system
    pe.dwSize = sizeof(PROCESSENTRY32);
    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

    //find process
    Process32First(hSnapShot, &pe);
    do
    {
        //printf("process Name: %S\n", pe.szExeFile);
        if (!lstrcmp(szProcessName, pe.szExeFile))
        {
            dwPID = pe.th32ProcessID;
            break;
        }

    } while (Process32Next(hSnapShot, &pe));

    CloseHandle(hSnapShot);

    return dwPID;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    HANDLE hThread = NULL;
    g_hMod = (HMODULE)hinstDLL;
    SIZE_T nRread = 0;
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            OutputDebugString(L"Injection Success!!!");
            PID = FindProcessID(L"DumpIt.exe");
            address = GetModuleBaseAddress(PID, L"DumpIt.exe");
            addr_pfnDeviceIoControl = (LPBYTE)GetProcAddress
            (GetModuleHandle(L"kernel32.dll"), "DeviceIoControl");
            memcpy(DeviceIoControlBuf, addr_pfnDeviceIoControl, 5);
            DeviceIoControlHook();
            break;

        case DLL_PROCESS_DETACH:
            DeviceIoControlUnHook();
            break;
    }

    return TRUE;
}