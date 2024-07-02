#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "libproc.h"

#ifdef DEBUG
void    list_dll()
{
    PTEB pTeb = NtCurrentTeb();
    PPEB pPeb = pTeb->ProcessEnvironmentBlock;

    LOG("Teb %p\n", pTeb);
    LOG("Peb %p\n", pPeb);
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    LOG("LDR %p\n", pLdr);
    PLIST_ENTRY pList = &pLdr->InMemoryOrderModuleList;
    for (PLIST_ENTRY pNode = pList->Flink; pNode != pList; pNode = pNode->Flink)
    {
        LOG("node %p\n", pNode);
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pNode, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        LOG("entry %ls\n", pEntry->FullDllName.Buffer);
        LOG("base %p\n", pEntry->DllBase);
    }
}

void    list_func(PVOID dllBase)
{
    PIMAGE_DOS_HEADER   pDosHeader = (PIMAGE_DOS_HEADER)dllBase;
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)dllBase + pDosHeader->e_lfanew);
    LOG("NtHead %p\n", pNtHeader);
    PIMAGE_DATA_DIRECTORY pDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    LOG("pDir %p\n", pDir);
    LOG("pVirt %x\n", pDir->VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)dllBase + pDir->VirtualAddress);
    LOG("pExp %p\n", pExp);
    PDWORD rvaNames = (PDWORD)((PUCHAR)dllBase + pExp->AddressOfNames);
    PWORD aryOrds = (PWORD)((PUCHAR)dllBase + pExp->AddressOfNameOrdinals);
    PDWORD rvaFuncs = (PDWORD)((PUCHAR)dllBase + pExp->AddressOfFunctions);
    for (int i = 0; i < pExp->NumberOfFunctions; i += 1)
    {
        LOG("rvaName %d\n", rvaNames[i]);
        LOG("Name %s\n", (PCHAR)((PCHAR)dllBase + rvaNames[i]));
        WORD ord = aryOrds[i];
        LOG("ord %d\n", ord);
        PVOID pFunc = (PVOID)((PUCHAR)dllBase + rvaFuncs[ord]);
        LOG("pFunc %p\n", pFunc);
    }
}

#endif

__declspec(code_seg("injected"))
int my_wstrcmp(PWSTR src1, PWSTR src2)
{
    for (int i = 0; src1[i]; i += 1)
        if (src1[i] != src2[i])
            return src1[i] - src2[i];
    return 0;
}

__declspec(code_seg("injected"))
int my_strcmp(PCHAR src1, PCHAR src2)
{
    for (int i = 0; src1[i]; i += 1)
        if (src1[i] != src2[i])
            return src1[i] - src2[i];
    return 0;
}

__declspec(code_seg("injected"))
PVOID    get_dll(PWSTR name)
{
    PTEB pTeb = NtCurrentTeb();
    PPEB pPeb = pTeb->ProcessEnvironmentBlock;

    LOG("Teb %p\n", pTeb);
    LOG("Peb %p\n", pPeb);
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    LOG("LDR %p\n", pLdr);
    PLIST_ENTRY pList = &pLdr->InMemoryOrderModuleList;
    for (PLIST_ENTRY pNode = pList->Flink; pNode != pList; pNode = pNode->Flink)
    {
        LOG("node %p\n", pNode);
        PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY) (pNode - 1);
        LOG("entry %ls\n", pEntry->FullDllName.Buffer);
        LOG("base %p\n", pEntry->DllBase);
        if (!my_wstrcmp(name, pEntry->FullDllName.Buffer))
            return pEntry->DllBase;
    }
    return NULL;
}

__declspec(code_seg("injected"))
PVOID    get_func(PCHAR name, PVOID dllBase)
{
    PIMAGE_DOS_HEADER   pDosHeader = (PIMAGE_DOS_HEADER)dllBase;
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)dllBase + pDosHeader->e_lfanew);
    LOG("NtHead %p\n", pNtHeader);
    PIMAGE_DATA_DIRECTORY pDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    LOG("pDir %p\n", pDir);
    LOG("pVirt %x\n", pDir->VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)dllBase + pDir->VirtualAddress);
    LOG("pExp %p\n", pExp);
    PDWORD rvaNames = (PDWORD)((PUCHAR)dllBase + pExp->AddressOfNames);
    PWORD aryOrds = (PWORD)((PUCHAR)dllBase + pExp->AddressOfNameOrdinals);
    PDWORD rvaFuncs = (PDWORD)((PUCHAR)dllBase + pExp->AddressOfFunctions);
    for (int i = 0; i < pExp->NumberOfFunctions; i += 1)
    {
        LOG("rvaName %d\n", rvaNames[i]);
        PCHAR pName = (PCHAR)((PCHAR)dllBase + rvaNames[i]);
        LOG("Name %s\n", pName);
        if (!my_strcmp(name, pName))
        {
            WORD ord = aryOrds[i];
            LOG("ord %d\n", ord);
            PVOID pFunc = (PVOID)((PUCHAR)dllBase + rvaFuncs[ord]);
            LOG("pFunc %p\n", pFunc);
            return pFunc;
        }
    }
    return NULL;
}

typedef HMODULE (*loadlib_call)(LPCSTR);

typedef int (*msgbox_call)(
  HWND   hWnd,
  LPCSTR lpText,
  LPCSTR lpCaption,
  UINT   uType
);

__declspec(allocate("injected"))
short kernel32_str[] = L"C:\\Windows\\System32\\KERNEL32.DLL";

__declspec(allocate("injected"))
char loadlibrary_str[] = "LoadLibraryA";

__declspec(allocate("injected"))
char user32_str[] = "user32.dll";

__declspec(allocate("injected"))
char msgbox_str[] = "MessageBoxA";

__declspec(allocate("injected"))
char msgbox_body_str[] = "Yeah! Hacked!!!";

__declspec(allocate("injected"))
char msgbox_caption_str[] = "HackBox";

__declspec(code_seg("injected"))
void       inj_code_c() {
    PVOID dll = get_dll(kernel32_str);
    PVOID loadlib = get_func(loadlibrary_str, dll);
    HMODULE hM = ((loadlib_call)loadlib)(user32_str);
    PVOID msgbox = get_func(msgbox_str, hM);
    ((msgbox_call)msgbox)(NULL, msgbox_body_str, msgbox_caption_str, 0);
}
