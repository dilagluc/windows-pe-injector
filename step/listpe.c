#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "user32.lib")


int main(int ac, char **av)
{
    if (ac != 2)
    {
        printf("Usage: %s EXEFILE\n", av[0]);
        return 2600;
    }
    char *thefile = av[1];
    DWORD nb_add = 0;
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
    DWORD dwNewFileSize = dwFileSize + nb_add;
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
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)lpMapAdr + pDosHeader->e_lfanew);
    //printf("NT SIG %c%c\n", ((char*)&pNtHeader->Signature)[0], ((char*)&pNtHeader->Signature)[1]);
    char *sig = (char*)&pNtHeader->Signature;
    printf("NT SIG %s\n", sig);
    printf("NT Machine %02X\n", pNtHeader->FileHeader.Machine);

    // Optional Header
    printf("Optional SizeOfCode %08X\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("Optional AOEP %08X\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
    printf("Optional ImageBase %016X\n", pNtHeader->OptionalHeader.ImageBase);

    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((PUCHAR)pNtHeader + sizeof (IMAGE_NT_HEADERS64));

    for (WORD idxSection = 0; idxSection < pNtHeader->FileHeader.NumberOfSections; idxSection += 1)
    {
        printf("Section Name: %s\n", pSection[idxSection].Name);
        printf("Virtual Adr: %08X\n", pSection[idxSection].VirtualAddress);
        printf("Virtual Size: %d\n", pSection[idxSection].Misc.VirtualSize);
        printf("PointerRawData Adr: %08X\n", pSection[idxSection].PointerToRawData);
        printf("Size Of Raw Data: %d\n", pSection[idxSection].SizeOfRawData);
        int is_exec = (pSection[idxSection].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        printf("is exec %d\n", is_exec);
    }

}
