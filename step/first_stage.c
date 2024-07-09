#include <windows.h>
#include <stdio.h>

#define NEW_SECTION_NAME ".packed"
#define NEW_SECTION_SIZE 0x1000  // 4KB for the new section

int add_section(const char* filename) {
    HANDLE hFile = CreateFile(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Could not open file.\n");
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, fileSize + NEW_SECTION_SIZE, NULL);
    if (hMapping == NULL) {
        printf("Could not create file mapping.\n");
        CloseHandle(hFile);
        return 1;
    }

    BYTE* fileData = (BYTE*)MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
    if (fileData == NULL) {
        printf("Could not map view of file.\n");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileData + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid PE file.\n");
        UnmapViewOfFile(fileData);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER newSectionHeader = &sectionHeader[numberOfSections];

    // Set new section name
    strncpy((char*)newSectionHeader->Name, NEW_SECTION_NAME, IMAGE_SIZEOF_SHORT_NAME);

    // Calculate new section attributes
    DWORD newSectionVirtualAddress = sectionHeader[numberOfSections - 1].VirtualAddress + sectionHeader[numberOfSections - 1].Misc.VirtualSize;
    newSectionVirtualAddress = (newSectionVirtualAddress + 0xFFF) & ~0xFFF;  // Align to 4KB
    DWORD newSectionPointerToRawData = sectionHeader[numberOfSections - 1].PointerToRawData + sectionHeader[numberOfSections - 1].SizeOfRawData;

    // Fill new section header
    newSectionHeader->Misc.VirtualSize = NEW_SECTION_SIZE;
    newSectionHeader->VirtualAddress = newSectionVirtualAddress;
    newSectionHeader->SizeOfRawData = NEW_SECTION_SIZE;
    newSectionHeader->PointerToRawData = newSectionPointerToRawData;
    newSectionHeader->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    // Update NT headers
    ntHeaders->FileHeader.NumberOfSections += 1;
    ntHeaders->OptionalHeader.SizeOfImage = newSectionVirtualAddress + NEW_SECTION_SIZE;

    // Unmap and close handles
    UnmapViewOfFile(fileData);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pe_file>\n", argv[0]);
        return 1;
    }

    if (add_section(argv[1]) == 0) {
        printf("Section added successfully.\n");
    } else {
        printf("Failed to add section.\n");
    }

    return 0;
}
