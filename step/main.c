#include <stdio.h>
#include "libproc.h"

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

/*int is_pe_file(LPCTSTR filename, PVOID dll) {
    //PVOID dll = get_dll(kernel32_str);
    PVOID create_file_a = get_func("CreateFileA", dll);
    HANDLE hFile = ((create_file_a_def)create_file_a)(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    //HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
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


void list_pe_files() {
    
    PVOID dll = get_dll(kernel32_str);
    PVOID find_first_file = get_func("FindFirstFile", dll);
    //printf("aaa");
    char temp_buffer[64];
    //...
    sprintf(temp_buffer, "%p", (void *) &find_first_file);

    /*PVOID loadlib = get_func(loadlibrary_str, dll);
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
                /*PVOID dll = get_dll(kernel32_str);
                PVOID loadlib = get_func(loadlibrary_str, dll);
                HMODULE hM = ((loadlib_call)loadlib)(user32_str);
                PVOID msgbox = get_func(msgbox_str, hM);
                ((msgbox_call)msgbox)(NULL, msgbox_body_str, msgbox_caption_str, 0);
                printf("PE File: %s\n", findFileData.cFileName);
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
}*/

/*int is_pe_file(LPCTSTR filename) {
    HANDLE hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }

    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return 0;
    }

    LPVOID lpMapAdr = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!lpMapAdr) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpMapAdr;

    // Check if the file has the 'MZ' magic number
    if (pDosHeader->e_magic != 0x5A4D) {
        UnmapViewOfFile(lpMapAdr);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }

    // Check if it has a valid PE signature
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpMapAdr + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != 0x00004550) { // 'PE\0\0'
        UnmapViewOfFile(lpMapAdr);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }

    // Clean up
    UnmapViewOfFile(lpMapAdr);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return 1;
}

void list_pe_files_in_current_directory() {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile("*", &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        printf("FindFirstFile failed (%d)\n", GetLastError());
        return;
    } 

    do {
        if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            if (is_pe_file(findFileData.cFileName)) {
                printf("PE File: %s\n", findFileData.cFileName);
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
}*/


int main()
{
    //list_dll();
    //list_pe_files_in_current_directory();
    
    //list_pe_files_and_inject();
    PVOID dll = get_dll(L"C:\\Windows\\System32\\KERNEL32.DLL");
    //list_pe_and(dll);
    /*LOG("KERNEL32 at %p\n", dll);
    //list_func(dll);
    PVOID loadlib = get_func("LoadLibraryA", dll);
    LOG("loadlib at %p\n", loadlib);
    HMODULE hM = ((loadlib_call)loadlib)("user32.dll");
    LOG("hmod at %p\n", hM);
    LOG("what %s\n", (PCHAR)hM);
    PVOID msgbox = get_func("MessageBoxA", hM);
    LOG("msgbox at %p\n", msgbox);
    ((msgbox_call)msgbox)(NULL, "Yeah! Hacked!!!", "HackBox", 0);*/

    return 0;
}
