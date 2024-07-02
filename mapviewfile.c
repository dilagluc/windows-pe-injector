#include <windows.h>
#include <stdio.h>
#include <string.h>

void my_memcpy(char *dst, char *src, size_t len)
{
    size_t i = 0;
    while (i < len)
    {
        dst[i] = src[i];
        i += 1;
    }
}

int main(void)
{
    char *thefile = "test.txt";
    char *to_add = "\n<Some content.>\n";
    //int nb_add = 17;
    int nb_add = strlen(to_add);
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
    my_memcpy((char*)lpMapAdr + dwFileSize, to_add, nb_add);
#if DEBUG
    printf("CONTENT:\n%s", (char*)lpMapAdr);
#endif
}
