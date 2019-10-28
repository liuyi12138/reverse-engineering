#include "windows.h"
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>

BOOL HookIAT(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew);
BOOL WINAPI HookedReadFile(
    HANDLE hFile,       //�ļ��ľ��
     LPVOID lpBuffer,    //���ڱ���������ݵ�һ��������
     DWORD nNumberOfBytesToRead,     //Ҫ������ֽ���
     LPDWORD lpNumberOfBytesRead,   //ָ��ʵ�ʶ�ȡ�ֽ�����ָ��
     LPOVERLAPPED lpOverlapped
);
BOOL WINAPI HookedWriteFile(
HANDLE  hFile,//�ļ����
LPCVOID lpBuffer,//���ݻ�����ָ��
DWORD   nNumberOfBytesToWrite,//Ҫд���ֽ���
LPDWORD lpNumberOfBytesWritten,//���ڱ���ʵ��д���ֽ����Ĵ洢�����ָ��
LPOVERLAPPED lpOverlapped//OVERLAPPED�ṹ��ָ��
);

typedef BOOL (WINAPI *PFSETWINDOWTEXTW)(HWND hWnd, LPWSTR lpString);
#define BUF_SIZE 4096

LPVOID g_readProc = NULL;
LPVOID g_writeProc = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch( fdwReason )
    {
    case DLL_PROCESS_ATTACH :

        g_readProc = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadFile");
        g_writeProc = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");
        if (g_readProc) {
            HookIAT("kernel32.dll", (PROC)g_readProc, (PROC)HookedReadFile);
            HookIAT("kernel32.dll", (PROC)g_writeProc, (PROC)HookedWriteFile);
        }
        break;
    case DLL_PROCESS_DETACH:
        //HookIAT("kernel32.dll", (PROC)HookedReadFile, (PROC)g_readProc);
        //HookIAT("kernel32.dll", (PROC)HookedWriteFile, g_writeProc);
    break;
    }

    return TRUE;
}

BOOL WINAPI HookedReadFile(
    HANDLE hFile,       //�ļ��ľ��
    LPVOID lpBuffer,    //���ڱ���������ݵ�һ��������
    DWORD nNumberOfBytesToRead,     //Ҫ������ֽ���
    LPDWORD lpNumberOfBytesRead,   //ָ��ʵ�ʶ�ȡ�ֽ�����ָ��
    LPOVERLAPPED lpOverlapped
){
    int status = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    HANDLE hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS,NULL,"myhack");
    if(hMapFile){
        LPVOID lpBase = MapViewOfFile(hMapFile,FILE_MAP_ALL_ACCESS,0,0,0);
        char szBuffer[BUF_SIZE] = "ReadFile:    ";
        strncat(szBuffer, (char*)lpBuffer, (*lpNumberOfBytesRead));
        strcat(szBuffer, "\n");
        //д������
        strcpy((char*)lpBase,szBuffer);
        // ����ļ�ӳ��
        UnmapViewOfFile(lpBase);
        // �ر��ڴ�ӳ���ļ�������
        CloseHandle(hMapFile);
    }
    return status;
}

BOOL WINAPI HookedWriteFile(
    HANDLE  hFile,//�ļ����
    LPCVOID lpBuffer,//���ݻ�����ָ��
    DWORD   nNumberOfBytesToWrite,//Ҫд���ֽ���
    LPDWORD lpNumberOfBytesWritten,//���ڱ���ʵ��д���ֽ����Ĵ洢�����ָ��
    LPOVERLAPPED lpOverlapped//OVERLAPPED�ṹ��ָ��
) {
    HANDLE hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS,NULL,"myhack");
    if(hMapFile){
        LPVOID lpBase = MapViewOfFile(hMapFile,FILE_MAP_ALL_ACCESS,0,0,0);
        char szBuffer[BUF_SIZE] = "WriteFile:   ";
        strncat(szBuffer, (char*)lpBuffer, nNumberOfBytesToWrite);
        strcat(szBuffer, "\n");
        //д������
        strcpy((char*)lpBase,szBuffer);
        // ����ļ�ӳ��
        UnmapViewOfFile(lpBase);
        // �ر��ڴ�ӳ���ļ�������
        CloseHandle(hMapFile);
    }
    return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}


//   ����iat�Ĺ�ȡ
BOOL HookIAT(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew)
{
    HMODULE hMod;
    LPCSTR szLibName;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_THUNK_DATA pThunk;
    DWORD dwOldProtect, dwRVA;
    PBYTE pAddr;
    //*���Ƚ���PE�ļ�ͷ��Ϣ�Ķ�ȡ*/
    // hMod, pAddr = ImageBase of notepad.exe
    //             = VA to MZ signature (IMAGE_DOS_HEADER)
    hMod = GetModuleHandle(NULL);
    pAddr = (PBYTE)hMod;
    // pAddr = VA to PE signature (IMAGE_NT_HEADERS)
    pAddr += *((DWORD*)&pAddr[0x3C]);

    // dwRVA = RVA to IMAGE_IMPORT_DESCRIPTOR Table
    dwRVA = *((DWORD*)&pAddr[0x80]);

    // pImportDesc = VA to IMAGE_IMPORT_DESCRIPTOR Table �����Ҫ�ҵ�IAT����Ҫ�ҵ�������Ӧ��λ��
    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod+dwRVA);
    /*ͨ��ѭ�����Ƚ��ҵ�kernel32.dll�еĵ����ṹ*/

    for( ; pImportDesc->Name; pImportDesc++ )
    {
        // szLibName = VA to IMAGE_IMPORT_DESCRIPTOR.Name
        szLibName = (LPCSTR)((DWORD)hMod + pImportDesc->Name);
        if( !_stricmp(szLibName, szDllName) )
        {
            // pThunk = IMAGE_IMPORT_DESCRIPTOR.FirstThunk
            //        = VA to IAT(Import Address Table)
            pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod +
                                         pImportDesc->FirstThunk);

            // pThunk->u1.Function = VA to API
            for( ; pThunk->u1.Function; pThunk++ )
            {
                if( pThunk->u1.Function == (DWORD)pfnOrg )
                {
                    // �����ڴ�����ΪE/R/W
                    //���ڼ�����ԭ��IAT�ڴ�������ֻ�ɶ���
                    //���Թ�ȡ֮ǰͨ��VirtualProtect��������Ӧ��IAT���ڴ��������Ϊ�ɶ�дģʽ
                    bool a = VirtualProtect((LPVOID)&pThunk->u1.Function,   // Ŀ���ַ��ʼλ��
                                   4,                              // ��С
                                   PAGE_EXECUTE_READWRITE,         // ����ı�����ʽ ���������ִ�д��룬Ӧ�ó�����Զ�д������
                                   &dwOldProtect);                 // �����ϵı�����ʽ

                    //�޸�IATֵ����ȡ����ԭ��ָ��user32.dll/Setwindowtext��ֵָ�������Լ��ĺ���MySetWindowTextW
                    pThunk->u1.Function = (DWORD)pfnNew;
                    // �ָ��ڴ�����
                    VirtualProtect((LPVOID)&pThunk->u1.Function,
                                   4,
                                   dwOldProtect,
                                   &dwOldProtect);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}
