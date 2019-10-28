#include "windows.h"
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>

BOOL HookIAT(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew);
BOOL WINAPI HookedReadFile(
    HANDLE hFile,       //文件的句柄
     LPVOID lpBuffer,    //用于保存读入数据的一个缓冲区
     DWORD nNumberOfBytesToRead,     //要读入的字节数
     LPDWORD lpNumberOfBytesRead,   //指向实际读取字节数的指针
     LPOVERLAPPED lpOverlapped
);
BOOL WINAPI HookedWriteFile(
HANDLE  hFile,//文件句柄
LPCVOID lpBuffer,//数据缓存区指针
DWORD   nNumberOfBytesToWrite,//要写的字节数
LPDWORD lpNumberOfBytesWritten,//用于保存实际写入字节数的存储区域的指针
LPOVERLAPPED lpOverlapped//OVERLAPPED结构体指针
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
    HANDLE hFile,       //文件的句柄
    LPVOID lpBuffer,    //用于保存读入数据的一个缓冲区
    DWORD nNumberOfBytesToRead,     //要读入的字节数
    LPDWORD lpNumberOfBytesRead,   //指向实际读取字节数的指针
    LPOVERLAPPED lpOverlapped
){
    int status = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    HANDLE hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS,NULL,"myhack");
    if(hMapFile){
        LPVOID lpBase = MapViewOfFile(hMapFile,FILE_MAP_ALL_ACCESS,0,0,0);
        char szBuffer[BUF_SIZE] = "ReadFile:    ";
        strncat(szBuffer, (char*)lpBuffer, (*lpNumberOfBytesRead));
        strcat(szBuffer, "\n");
        //写入数据
        strcpy((char*)lpBase,szBuffer);
        // 解除文件映射
        UnmapViewOfFile(lpBase);
        // 关闭内存映射文件对象句柄
        CloseHandle(hMapFile);
    }
    return status;
}

BOOL WINAPI HookedWriteFile(
    HANDLE  hFile,//文件句柄
    LPCVOID lpBuffer,//数据缓存区指针
    DWORD   nNumberOfBytesToWrite,//要写的字节数
    LPDWORD lpNumberOfBytesWritten,//用于保存实际写入字节数的存储区域的指针
    LPOVERLAPPED lpOverlapped//OVERLAPPED结构体指针
) {
    HANDLE hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS,NULL,"myhack");
    if(hMapFile){
        LPVOID lpBase = MapViewOfFile(hMapFile,FILE_MAP_ALL_ACCESS,0,0,0);
        char szBuffer[BUF_SIZE] = "WriteFile:   ";
        strncat(szBuffer, (char*)lpBuffer, nNumberOfBytesToWrite);
        strcat(szBuffer, "\n");
        //写入数据
        strcpy((char*)lpBase,szBuffer);
        // 解除文件映射
        UnmapViewOfFile(lpBase);
        // 关闭内存映射文件对象句柄
        CloseHandle(hMapFile);
    }
    return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}


//   负责iat的勾取
BOOL HookIAT(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew)
{
    HMODULE hMod;
    LPCSTR szLibName;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_THUNK_DATA pThunk;
    DWORD dwOldProtect, dwRVA;
    PBYTE pAddr;
    //*首先进行PE文件头信息的读取*/
    // hMod, pAddr = ImageBase of notepad.exe
    //             = VA to MZ signature (IMAGE_DOS_HEADER)
    hMod = GetModuleHandle(NULL);
    pAddr = (PBYTE)hMod;
    // pAddr = VA to PE signature (IMAGE_NT_HEADERS)
    pAddr += *((DWORD*)&pAddr[0x3C]);

    // dwRVA = RVA to IMAGE_IMPORT_DESCRIPTOR Table
    dwRVA = *((DWORD*)&pAddr[0x80]);

    // pImportDesc = VA to IMAGE_IMPORT_DESCRIPTOR Table 如果想要找到IAT首先要找到导入表对应的位置
    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod+dwRVA);
    /*通过循环来比较找到kernel32.dll中的导入表结构*/

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
                    // 更改内存属性为E/R/W
                    //由于计算器原有IAT内存区域是只可读的
                    //所以勾取之前通过VirtualProtect函数将相应的IAT的内存区域更改为可读写模式
                    bool a = VirtualProtect((LPVOID)&pThunk->u1.Function,   // 目标地址起始位置
                                   4,                              // 大小
                                   PAGE_EXECUTE_READWRITE,         // 请求的保护方式 区域包含可执行代码，应用程序可以读写该区域。
                                   &dwOldProtect);                 // 保存老的保护方式

                    //修改IAT值（勾取）把原有指向user32.dll/Setwindowtext的值指向我们自己的函数MySetWindowTextW
                    pThunk->u1.Function = (DWORD)pfnNew;
                    // 恢复内存属性
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
