#include <windows.h>
#include <stdio.h>
#include <Tlhelp32.h>

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnable);
BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath);
DWORD ProcessNameToPID(char* Name);
#define BUF_SIZE 4096

int main(int argc, char* argv[])
{
    if(argc != 3){
        printf("input error, Usage: %s <pid> <dll_path>", argv[0]);
        return 1;
    }
    DWORD pid = ProcessNameToPID(argv[1]);
    printf("PID: %d\n", pid);

    //change privilege
    if(!SetPrivilege(SE_DEBUG_NAME, true))
        return 1;

    char szBuffer[BUF_SIZE] = {0};
    char szBufferLast[BUF_SIZE] = {0};
    //inject dll
    while(1){
        pid = ProcessNameToPID(argv[1]);
        if(pid != 0 && InjectDll((DWORD)pid, (LPCTSTR)argv[2])){
            printf("InjectDll(\"%s\") success!!!\n", argv[2]);
            // 定义共享数据

            // 创建共享文件句柄
            HANDLE hMapFile = CreateFileMapping(
                INVALID_HANDLE_VALUE,   // 物理文件句柄
                NULL,   // 默认安全级别
                PAGE_READWRITE,   // 可读可写
                0,   // 高位文件大小
                BUF_SIZE,   // 地位文件大小
                "myhack"   // 共享内存名称
                );

            // 映射缓存区视图 , 得到指向共享内存的指针
            LPVOID lpBase = MapViewOfFile(
                hMapFile,            // 共享内存的句柄
                FILE_MAP_ALL_ACCESS, // 可读写许可
                0,
                0,
                BUF_SIZE
                );

            while(1){
                //缓存上一次的数据
                strcpy(szBufferLast,szBuffer);
                // 将共享内存数据拷贝出来
                strcpy(szBuffer,(char*)lpBase);
                if(strcmp(szBuffer, szBufferLast)){
                    printf("%s",szBuffer);
                }
                Sleep(200);
            }
        }
        else{
            printf("Waiting for (\"%s\")\n", argv[1]);
        }
        Sleep(200);
    }

    return 0;
}

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath){
    HANDLE hProcess = NULL, hThread = NULL;
    HMODULE hMod = NULL;
    LPVOID pRemoteBuf = NULL;
    DWORD dwBufSize = (DWORD)(strlen(szDllPath) + 1) * sizeof(char);
    LPTHREAD_START_ROUTINE pThreadProc;

    //获取目标进程句柄，获取PROCESS_ALL_ACCESS权限
    if(!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) )
    {
        //printf("OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
        return FALSE;
    }

    //将注入的DLL路径写入目标进程内存
    //在指定进程的虚拟空间保留或提交内存区域
    pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

    WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);

    hMod = GetModuleHandle("kernel32.dll");

    pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");

    //创建远程线程
    hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}


BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnable) {
    OutputDebugString(lpszPrivilege);
    BOOL bRet = FALSE;
    HANDLE hToken = NULL;
    HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, ::GetCurrentProcessId());
    if (!::OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        goto __EXIT;
    }
    LUID Luid;
    if (!::LookupPrivilegeValue(NULL, lpszPrivilege, &Luid))
    {
        goto __EXIT;
    }
    TOKEN_PRIVILEGES newPrivilege;
    newPrivilege.PrivilegeCount = 1;
    newPrivilege.Privileges[0].Luid = Luid;
    newPrivilege.Privileges[0].Attributes = //设置特权属性
               bEnable ?
               SE_PRIVILEGE_ENABLED :
               SE_PRIVILEGE_ENABLED_BY_DEFAULT;
    if (!::AdjustTokenPrivileges(hToken, FALSE, &newPrivilege,
        sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        TCHAR s[64] = { 0 };
        //printf("AdjustTokenPrivileges error: %d\n",GetLastError());
        OutputDebugString(s);
        goto __EXIT;
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)//查看是否真的设置成功了
    {
        printf("The token does not have the specified privilege. \n");
        goto __EXIT;
    }
    bRet = TRUE;
    printf("Set OK\n");
__EXIT:
    if (hProcess)
    {
        ::CloseHandle(hProcess);
    }
    if (hToken)
    {
        ::CloseHandle(hToken);
    }
    return bRet;
}

DWORD ProcessNameToPID(char* Name){

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(hSnapshot == INVALID_HANDLE_VALUE){
        printf("Create Snapshot failed");
        return 1;
    }
    PROCESSENTRY32 pi;
    pi.dwSize = sizeof(PROCESSENTRY32);
    BOOL bRet = Process32First(hSnapshot,&pi);
    while(bRet){
        if(strcmp(pi.szExeFile, Name) == 0){
            return pi.th32ProcessID;
        }
        else{
            bRet = Process32Next(hSnapshot,&pi);
        }
    }
    return 0;

}








