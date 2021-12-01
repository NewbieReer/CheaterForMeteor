#include "windows.h"
#include<stdio.h>
#include <windows.h>
#include <tlhelp32.h>

int main(){

    HANDLE snapshot;
    PROCESSENTRY32 entry;
    DWORD dwProcessId;
    entry.dwSize = sizeof(PROCESSENTRY32);
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (stricmp(entry.szExeFile, "Meteor.exe") == 0)
            {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                dwProcessId = GetProcessId(hProcess);
                CloseHandle(hProcess);
            }
        }
    }
// 1.打开目标进程
HANDLE hProcess = OpenProcess(
    PROCESS_ALL_ACCESS,     // 打开权限
    FALSE,                  // 是否继承
    dwProcessId);           // 进程PID
if(hProcess== NULL){
    MessageBox(NULL,"打开目标进程失败！", "打开目标进程失败！", MB_OK);
    return FALSE;
}

const char * pszDllFileName = "C:\\Users\\42914\\Desktop\\注入\\dll注入\\Dll1\\Release\\Dll1.dll";

// 2.在目标进程中申请空间
LPVOID lpPathAddr = VirtualAllocEx(
    hProcess,                   // 目标进程句柄
    0,                          // 指定申请地址
    strlen(pszDllFileName) + 1,   // 申请空间大小
    MEM_RESERVE | MEM_COMMIT, // 内存的状态
    PAGE_READWRITE);            // 内存属性
if (NULL == lpPathAddr)
{
    MessageBox(NULL, "在目标进程中申请空间失败！", "在目标进程中申请空间失败！", MB_OK);
    CloseHandle(hProcess);
    return FALSE;
}

// 3.在目标进程中写入Dll路径
SIZE_T dwWriteSize = 0;
if (FALSE == WriteProcessMemory(
    hProcess,                   // 目标进程句柄
    lpPathAddr,                 // 目标进程地址
    pszDllFileName,                 // 写入的缓冲区
    strlen(pszDllFileName) + 1,   // 缓冲区大小
    &dwWriteSize))              // 实际写入大小
{
    MessageBox(NULL, "目标进程中写入Dll路径失败！", "目标进程中写入Dll路径失败！", MB_OK);
    CloseHandle(hProcess);
    return FALSE;
}

//获取LoadLibraryA的函数地址
//FARPROC可以自适应32位与64位
FARPROC pFuncProcAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
if (NULL == pFuncProcAddr)
{
    MessageBox(NULL, "获取LoadLibrary函数地址失败！", "获取LoadLibrary函数地址失败！", MB_OK);
    CloseHandle(hProcess);
    return FALSE;
}

// 4.在目标进程中创建线程
HANDLE hThread = CreateRemoteThread(
    hProcess,                   // 目标进程句柄
    NULL,                       // 安全属性
    NULL,                       // 栈大小
    (PTHREAD_START_ROUTINE)pFuncProcAddr,   // 回调函数
    lpPathAddr,                 // 回调函数参数
    NULL,                       // 标志
    NULL                        // 线程ID
);
if (NULL == hThread)
{
    MessageBox(NULL, "目标进程中创建线程失败！", "目标进程中创建线程失败！", MB_OK);
    CloseHandle(hProcess);
    return FALSE;
}

// 5.等待线程结束
WaitForSingleObject(hThread, -1);

// 6.清理环境
VirtualFreeEx(hProcess, lpPathAddr, 0, MEM_RELEASE);
CloseHandle(hThread);
CloseHandle(hProcess);
return TRUE;
}