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
// 1.��Ŀ�����
HANDLE hProcess = OpenProcess(
    PROCESS_ALL_ACCESS,     // ��Ȩ��
    FALSE,                  // �Ƿ�̳�
    dwProcessId);           // ����PID
if(hProcess== NULL){
    MessageBox(NULL,"��Ŀ�����ʧ�ܣ�", "��Ŀ�����ʧ�ܣ�", MB_OK);
    return FALSE;
}

const char * pszDllFileName = "C:\\Users\\42914\\Desktop\\ע��\\dllע��\\Dll1\\Release\\Dll1.dll";

// 2.��Ŀ�����������ռ�
LPVOID lpPathAddr = VirtualAllocEx(
    hProcess,                   // Ŀ����̾��
    0,                          // ָ�������ַ
    strlen(pszDllFileName) + 1,   // ����ռ��С
    MEM_RESERVE | MEM_COMMIT, // �ڴ��״̬
    PAGE_READWRITE);            // �ڴ�����
if (NULL == lpPathAddr)
{
    MessageBox(NULL, "��Ŀ�����������ռ�ʧ�ܣ�", "��Ŀ�����������ռ�ʧ�ܣ�", MB_OK);
    CloseHandle(hProcess);
    return FALSE;
}

// 3.��Ŀ�������д��Dll·��
SIZE_T dwWriteSize = 0;
if (FALSE == WriteProcessMemory(
    hProcess,                   // Ŀ����̾��
    lpPathAddr,                 // Ŀ����̵�ַ
    pszDllFileName,                 // д��Ļ�����
    strlen(pszDllFileName) + 1,   // ��������С
    &dwWriteSize))              // ʵ��д���С
{
    MessageBox(NULL, "Ŀ�������д��Dll·��ʧ�ܣ�", "Ŀ�������д��Dll·��ʧ�ܣ�", MB_OK);
    CloseHandle(hProcess);
    return FALSE;
}

//��ȡLoadLibraryA�ĺ�����ַ
//FARPROC��������Ӧ32λ��64λ
FARPROC pFuncProcAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
if (NULL == pFuncProcAddr)
{
    MessageBox(NULL, "��ȡLoadLibrary������ַʧ�ܣ�", "��ȡLoadLibrary������ַʧ�ܣ�", MB_OK);
    CloseHandle(hProcess);
    return FALSE;
}

// 4.��Ŀ������д����߳�
HANDLE hThread = CreateRemoteThread(
    hProcess,                   // Ŀ����̾��
    NULL,                       // ��ȫ����
    NULL,                       // ջ��С
    (PTHREAD_START_ROUTINE)pFuncProcAddr,   // �ص�����
    lpPathAddr,                 // �ص���������
    NULL,                       // ��־
    NULL                        // �߳�ID
);
if (NULL == hThread)
{
    MessageBox(NULL, "Ŀ������д����߳�ʧ�ܣ�", "Ŀ������д����߳�ʧ�ܣ�", MB_OK);
    CloseHandle(hProcess);
    return FALSE;
}

// 5.�ȴ��߳̽���
WaitForSingleObject(hThread, -1);

// 6.������
VirtualFreeEx(hProcess, lpPathAddr, 0, MEM_RELEASE);
CloseHandle(hThread);
CloseHandle(hProcess);
return TRUE;
}