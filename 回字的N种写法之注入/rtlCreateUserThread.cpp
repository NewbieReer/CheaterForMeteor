#include<windows.h>
#include<stdio.h>
#include <tlhelp32.h>
#pragma warning(disable:4996)
//https://www.cnblogs.com/jentleTao/p/12728142.html
//https://blog.csdn.net/qq_18218335/article/details/75246816

typedef struct _INJECT_DATA {
	BYTE ShellCode[0x20];		//0x00
	LPVOID lpThreadStartRoutine;	//0x20
	LPVOID lpParameter;			//0x24
	LPVOID AddrOfZwTerminateThread;	//0x28
}INJECT_DATA;

__declspec (naked)		//��仰�Ǹ��߱���������Ĵ�����ֱ�������õ�
						//����ҪΪ���������������
VOID ShellCodeFun(VOID) {
	//ThreadProc(lpParameter);
	//ZwTerminateThread(GetCurrentThread,0);
	__asm {
		call L001
	L001:
		pop ebx
		sub ebx,5
		push dword ptr ds:[ebx+0x24]	//lpParameter
		call dword ptr ds:[ebx+0x20]	//ThreadProc
		xor eax,eax
		push eax
		push -2		//CurrentThread
		call dword ptr ds:[ebx+0x28]	//ZwTerminateThread
		nop
	}
}

typedef DWORD(WINAPI * PCreateThread)(
	IN HANDLE                     ProcessHandle,
	IN PSECURITY_DESCRIPTOR     SecurityDescriptor,
	IN BOOL                     CreateSuspended,
	IN ULONG                    StackZeroBits,
	IN OUT PULONG                StackReserved,
	IN OUT PULONG                StackCommit,
	IN LPVOID                    StartAddress,
	IN LPVOID                    StartParameter,
	OUT HANDLE                     ThreadHandle,
	OUT LPVOID                    ClientID
	);

HANDLE RtlCreatRemoteThead(
	IN HANDLE hProcess,
	IN LPSECURITY_ATTRIBUTES lpThreadAttributes,
	IN DWORD dwStackSize,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN DWORD dwCreationFlags,
	OUT LPDWORD lpThreadId
) {
	PCreateThread RtlCreateUserThread;
	LPVOID Cid;
	NTSTATUS status = NULL;
	HANDLE hThread = NULL;
	DWORD dwIoCnt = 0;
	if (hProcess == NULL || lpStartAddress == NULL)
		return NULL;

	//��ȡNative API�����ĵ�ַ

	RtlCreateUserThread = (PCreateThread)GetProcAddress(GetModuleHandle("ntdll"), \
		"RtlCreateUserThread");
	if (RtlCreateUserThread == NULL)
		return NULL;

	//��Ŀ������������ڴ棬д��Shellcode
	PBYTE pMem = (PBYTE)VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, \
		PAGE_EXECUTE_READWRITE);
	if (pMem == NULL)
		return NULL;

	printf("[*] pMem = 0x%p\n", pMem);

	INJECT_DATA Data;
	PBYTE pShellCode = (PBYTE)ShellCodeFun;

#ifdef _DEBUG
	if (pShellCode[0] == 0xe9) {
		pShellCode = pShellCode + *(ULONG*)(pShellCode + 1) + 5;
	}
#endif

	ZeroMemory(&Data, sizeof(INJECT_DATA));
	memcpy(Data.ShellCode, pShellCode, 32);
	Data.lpParameter = lpParameter;
	Data.lpThreadStartRoutine = lpStartAddress;
	Data.AddrOfZwTerminateThread = GetProcAddress(GetModuleHandle("ntdll"), \
		"ZwTerminateThread");

	//д��Shellcode
	if (!WriteProcessMemory(hProcess, pMem, &Data, sizeof(INJECT_DATA), &dwIoCnt)) {
		printf("[-] WriteProcessMemory Failed!\n");
		VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
		return NULL;
	}

	printf("ShellCode Write OK.\n");

	status = RtlCreateUserThread(
		hProcess,
		lpThreadAttributes,	//ThreadSecurityDescriptor
		TRUE,	//CreateSuspend
		0,		//ZeroBits
		0,		//MaximumStackSize
		0,		//CommittedStackSize
		(LPVOID)pMem,	//pMem�Ŀ�ͷ����Shellcode
		NULL,
		&hThread,
		&Cid
	);
	if (status >= 0) {
		printf("�����̳߳ɹ�\n");
		/*
		if (lpThreadId != NULL) {
			*lpThreadId = (DWORD)Cid.UniqueThread;
		}*/
		if (!(dwCreationFlags & CREATE_SUSPENDED)) {
			ResumeThread(hThread);
		}
	}
	return hThread;
}

int main() {

	FARPROC pFuncProcAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	const char* pszDllFileName = "C:\\Users\\42914\\Desktop\\ע��\\dllע��\\Dll1\\Release\\Dll1.dll";
	SIZE_T dwWriteSize = 0;



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
				
				RtlCreatRemoteThead(hProcess,NULL,NULL, (PTHREAD_START_ROUTINE)pFuncProcAddr, lpPathAddr,NULL,NULL);
				dwProcessId = GetProcessId(hProcess);
				CloseHandle(hProcess);
			}
		}
	}

	printf("done");
	return 0;
}