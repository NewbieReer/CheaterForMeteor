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

__declspec (naked)		//这句话是告诉编译器下面的代码是直接拿来用的
						//不需要为它添加其他汇编代码
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

	//获取Native API函数的地址

	RtlCreateUserThread = (PCreateThread)GetProcAddress(GetModuleHandle("ntdll"), \
		"RtlCreateUserThread");
	if (RtlCreateUserThread == NULL)
		return NULL;

	//在目标进程中申请内存，写入Shellcode
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

	//写入Shellcode
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
		(LPVOID)pMem,	//pMem的开头就是Shellcode
		NULL,
		&hThread,
		&Cid
	);
	if (status >= 0) {
		printf("创建线程成功\n");
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
	const char* pszDllFileName = "C:\\Users\\42914\\Desktop\\注入\\dll注入\\Dll1\\Release\\Dll1.dll";
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
				
				RtlCreatRemoteThead(hProcess,NULL,NULL, (PTHREAD_START_ROUTINE)pFuncProcAddr, lpPathAddr,NULL,NULL);
				dwProcessId = GetProcessId(hProcess);
				CloseHandle(hProcess);
			}
		}
	}

	printf("done");
	return 0;
}