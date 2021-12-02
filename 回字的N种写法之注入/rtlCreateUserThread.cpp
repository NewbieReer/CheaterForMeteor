#include<Windows.h>
#include<stdio.h>

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
		push dowrd ptr ds:[ebx+0x24]	//lpParameter
		call dword ptr ds:[ebx+0x20]	//ThreadProc
		xor eax,eax
		push eax
		push -2		//CurrentThread
		call dword ptr ds:[ebx+0x28]	//ZwTerminateThread
		nop
	}
}

HANDLE RtlCreatRemoteThead(
	IN HANDLE hProcess,
	IN LPSECURITY_ATTRIBUTES lpThreadAttributes,
	IN DWORD dwStackSize,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN DWORD dwCreationFlags,
	OUT LPDWORD lpThreadId
) {
	NTSTATUS status = STATUS_SUCCESS;
	CLIENT_ID Cid;
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

	printf("[*] pMen = 0x%p\n", pMem);

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
		lpThreadAttribute,  //ThreadSecurityDescriptor
		TRUE,	//CreateSuspend
		0,		//ZeroBits
		dwStackSize,	//MaximumStackSize
		0,	//CommittedStackSize
		(PUSER_THREAD_START_ROUTINE)pMem,	//pMem的开头就是Shellcode
		NULL,
		&hThread,
		&Cid
	);
	if (status >= 0) {
		printf("创建线程成功\n");
		if (lpThreadId != NULL) {
			*lpThreadId = (DWORD)Cid.UniqueThread;
		}
		if (!(dwCreationFlags & CREATE_SUSPENDED)) {
			ResumeThread(hThread);
		}
	}
	return hThread;
}
