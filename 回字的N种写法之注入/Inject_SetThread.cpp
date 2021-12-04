#include<stdio.h>
#include<Windows.h>
#include <tlhelp32.h>
#pragma warning(disable:4996)

typedef struct _INJECT_DATA {
	BYTE ShellCode[0x32];
	ULONG_PTR AddrofLoadLibraryA;
	PBYTE lpDLLPath;
	ULONG_PTR OriginalEIP;
	char szDLLPath[MAX_PATH];
}INJECT_DATA;

__declspec (naked)
VOID ShellCodeFun(VOID)
{
	__asm {
		push eax
		pushad
		pushfd
		call L001
	L001:
		pop ebx
		sub ebx,8
		push dword ptr ds:[ebx+0x34]
		call dword ptr ds:[ebx+0x30]
		mov eax, dword ptr ds:[ebx+0x38]
		xchg eax,[esp+0x24]
		popfd
		popad
		retn
	}
}


int main() {
	const char* szDLLFullPath = "C:\\Users\\42914\\Desktop\\注入\\dll注入\\Dll1\\Release\\Dll1.dll";
	BOOL bStatus = FALSE;
	DWORD Index = 0;
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	DWORD dwTidList[100];

	FARPROC pFuncProcAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return FALSE;

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


	printf("%d,", dwProcessId);
	bStatus = FALSE;
	THREADENTRY32 te32 = {sizeof(THREADENTRY32)};
	//枚举所有线程
	if (Thread32First(hThreadSnap, &te32)) {
		do {
			if (te32.th32OwnerProcessID == dwProcessId) {
				bStatus = TRUE;
				printf("hit");
				dwTidList[Index++] = te32.th32ThreadID;
			}
		} while (Thread32Next(hThreadSnap, &te32));
	}
	CloseHandle(hThreadSnap);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwTidList[3]);

	printf("%p",hThread);

	CONTEXT Context;
	ULONG_PTR uEIP = 0;
	//获取Context
	ZeroMemory(&Context, sizeof(CONTEXT));
	Context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &Context);
	//保存eip，备用
	uEIP = Context.Eip;

	PBYTE lpData = (PBYTE)VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	INJECT_DATA Data;
	memcpy(Data.ShellCode, (PBYTE)ShellCodeFun, 0x32);
	lstrcpy(Data.szDLLPath, szDLLFullPath);
	Data.AddrofLoadLibraryA = (ULONG_PTR)pFuncProcAddr;
	Data.OriginalEIP = uEIP;
	Data.lpDLLPath = lpData + FIELD_OFFSET(INJECT_DATA, szDLLPath);

	WriteProcessMemory(hProcess, lpData, &Data, sizeof(INJECT_DATA), NULL);

	//设置线程的CONTEXT，使eip指向Shellcode的起始地址
	Context.Eip = (ULONG)lpData;
	//设置CONTEXT
	SetThreadContext(hThread, &Context);
	//恢复线程的运行
	DWORD dwSuspendCnt = ResumeThread(hThread);

}