#include<Windows.h>
#include <tlhelp32.h>
#pragma warning(disable:4996)

BOOL InjectModuleToProcessById(DWORD dwPid, char* szDLLFullPath) {
	DWORD dwRet = 0;
	BOOL bStatus = FALSE;
	LPVOID lpData = NULL;
	SIZE_T uLen = lstrlen(szDLLFullPath) + 1;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess) {
		//分配空间
		lpData = VirtualAllocEx(hProcess, NULL, uLen, MEM_COMMIT, PAGE_READWRITE);
		DWORD dwErr = GetLastError();
		if (lpData) {
			//dll路径名
			bStatus = WriteProcessMemory(hProcess, lpData, szDLLFullPath, uLen, &dwRet);
		}
		CloseHandle(hProcess);
	}

	if (bStatus == FALSE)
		return FALSE;

	//创建线程快照
	THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return FALSE;

	bStatus = FALSE;
	//枚举所有线程
	if (Thread32First(hThreadSnap, &te32)) {
		do {
			//判断是否为目标进程中的线程
			if (te32.th32OwnerProcessID == dwPid) {
				//打开线程
				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
				if (hThread) {
					DWORD dwRet = QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (ULONG_PTR)lpData);
					if (dwRet > 0)
						bStatus = TRUE;
					CloseHandle(hThread);
				}
			}
		} while (Thread32Next(hThreadSnap, &te32));
	}
	CloseHandle(hThreadSnap);
	return bStatus;
}

int main() {
	FARPROC pFuncProcAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	const char* pszDllFileName = "C:\\Users\\42914\\Desktop\\注入\\dll注入\\Dll1\\Release\\Dll1.dll";

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
	InjectModuleToProcessById(dwProcessId, (char*)pszDllFileName);

}