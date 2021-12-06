#include<windows.h>
#include<stdio.h>
#pragma data_seg(."Share")
HHOOK g_hHook = NULL;		//必须赋初值
HMODULE g_hModule = NULL;
#pragma data_seg()

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	char szModulePath[100] = { 0 };
	char szBuffer[1024] = { 0 };
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH: {
		g_hModule = (HMODULE)hModule;
		GetModuleFileName(NULL, szModulePath, MAX_PATH);
		sprintf(szBuffer,"[MsgHook.dll] Injected into %s\n", szModulePath);
		OutputDebugString(szBuffer);
		break;
	}
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH: {
		g_hModule = (HMODULE)hModule;
		GetModuleFileName(NULL,szModulePath,100);	//最后一个参数：lpFilename缓冲区的大小，以TCHARs 为单位。
		//如果第一个参数为NULL，该函数返回该应用程序全路径。
		sprintf(szBuffer, "[MsgHook.dll] Unloaded from %s\n", szModulePath);
		OutputDebugString(szBuffer);
		break;
	}
		break;
	}
	return TRUE;
}

LRESULT CALLBACK MsgHookProc(int code, WPARAM wParam, LPARAM lParam) {
	return CallNextHookEx(g_hHook,code,wParam,lParam);
}

extern "C" MSGHOOK_API VOID InstallHook() {
	g_hHook = SetWindowsHookEx(WH_GETMESSAGE, MsgHookProc, g_hModule, 0);
}

extern "C" MSGHOOK_API VOID UnInstallHook() {
	UnhookWindowsHookEx(g_hHook);
}