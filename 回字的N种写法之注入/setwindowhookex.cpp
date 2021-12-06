#include<windows.h>
#include<stdio.h>
#pragma data_seg(."Share")
HHOOK g_hHook = NULL;		//���븳��ֵ
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
		GetModuleFileName(NULL,szModulePath,100);	//���һ��������lpFilename�������Ĵ�С����TCHARs Ϊ��λ��
		//�����һ������ΪNULL���ú������ظ�Ӧ�ó���ȫ·����
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