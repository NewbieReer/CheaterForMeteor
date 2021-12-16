/////////////////////////////////////////////////////////////////
//         ��13��  Hook���� ����������ܣ����İ棩��           //
//                                                             //
//         Author: achillis(���½���)                          //
//         Blog  : http://www.cnblogs.com/achillis/            //
//         QQ    : 344132161                                   //
//         Email : achillis@126.com                            //
//         ת���뱣��������Ϣ                                  //
//         (c)  ��ѩѧԺ www.kanxue.com 2000-2018              //
/////////////////////////////////////////////////////////////////
//������:Ϊ�����̵�exeģ�鰲װIAT Hook��Ŀ�꺯����MessageBoxA

#include <windows.h>
#include <stdio.h>
#include <imagehlp.h>
#pragma comment(lib,"imagehlp.lib")
#pragma warning(disable:4996)


//��MessageBoxA��ԭ�Ͷ���һ������ָ������
typedef int 
(WINAPI *PFN_MessageBoxA)(
	HWND hWnd,          // handle of owner window
	LPCTSTR lpText,     // address of text in message box
	LPCTSTR lpCaption,  // address of title of message box
	UINT uType          // style of message box
	);

//��MessageBoxA��ԭ�Ͷ���һ�����������ԭʼ��MessageBoxA
int WINAPI My_MessageBoxA(
	HWND hWnd,          // handle of owner window
	LPCTSTR lpText,     // address of text in message box
	LPCTSTR lpCaption,  // address of title of message box
	UINT uType          // style of message box
	);

//�������¹�ϵ
//*(*pThunkPointer) == *pOriginalFuncAddr ;
BOOL InstallModuleIATHook(
	HMODULE hModToHook,
	char *szModuleName, 
	char *szFuncName,
	PVOID ProxyFunc,
	PULONG_PTR *pThunkPointer,
	ULONG_PTR *pOriginalFuncAddr
	);

VOID ShowMsgBox(char *szMsg);
BOOL IAT_InstallHook();
VOID IAT_UnInstallHook();
BOOL IsWow64();
//����ԭʼMessageBoxA�ĵ�ַ
PFN_MessageBoxA OldMessageBox=NULL;
//ָ��IAT��pThunk�ĵ�ַ
PULONG_PTR g_PointerToIATThunk = NULL;

int main(int argc, char *argv[ ])
{
	BOOL bIsWow64 = IsWow64();
	printf("IsWow64 = %d\n",bIsWow64);
	ShowMsgBox((char *)"Before IAT Hook");
	IAT_InstallHook();
	ShowMsgBox((char*)"After  IAT Hook");
	IAT_UnInstallHook();
	ShowMsgBox((char*)"After  IAT Hook UnHooked");
	return 0;
}

//֮���԰�������õ�������һ�������У�����ΪReleaseģʽ�¶Ե��ý������Ż�,�ڶ��ε���ʱֱ�Ӳ����˼Ĵ���Ѱַ�����ǵ����
//��ˣ���������һ�������п��Ա�����������

VOID ShowMsgBox(char *szMsg)
{
	MessageBoxA(NULL,szMsg,"Test",MB_OK);
}


int WINAPI My_MessageBoxA(
	HWND hWnd,          // handle of owner window
	LPCTSTR lpText,     // address of text in message box
	LPCTSTR lpCaption,  // address of title of message box
	UINT uType          // style of message box
	)
{	
	//���������Զ�ԭʼ���������������
	int ret;
	char newText[1024]={0};
	char newCaption[256]="pediy.com";
	printf("���˵���MessageBox!\n");
	//�ڵ���ԭ����֮ǰ�����Զ�IN(������)�������и���
	lstrcpy(newText,lpText);//Ϊ��ֹԭ�����ṩ�Ļ��������������︴�Ƶ������Լ���һ�����������ٽ��в���
	lstrcat(newText,"\n\tMessageBox Hacked by pediy.com!");//�۸���Ϣ������
	uType|=MB_ICONERROR;//����һ������ͼ��
	ret = OldMessageBox(hWnd,newText,newCaption,uType);//����ԭMessageBox�������淵��ֵ
	//����ԭ����֮�󣬿��Լ�����OUT(�����)�������и���,�������纯����recv�����Ը��淵�ص�����
	return ret;//�����㻹���Ը���ԭʼ�����ķ���ֵ
	
}

BOOL IAT_InstallHook()
{
	BOOL bResult = FALSE ;
	HMODULE hCurExe = GetModuleHandle(NULL);
	PULONG_PTR pt ;
	ULONG_PTR OrginalAddr;
	bResult = InstallModuleIATHook(hCurExe, (char *)"user32.dll",(char *)"MessageBoxA",(PVOID)My_MessageBoxA,&pt,&OrginalAddr);
	if (bResult)
	{
		printf("[*]Hook��װ���! pThunk=0x%p  OriginalAddr = 0x%p\n",pt,OrginalAddr);
		g_PointerToIATThunk = pt ;
		OldMessageBox = (PFN_MessageBoxA)OrginalAddr ;
	}
	return bResult;
	
}

VOID IAT_UnInstallHook()
{
	
	DWORD dwOLD;
	MEMORY_BASIC_INFORMATION  mbi;
	if (g_PointerToIATThunk)
	{
		//��ѯ���޸��ڴ�ҳ������
		VirtualQuery((LPCVOID)g_PointerToIATThunk,&mbi,sizeof(mbi));
		VirtualProtect(mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&dwOLD);
		//��ԭʼ��MessageBoxA��ַ����IAT��
		*g_PointerToIATThunk = (ULONG)OldMessageBox;
		//�ָ��ڴ�ҳ������
		VirtualProtect(mbi.BaseAddress,mbi.RegionSize,dwOLD,0);
	}

}

//************************************
// FullName:    InstallModuleIATHook
// Description: Ϊָ��ģ�鰲װIAT Hook
// Access:      public 
// Returns:     BOOL
// Parameter:   HMODULE hModToHook , ��Hook��ģ���ַ
// Parameter:   char * szModuleName , Ŀ�꺯������ģ�������
// Parameter:   char * szFuncName , Ŀ�꺯��������
// Parameter:   PVOID DetourFunc , Detour������ַ
// Parameter:   PULONG * pThunkPointer , ���Խ���ָ���޸ĵ�λ�õ�ָ��
// Parameter:   ULONG * pOriginalFuncAddr , ���Խ���ԭʼ������ַ
//************************************
BOOL InstallModuleIATHook(
	HMODULE hModToHook,// IN
	char *szModuleName,// IN
	char *szFuncName,// IN
	PVOID DetourFunc,// IN
	PULONG_PTR *pThunkPointer,//OUT
	ULONG_PTR *pOriginalFuncAddr//OUT
	)
{
	PIMAGE_IMPORT_DESCRIPTOR  pImportDescriptor;
	PIMAGE_THUNK_DATA         pThunkData;
	ULONG ulSize;
	HMODULE hModule=0;
	ULONG_PTR TargetFunAddr;
	PULONG_PTR lpAddr;
	char *szModName;
	BOOL result = FALSE ;
	BOOL bRetn = FALSE;

	hModule = LoadLibrary(szModuleName);
	TargetFunAddr = (ULONG_PTR)GetProcAddress(hModule,szFuncName);
	printf("[*]Address of %s:0x%p\n",szFuncName,TargetFunAddr);
	printf("[*]Module To Hook at Base:0x%p\n",hModToHook);
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModToHook, TRUE,IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);;
	printf("[*]Find ImportTable,Address:0x%p\n",pImportDescriptor);
	while (pImportDescriptor->FirstThunk)
	{
		szModName = (char*)((PBYTE)hModToHook+pImportDescriptor->Name) ;
		printf("[*]Cur Module Name:%s\n",szModName);
		if (stricmp(szModName,szModuleName) != 0)
		{
			printf("[*]Module Name does not match, search next...\n");
			pImportDescriptor++;
			continue;
		}
		//����ĵ��������Ϻ�OriginalFirstThunk��������Ч�ģ������ٸ������������ң����Ǳ���FirstThunkֱ�Ӹ��ݵ�ַ�ж�
		pThunkData = (PIMAGE_THUNK_DATA)((BYTE *)hModToHook + pImportDescriptor->FirstThunk);
		while(pThunkData->u1.Function)
		{
			lpAddr = (ULONG_PTR*)pThunkData;
			//�ҵ��˵�ַ
			if((*lpAddr) == TargetFunAddr)
			{
				printf("[*]Find target address!\n");
				//ͨ������µ���������ڴ�ҳ����ֻ���ģ������Ҫ���޸��ڴ�ҳ������Ϊ��д
				DWORD dwOldProtect;
				MEMORY_BASIC_INFORMATION  mbi;
				VirtualQuery(lpAddr,&mbi,sizeof(mbi));
				bRetn = VirtualProtect(mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&dwOldProtect);
				if (bRetn)
				{
					//�ڴ�ҳ�����޸ĳɹ�,������һ������,�ȱ���ԭʼ����
					if (pThunkPointer != NULL)
					{
						*pThunkPointer = lpAddr ;
					}
					if (pOriginalFuncAddr != NULL)
					{
						*pOriginalFuncAddr = *lpAddr ;
					}
					//�޸ĵ�ַ
					*lpAddr = (ULONG_PTR)DetourFunc;
					result = TRUE ;
					//�ָ��ڴ�ҳ������
					VirtualProtect(mbi.BaseAddress,mbi.RegionSize,dwOldProtect,0);
					printf("[*]Hook ok.\n");
				}
				
				break;	
			}
			//---------
			pThunkData++;
		}
		pImportDescriptor++;
	}
	
	FreeLibrary(hModule);
	return result;
}
typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

LPFN_ISWOW64PROCESS fnIsWow64Process;

BOOL IsWow64()
{
	BOOL bIsWow64 = FALSE;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
		GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

	if (NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(GetCurrentProcess(),&bIsWow64))
		{
			// handle error
		}
	}
	return bIsWow64;
}

