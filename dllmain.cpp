// dllmain.cpp : 定义 DLL 应用程序的入口点。

#include "pch.h"
#include<stdio.h>
#include <windows.h>
#include <tlhelp32.h>
# pragma warning(disable:4996)


DWORD* p_atexit = (DWORD*)0x5089BC;
BYTE * bytea;
BYTE * byteb;
DWORD* p_father_weapon = (DWORD*)0x4DC9A0;
DWORD* sub_4A8E30 = (DWORD*)0x4A8E30;
DWORD* sub_49C640 = (DWORD*)0x49C640;
DWORD* sub_4E4130 = (DWORD*)0x4E4130;
DWORD* sub_402570 = (DWORD*)0x402570;
DWORD* rett = (DWORD*)0x4CFD2E;

int new_weapon(){
    __asm {
        pop edi;
        pop esi;
        pop ebx;
        mov esp, ebp;
        pop ebp;
        mov eax, [esp + 8];
        cmp eax, 5h;
        jz  a1;
        retn;
    a1:
        call a2;
        add esp, 4;
        ret;
    a2:
        mov cl, byte ptr[bytea];    //bytea
        mov al, 1;
        test cl, al;
        jnz a3;
        mov dl, cl;
        mov ecx, offset byteb;    //byteb
        or dl, al;
        mov byte ptr[bytea], dl;
        call a3;                   //构造父武器和子武器
        push 0x4DE210;          //unknown_libname_36
        call p_atexit;          //_atexit
        add esp, 4;
        mov eax, offset byteb;
        ret;
    a3:
        push 0xFFFFFFFF;
        push 0x5A28E8;
        mov eax, fs: [0] ;
        push eax;
        mov fs : [0] , esp;
        push ecx;
        push    esi;
        mov     esi, ecx;
        mov [esp + 4], esi;
        call    p_father_weapon;
        mov     ecx, esi;
        mov     dword ptr[esp + 16], 0;
        mov     dword ptr[esi], 0x5AABE0;
        call    a4;
        mov     ecx, [esp + 8];
        mov     eax, esi;
        pop     esi;
        mov     fs : [0] , ecx;
        add     esp, 10h;
        retn;
    a4:
        sub     esp, 14h;
        push    ebx;
        push    esi;
        push    edi;
        mov     edi, ecx;
        mov dword ptr[esp + 16], 44h;
        mov     ebx, 4;
        lea     esi, [edi + 1Ch];
        mov     dword ptr[edi + 14h], 5; //音效-武器TypeID
        mov     dword ptr[edi + 18h], 10h;
        mov     eax, [esi + 4];
        mov     ecx, [esi + 8];
        cmp     eax, ecx;
        jz      a5;
        lea     ecx, [esp + 16];
        push    ecx;
        push    eax;
        call    sub_4A8E30;
        mov     eax, [esi + 4];
        add     esp, 8;
        add     eax, ebx;
        mov[esi + 4], eax;
        jmp     a6;
    a5:
        lea     edx, [esp + 16];
        mov     ecx, esi;
        push    edx;
        push    eax;
        call    sub_49C640;
    a6:
        mov     eax, [esi + 4];
        mov     ecx, [esi + 8];
        cmp     eax, ecx;
        mov dword ptr[esp + 16], 45h;
        jz      a7;
        lea     ecx, [esp + 16];
        push    ecx;
        push    eax;
        call    sub_4A8E30;
        mov     eax, [esi + 4];
        add     esp, 8;
        add     eax, ebx;
        mov[esi + 4], eax;
        jmp     a8;
     a7:
        lea     edx, [esp + 16];
        mov     ecx, esi;
        push    edx;
        push    eax;
        call    sub_49C640;

     a8:
        mov     eax, [esi + 4];
        mov     ecx, [esi + 8];
        cmp     eax, ecx;
        mov     dword ptr[esp + 16], 46h;
        jz      short loc_5CAE66;
        lea     ecx, [esp + 16];
        push    ecx;
        push    eax;
        call    sub_4A8E30;
        mov     eax, [esi + 4];
        add     esp, 8;
        add     eax, ebx;
        mov [esi + 4], eax;
        jmp     short loc_5CAE73;
    loc_5CAE66:
        lea     edx, [esp + 16];
        mov     ecx, esi;
        push    edx;
        push    eax;
        call    sub_49C640;
     loc_5CAE73 :
        mov     eax, [esi + 4];
        mov     ecx, [esi + 8];
        cmp     eax, ecx;
        mov     dword ptr[esp + 16], 47h;
        jz      short loc_5CAE9D;
        lea     ecx, [esp + 16];
        push    ecx;
        push    eax;
        call    sub_4A8E30;
        mov     eax, [esi + 4];
        add     esp, 8;
        add     eax, ebx;
        mov [esi + 4], eax;
        jmp     short loc_5CAEAA;
     loc_5CAE9D:
        lea     edx, [esp + 16];
        mov     ecx, esi;
        push    edx;
        push    eax;
        call    sub_49C640;
     loc_5CAEAA : 
        mov     eax, [esi + 4];
        mov     ecx, [esi + 8];
        cmp     eax, ecx;
        mov dword ptr[esp + 16], 50h;
        jz      short loc_5CAED4;
        lea     ecx, [esp + 16];
        push    ecx;
        push    eax;
        call    sub_4A8E30;
        mov     eax, [esi + 4];
        add     esp, 8;
        add     eax, ebx;
        mov[esi + 4], eax;
        jmp     short loc_5CAEE1;
     loc_5CAED4:
        lea     edx, [esp + 16];
        mov     ecx, esi;
        push    edx;
        push    eax;
        call    sub_49C640;
     loc_5CAEE1 :
        mov     eax, [esi + 4];
        mov     ecx, [esi + 8];
        cmp     eax, ecx;
        mov dword ptr[esp + 16], 51h;
        jz      short loc_5CAF0B;
        lea     ecx, [esp + 16];
        push    ecx;
        push    eax;
        call    sub_4A8E30;
        mov     eax, [esi + 4];
        add     esp, 8;
        add     eax, ebx;
        mov[esi + 4], eax;
        jmp     short loc_5CAF18;
     loc_5CAF0B:
        lea     edx, [esp + 16];
        mov     ecx, esi;
        push    edx;
        push    eax;
        call    sub_49C640;
     loc_5CAF18 :
        mov     eax, [esi + 4];
        mov     ecx, [esi + 8];
        cmp     eax, ecx;
        mov dword ptr[esp + 16], 52h;
        jz      short loc_5CAF42;
        lea     ecx, [esp + 16];
        push    ecx;
        push    eax;
        call    sub_4A8E30;
        mov     eax, [esi + 4];
        add     esp, 8;
        add     eax, ebx;
        mov[esi + 4], eax;
        jmp     short loc_5CAF4F;
     loc_5CAF42:
        lea     edx, [esp + 16];
        mov     ecx, esi;
        push    edx;
        push    eax;
        call    sub_49C640;
    loc_5CAF4F : 
        mov     eax, [edi + 2Ch];
        mov     ecx, [edi + 30h];
        lea     esi, [edi + 28h];
        cmp     eax, ecx;
        mov dword ptr[esp + 16], 46h;
        jz      short loc_5CAF7C;
        lea     ecx, [esp + 16];
        push    ecx;
        push    eax;
        call    sub_4A8E30;
        mov     eax, [esi + 4];
        add     esp, 8;
        add     eax, ebx;
        mov     [esi + 4], eax;
        jmp     short loc_5CAF89;
    loc_5CAF7C:
        lea     edx, [esp + 16];
        mov     ecx, esi;
        push    edx;
        push    eax;
        call    sub_49C640;
     loc_5CAF89 : 
        lea     eax, [esp + 16];
        lea     ecx, [esp + 24];
        lea     esi, [edi + 34h];
        push    eax;
        mov     ebx, 3ch;
        push    ecx;
        mov     ecx, esi;
        mov     dword ptr[esp + 24], 0A4h;
        mov[esp + 28], ebx;
        call    sub_4E4130;
        lea     edx, [esp + 16];
        lea     eax, [esp + 24];
        push    edx;
        push    eax;
        mov     ecx, esi;
        mov     dword ptr [esp + 24], 0A6h;
        mov     [esp + 28], ebx;
        call    sub_4E4130;
        push    ebx;
        lea     edx, [esp + 19];
        sub     esp, 0Ch;
        mov     ecx, esp;
        mov[esp + 32], esp;
        push    edx;
        push    0x5C6838;
        call    sub_402570;
        mov     eax, [edi + 4];
        lea     esi, [edi + 4];
        mov     ecx, esi;
        call    dword ptr[eax + 8];
        push    3Dh;
        lea     edx, [esp + 19];
        sub     esp, 0Ch;
        mov     ecx, esp;
        mov     [esp + 32], esp;
        push    edx;
        push    0x5C9E48;
        call    sub_402570;
        mov     eax, [esi];
        mov     ecx, esi;
        call    dword ptr[eax + 8];
        push    3Eh;
        lea     edx, [esp + 19];
        sub     esp, 0Ch;
        mov     ecx, esp;
        mov[esp + 32], esp;
        push    edx;
        push    0x5C7C28;
        call    sub_402570;
        mov     eax, [esi];
        mov     ecx, esi;
        call    dword ptr[eax + 8];
        push    3Fh;
        lea     edx, [esp + 19];
        sub     esp, 0Ch;
        mov     ecx, esp;
        mov[esp + 32], esp;
        push    edx;
        push    0x5C9E44;
        call    sub_402570;
        mov     eax, [esi];
        mov     ecx, esi;
        call    dword ptr[eax + 8];
        push    40h;
        lea     edx, [esp + 19];
        sub     esp, 0Ch;
        mov     ecx, esp;
        mov     [esp + 32], esp;
        push    edx;
        push    0x5C9E40;
        call    sub_402570;
        mov     eax, [esi];
        mov     ecx, esi;
        call    dword ptr[eax + 8];
        push    47h;
        lea     edx, [esp + 19];
        sub     esp, 0Ch;
        mov     ecx, esp;
        mov[esp + 32], esp;
        push    edx;
        push    0x5C9E3C;
        call    sub_402570;
        mov     eax, [esi];
        mov     ecx, esi;
        call    dword ptr[eax + 8];
        push    41h;
        lea     edx, [esp + 19];
        sub     esp, 0Ch;
        mov     ecx, esp;
        mov[esp + 32], esp;
        push    edx;
        push    0x5C9E2C;
        call    sub_402570;
        mov     eax, [esi];
        mov     ecx, esi;
        call    dword ptr[eax + 8];
        push    42h;
        lea     edx, [esp + 19];
        sub     esp, 0Ch;
        mov     ecx, esp;
        mov[esp + 32], esp;
        push    edx;
        push    0x5C9E34;
        call    sub_402570;
        mov     eax, [esi];
        mov     ecx, esi;
        call    dword ptr[eax + 8];
        push    43h;
        lea     edx, [esp + 19];
        sub     esp, 0Ch;
        mov     ecx, esp;
        mov[esp + 32], esp;
        push    edx;
        push    0x5C9E38;
        call    sub_402570;
        mov     eax, [esi];
        mov     ecx, esi;
        call    dword ptr[eax + 8];
        push    44h;
        lea     edx, [esp + 19];
        sub     esp, 0Ch;
        mov     ecx, esp;
        mov    [esp + 32], esp;
        push    edx;
        push    0x5C9E18;
        call    sub_402570;
        mov     eax, [esi];
        mov     ecx, esi;
        call    dword ptr[eax + 8];
        push    45h;
        lea     edx, [esp + 19];
        sub     esp, 0Ch;
        mov     ecx, esp;
        mov[esp + 32], esp;
        push    edx;
        push    0x5C9E1C;
        call    sub_402570;
        mov     eax, [esi];
        mov     ecx, esi;
        call    dword ptr[eax + 8];
        push    46h;
        lea     edx, [esp + 19];
        sub     esp, 0Ch;
        mov     ecx, esp;
        mov[esp + 32], esp;
        push    edx;
        push    0x5C9E50;
        call    sub_402570;
        mov     eax, [esi];
        mov     ecx, esi;
        call    dword ptr[eax + 8];
        push    3Ah;
        lea     edx, [esp + 19];
        sub     esp, 0Ch;
        mov     ecx, esp;
        mov     [esp + 32], esp;
        push    edx;
        push    0x5C9E4C;
        call    sub_402570;
        mov     eax, [esi];
        mov     ecx, esi;
        call    dword ptr[eax + 8];
        push    9Ah;
        lea     edx, [esp + 19];
        sub     esp, 0Ch;
        mov     ecx, esp;
        mov    [esp + 32], esp;
        push    edx;
        push    0x5C9E14;
        call    sub_402570;
        mov     eax, [esi];
        mov     ecx, esi;
        call    dword ptr[eax + 8];
        push    9Bh;
        lea     edx, [esp + 19];
        sub     esp, 0Ch;
        mov     ecx, esp;
        mov    [esp + 32], esp;
        push    edx;
        push    0x5C9E60;
        call    sub_402570;
        mov     eax, [esi];
        mov     ecx, esi;
        call    dword ptr[eax + 8];
        pop     edi;
        pop     esi;
        pop     ebx;
        add     esp, 14h;
        retn;

    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
        DWORD pid;
        HANDLE c;
        HANDLE snapshot;
        void* p;
        int t;
        char tmp[100];
        int t1;
        int addr_4938A2;
        int addr_4CFD29;
        unsigned char call_head;
    case DLL_PROCESS_ATTACH:
        char a[100];
        char a1[100];
        t = (int)new_weapon - 0x4e3d7c - 5;
        addr_4938A2 = 0x4E3D7C - 0x4938A2 - 5;
        addr_4CFD29 = 0x4E3D7C - 0x4CFD29 - 5;
        t1 = 0x90;
        call_head = 0xe8;

        //c = FindWindow(NULL,L"Meteor");
        //tid = GetProcessIdOfThread(c);    

        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
        if (Process32First(snapshot, &entry) == TRUE)
        {
            while (Process32Next(snapshot, &entry) == TRUE)
            {
                if (stricmp(entry.szExeFile, "Meteor.exe") == 0)
                {
                    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                    pid = GetProcessId(hProcess);
                    sprintf(a, "远程线程注入成功！%d", pid);
                    MessageBoxA(NULL, a, "提示", NULL);
                    WriteProcessMemory(hProcess, (LPVOID)0x4E3D7C, &call_head, 1, NULL);
                    WriteProcessMemory(hProcess, (LPVOID)0x4E3D7D, &t, 4, NULL);
                    WriteProcessMemory(hProcess, (LPVOID)0x4E3D81, &t1, 1, NULL);
                    WriteProcessMemory(hProcess, (LPVOID)0x4E3D82, &t1, 1, NULL);
                    WriteProcessMemory(hProcess, (LPVOID)0x4938A3, &addr_4938A2, 4, NULL);
                    WriteProcessMemory(hProcess, (LPVOID)0x4CFD2A, &addr_4CFD29, 4, NULL);
                    sprintf(a1, "偏移是%x", t);
                    MessageBoxA(NULL, a1, "提示", NULL);
                    CloseHandle(hProcess);
                }
            }
        }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

