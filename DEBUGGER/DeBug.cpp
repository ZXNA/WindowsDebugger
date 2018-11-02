#include "DeBug.h"
#include "stdafx.h"
#include "debugRegisters.h"
#include <vector>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <vector>
#include <String>
#include <winternl.h>
#include <Windows.h>
#include <atlstr.h>
#include <DbgHelp.h>
#pragma comment (lib, "Dbghelp.lib")
#pragma comment(lib, "ntdll.lib")
using namespace std;
#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL
//1. ����ͷ�ļ�
#include "keystone/keystone.h"

//2. ������̬��

#include "BeaEngine_4.1\\Win32\\headers\\BeaEngine.h"
#ifdef _WIN64
#pragma comment(lib,"BeaEngine_4.1\\Win64\\Win64\\Lib\\BeaEngine.lib")
#pragma comment (lib,"keystone/x64/keystone_x64.lib")
#else
#pragma comment(lib,"BeaEngine_4.1\\Win32\\Win32\\Lib\\BeaEngine.lib")
#pragma comment (lib,"keystone/x86/keystone_x86.lib")
#endif // _WIN32
#pragma comment(linker, "/NODEFAULTLIB:\"crt.lib\"")
#pragma comment(lib, "legacy_stdio_definitions.lib")

char FilePath[MAX_PATH] = { 0 };
//ȫ�ֽ����߳̾��
HANDLE g_Process = nullptr;
HANDLE g_Thread = nullptr;
//����һ��vector���������ģ����Ϣ
struct MYMODULEINFO
{
	char ModuleName[MAX_PATH] = { 0 };
	LPVOID ModuleBaseAddr = nullptr;
};
vector<MYMODULEINFO> ModuleInfo;
//�����Զ����ص�ģ��
vector<LOAD_DLL_DEBUG_INFO> ProgModule;
//��������ϵ�
struct SOFTBKINFO {
	BOOL sign = TRUE;
	LPVOID address;
	BYTE   oldData;// ����int3�ϵ㸲�ǵ�1�ֽ�����
};
vector<SOFTBKINFO> SoftInfo;//����������е�����ϵ�
//һ����־�������ж��ǵ������ǻ�ԭint3�ϵ�
bool Sign = FALSE;
//һ���ṹ����������ϵ���Ϣ
struct HARDBK
{
	int len;//Ӳ���ϵ�ĳ���
	int type;//Ӳ���ϵ������
	DWORD Address;//Ӳ���ϵ�ĵ�ַ
};
//������������������µĶϵ�
HARDBK HardPoint[4] = { 0 };
//�����־���������費��Ҫ��ԭӲ���ϵ�
BOOL SignHard = FALSE;
//����һ���ṹ���������������ϵ�
struct NOOD
{
	DWORD lpAddress;
	char buff[20];
	int val;
	BYTE OldCode;
};
//����һ���ṹ�嶯̬����
vector<NOOD> termNood;
BOOL SignTerm = FALSE;
//����һ���ṹ�����������ڴ�ϵ�
struct MEMORY
{
	DWORD Old;
	DWORD lpAddress;
	char type[20];
	BOOL Sign = FALSE;
};
//����һ���������ڴ�ϵ�
MEMORY MyMemory;
//����һ���ɵ��ڴ�ϵ㣬������ԭ
DWORD Old = 0;
//��־�ڴ�ϵ��費��Ҫ��������
BOOL MemSign = FALSE;
//���ڿ���̨���
HANDLE HandleOut = GetStdHandle(STD_OUTPUT_HANDLE);
//һ����̬�����������LOADLIBRARYģ����
vector<HINSTANCE> vecMou;



//�������ԣ�HOOK��API:NtQueryInformationProcess
void RePeb(void)
{

	HMODULE hmodule = LoadLibrary(_T("ntdll.dll"));
	LPVOID lpvoid = GetProcAddress(hmodule, ("NtQueryInformationProcess"));
	BYTE byte[5] = { 0XE9 };
	//���ٽ��̿ռ�
	BYTE byte1[33] = { 0X8B,0X44,0X24,0X08,0X83,0XF8,0X07,0X75,0X0D,0X8B,0X44,
		0X24,0X0C,0XC7,0X00,0X00, 0X00,0X00,0X00,0XC2,0X14,0X00, 0XB8,0X19,
		0X00,0X00, 0X00, 0X68, 0X75, 0XA3, 0X77, 0X77, 0XC3 };
	*(DWORD *)(byte1 + 28) = (DWORD)((DWORD)lpvoid + 5);
	LPVOID address = VirtualAllocEx(g_Process, NULL, 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(g_Process, address, byte1, 33, NULL);
	*(DWORD*)(byte + 1) = (DWORD)address - (DWORD)lpvoid - 5;
	WriteProcessMemory(g_Process, lpvoid, byte, 5, NULL);
	
}
//����PEB
void HidePeb(void)
{
	PROCESS_BASIC_INFORMATION stcProcess = { 0 };
	NtQueryInformationProcess(g_Process, ProcessBasicInformation, &stcProcess, sizeof(stcProcess), NULL);
	BYTE temp = '\0';
	WriteProcessMemory(g_Process, (LPVOID)&stcProcess.PebBaseAddress->BeingDebugged, &temp, 1, NULL);
}
//
BOOL GetSymName(SIZE_T nAddress, char *str)
{
	DWORD64 dwDisplacement = 0;
	char buff[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)] = { 0 };
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buff;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	//
	if (!SymFromAddr(g_Process, nAddress, &dwDisplacement, pSymbol))
	{
		return false;
	}
	strcpy_s(str, MAX_PATH, pSymbol->Name);
	return TRUE;
}

//����
void ShowSymbol(DWORD address)
{
	if (!SymInitialize(g_Process, NULL, FALSE))
	{
		printf("��ʼ������ʧ�ܣ�\n");
		return;
	}
	//����ģ������ļ�
	char buff[MAX_PATH] = { 0 };
	//vector<CString> str;
	for (auto vec : ProgModule)
	{
		SymLoadModule(g_Process, vec.hFile, NULL, NULL, (DWORD)vec.lpBaseOfDll, 0);
		if (GetSymName(address, buff))
		{
			printf("%s", buff);
			break;
		}
	}

}
//����̨��������������
void LocationPos(int nPosX, int nPosY)
{
	COORD PosRd;
	PosRd.X = nPosX * 2;
	PosRd.Y = nPosY;
	SetConsoleCursorPosition(HandleOut, PosRd);
}
void PrintChange(int& nPosX, int& nPosY)
{
	LocationPos(nPosX, nPosY++);
	printf("��                              ��");
}
//��ָ�������
void ClearBlock()
{
	int nPosx = 0;
	int nPosy = 49;
	LocationPos(nPosx, nPosy++);
	printf("                                                 \n");
	LocationPos(nPosx, nPosy++);
	printf("                                                 \n");
}
//��ջ�����
void ClearLine(void)
{
	while (getchar() != '\n')
		continue;
}
//���FilePath����
void ClearArray(char *pFiePath, int len)
{
	for (int i = 0; i < len; ++i)
		pFiePath[i] = '\0';
}
//��ȡ����ָ��
void GetOpcode(LPBYTE pbuff, int Beg, int End, LPBYTE pOpcode)
{
	ClearArray((char *)pbuff, MAX_PATH);
	int n = 0;
	while (Beg != End)
		pbuff[n++] = pOpcode[Beg++];
	n = 0;
	int nCount = 0;
	while (pbuff[n])
	{
		printf(" %02X", pbuff[n]);
		++n;
		nCount += 3;
	}
	while (nCount != 30)
	{
		putchar(' ');
		++nCount;
	}
}
//��ʾ������
void ShowAsm(LPVOID address, int len = 10, int posx = 0, int posy = 13)
{
	//150���ֽ�
	LPBYTE opcode = new BYTE[len * 15];
	SIZE_T dwRead = 0;
	//1���õ�������
	if (!ReadProcessMemory(g_Process, address, opcode, len * 15, &dwRead))
	{
		printf("��ȡ�ڴ�ʧ��!\n");
		exit(-1);
	}
	//2��ʹ�÷���������ȡ�������Ӧ�Ļ��ָ��
	DISASM dasm = { 0 };
	////opcode�Ļ�������ַ
	dasm.EIP = (UIntPtr)opcode;
	////ָ�����ڵĵ�ַ
	dasm.VirtualAddr = (UINT64)address;
	////���ָ���ƽ̨
#ifdef _WIN64
	dasm.Archi = 64;
#else
	dasm.Archi = 0;
#endif
	////�������
	int sum = 0;
	LPBYTE buff = new BYTE[MAX_PATH];
	//��ʾ������
	LocationPos(posx, posy++);
	printf("������������������������������������������������������������������������������������������");
	while (len--)
	{
		int nLen = Disasm(&dasm);//��ȡ�õ��Ļ��ָ��ĳ���
		if (-1 == nLen)//nLen==-1�����������޷��ҵ���Ӧ�Ļ��ָ��
			break;
		//������

		LocationPos(posx, posy++);
		printf("��%I64X  �� ", dasm.VirtualAddr);
		GetOpcode(buff, sum, sum + nLen, opcode);
		sum += nLen;
		printf("  ��  %-39s", dasm.CompleteInstr);
		if (len)
		{
			LocationPos(posx, posy++);
			printf("�� ");        
		}
		dasm.VirtualAddr += nLen;
		dasm.EIP += nLen;
	}
	LocationPos(posx, posy++);
	printf("������������������������������������������������������������������������������������������\n");
}
//ת��Ϊ����ָ��
void Translate(char *pOpasm, LPVOID opaddress)
{
	ks_engine *pengine = nullptr;
	if (KS_ERR_OK != ks_open(KS_ARCH_X86, KS_MODE_32, &pengine))
	{
		printf("��������ʼ��ʧ��\n");
		return;
	}
	int nRet = 0; // ���溯���ķ���ֵ�������жϺ����Ƿ�ִ�гɹ�
	unsigned char* opcode = NULL; // ���õ���opcode�Ļ������׵�ַ
	unsigned int nOpcodeSize = 0; // ��������opcode���ֽ���
	size_t stat_count = 0; // ����ɹ�����ָ�������
	nRet = ks_asm(pengine, /* �����������ͨ��ks_open�����õ�*/
		pOpasm, /*Ҫת���Ļ��ָ��*/
		0, /*���ָ�����ڵĵ�ַ*/
		&opcode,/*�����opcode*/
		&nOpcodeSize,/*�����opcode���ֽ���*/
		&stat_count /*����ɹ�����ָ�������*/
	);
	if (nRet == -1)
	{
		printf("���ʧ��!\n");
		return;
	}
	//ת���ɹ��������ָ��д���ڴ�
	SIZE_T WriteCount = 0;
	if (!WriteProcessMemory(g_Process, opaddress, opcode, nOpcodeSize, &WriteCount))
	{
		printf("д���ڴ�ʧ��!");
		exit(-1);
	}
}
//��ʾ�ڴ�����
DWORD ShowMemory(CONTEXT *Pct)
{
	//�鿴�ڴ�
	BYTE memory[512] = { 0 };
	ReadProcessMemory(g_Process, (LPCVOID)Pct->Eip, memory, 512, NULL);
	int posx = 0;
	int posy = 34;
	LocationPos(posx, posy++);
	printf("��������������������������������������������������������������������������");
	LocationPos(posx, posy++);
	printf("��     ��ַ     ��                        ����                          ��");
	LocationPos(posx, posy++);
	puts("��������������������������������������������������������������������������");
	DWORD lpMemory = Pct->Eip;
	for (int i = 0, j = 0; i < 5; ++i)
	{
		LocationPos(posx, posy++);
		printf("��   %08X   ��", lpMemory + i * 16);
		printf("  %08X  ��  %08X  ��  %08X  ��  %08X  ��\n", ((DWORD *)memory)[j],
			((DWORD *)memory)[j + 1], ((DWORD *)memory)[j + 2], ((DWORD *)memory)[j + 3]);
		j += 4;
		if (i != 4)
		{
			LocationPos(posx, posy++);
			puts("��������������������������������������������������������������������������");
		}
	}
	LocationPos(posx, posy++);
	printf("��������������������������������������������������������������������������\n");
	return 0;
}
//�޸��ڴ�����
void ShowNewMemory(DWORD lpMemory, DWORD pNewData)
{
	DWORD dwRead = 0;
	if (!WriteProcessMemory(g_Process, (LPVOID)lpMemory, &pNewData, sizeof(DWORD), &dwRead))
	{
		printf("д���ڴ�ʧ��\n");
		exit(-1);
	}
}
//��ʾջ�е�����
DWORD ShowStack(CONTEXT *Pct)
{
	//��ʾջ����
	BYTE stack[512] = { 0 };
	ReadProcessMemory(g_Process, (LPCVOID)Pct->Esp, stack, 512, NULL);
	int posx = 50;
	int posy = 32;
	LocationPos(posx, posy++);
	printf("������������������������������");
	LocationPos(posx, posy++);
	printf("��     ESP    ��    stack   ��");
	LocationPos(posx, posy++);
	printf("������������������������������");
	DWORD lpEsp = Pct->Esp;
	for (int i = 0; i < 10; ++i)
	{
		LocationPos(posx, posy++);
		printf("��  %08X  ��  %08X  ��\n", lpEsp, ((DWORD *)stack)[i]);
		lpEsp = lpEsp + 4;
		if (i != 9)
		{
			LocationPos(posx, posy++);
			printf("������������������������������\n");
		}
	}
	LocationPos(posx, posy++);
	printf("������������������������������\n");
	return 0;
}
//�鿴�Ĵ���
DWORD ShowReg(CONTEXT *Pct)
{
	int posx = 50;
	int posy = 10;
	LocationPos(posx, posy++);
	printf("����������������������������������");
	LocationPos(posx, posy++);
	printf("��EAX: %08X   EBX: %08X ��", Pct->Eax, Pct->Ebx);
	PrintChange(posx, posy);
	LocationPos(posx, posy++);
	printf("��ECX: %08X   EDX: %08X ��", Pct->Ecx, Pct->Edx);
	PrintChange(posx, posy);
	LocationPos(posx, posy++);
	printf("��ESI: %08X   EDI: %08X ��", Pct->Esi, Pct->Edi);
	PrintChange(posx, posy);
	LocationPos(posx, posy++);
	printf("��ESP: %08X   EBP: %08X ��", Pct->Esp, Pct->Ebp);
	PrintChange(posx, posy);
	LocationPos(posx, posy++);
	printf("��CS : %08X   SS : %08X ��", Pct->SegCs, Pct->SegSs);
	PrintChange(posx, posy);
	LocationPos(posx, posy++);
	printf("��DS : %08X   ES : %08X ��", Pct->SegDs, Pct->SegEs);
	PrintChange(posx, posy);
	LocationPos(posx, posy++);
	printf("��FS : %08X   GS : %08X ��", Pct->SegFs, Pct->SegGs);
	PrintChange(posx, posy);
	LocationPos(posx, posy++);
	printf("��EIP: %08X                 ��", Pct->Eip);
	LocationPos(posx, posy++);
	printf("����������������������������������");
	LocationPos(posx, posy++);
	puts("����������������������������������������������������������������������");
	LocationPos(posx, posy++);
	puts("��    OF     DF     IF     SF     ZF     AF     PF     CF           ��");
	LocationPos(posx, posy++);
	printf("��    %d      %d      %d      %d      %d      %d      %d      %d            ��",
		(bool)(Pct->EFlags & 0x0800),
		(bool)(Pct->EFlags & 0x0400),
		(bool)(Pct->EFlags & 0x0200),
		(bool)(Pct->EFlags & 0x0080),
		(bool)(Pct->EFlags & 0x0040),
		(bool)(Pct->EFlags & 0x0010),
		(bool)(Pct->EFlags & 0x0004),
		(bool)(Pct->EFlags & 0x0001));
	LocationPos(posx, posy++);
	printf("����������������������������������������������������������������������\n");
	return 0;
}
//�޸ļĴ���
void ReReg(char * pbuff, DWORD dwNum, CONTEXT *pCt)
{
	//�޸�ͨ�üĴ���
	if (!_stricmp(pbuff, "EAX"))
		pCt->Eax = dwNum;
	else if (!_stricmp(pbuff, "EBX"))
		pCt->Ebx = dwNum;
	else if (!_stricmp(pbuff, "ECX"))
		pCt->Ecx = dwNum;
	else if (!_stricmp(pbuff, "EDX"))
		pCt->Edx = dwNum;
	else if (!_stricmp(pbuff, "ESI"))
		pCt->Esi = dwNum;
	else if (!_stricmp(pbuff, "EDI"))
		pCt->Edi = dwNum;
	else if (!_stricmp(pbuff, "ESP"))
		pCt->Esp = dwNum;
	else if (!_stricmp(pbuff, "EBP"))
		pCt->Ebp = dwNum;
	//�޸ĶμĴ���
	else if (!_stricmp(pbuff, "CS"))
		pCt->SegCs = dwNum;
	else if (!_stricmp(pbuff, "SS"))
		pCt->SegSs = dwNum;
	else if (!_stricmp(pbuff, "DS"))
		pCt->SegDs = dwNum;
	else if (!_stricmp(pbuff, "ES"))
		pCt->SegEs = dwNum;
	else if (!_stricmp(pbuff, "FS"))
		pCt->SegFs = dwNum;
	else if (!_stricmp(pbuff, "GS"))
		pCt->SegGs = dwNum;
	//�޸�λ�Ĵ���
	else if (!_stricmp(pbuff, "OF"))
	{
		if (dwNum)
			//˵��Ҫ�޸ĳ�1
			pCt->EFlags |= 0x0800;
		else
			pCt->EFlags &= 0xF7FF;
	}
	else if (!_stricmp(pbuff, "DF"))
	{
		if (dwNum)
			//˵��Ҫ�޸ĳ�1
			pCt->EFlags |= 0x0400;
		else
			pCt->EFlags &= 0xFBFF;
	}
	else if (!_stricmp(pbuff, "IF"))
	{
		if (dwNum)
			//˵��Ҫ�޸ĳ�1
			pCt->EFlags |= 0x0200;
		else
			pCt->EFlags &= 0x0D00;
	}
	else if (!_stricmp(pbuff, "SF"))
	{
		if (dwNum)
			//˵��Ҫ�޸ĳ�1
			pCt->EFlags |= 0x0080;
		else
			pCt->EFlags &= 0xFF7F;
	}
	else if (!_stricmp(pbuff, "ZF"))
	{
		if (dwNum)
			//˵��Ҫ�޸ĳ�1
			pCt->EFlags |= 0x0040;
		else
			pCt->EFlags &= 0xFFBF;
	}
	else if (!_stricmp(pbuff, "AF"))
	{
		if (dwNum)
			//˵��Ҫ�޸ĳ�1
			pCt->EFlags |= 0x0010;
		else
			pCt->EFlags &= 0xFFEF;
	}
	else if (!_stricmp(pbuff, "PF"))
	{
		if (dwNum)
			//˵��Ҫ�޸ĳ�1
			pCt->EFlags |= 0x0004;
		else
			pCt->EFlags &= 0xFFFB;
	}
	else if (!_stricmp(pbuff, "CF"))
	{
		if (dwNum)
			//˵��Ҫ�޸ĳ�1
			pCt->EFlags |= 0x0001;
		else
			pCt->EFlags &= 0xFFFE;
	}
}
//�鿴ģ����Ϣ
void LookForModule(CONTEXT * pCt)
{
	DWORD dwPid = GetProcessId(g_Process);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
	MODULEENTRY32 module = { sizeof(MODULEENTRY32) };
	Module32First(hSnap, &module);
	ModuleInfo.clear();
	int nPosx = 0;
	int nPosy = 52;
	LocationPos(nPosx, nPosy++);
	printf("����������������������������������������������������������������������������������������������\n");
	LocationPos(nPosx, nPosy++);
	printf("��        ģ������      ��  ģ����  ��                      ģ���ַ                      ��\n");
	BOOL Sign = FALSE;
	do
	{
		_wsetlocale(LC_ALL, L"chs");
		LocationPos(nPosx, nPosy++);
		wprintf(L"��  %-18s  ", module.szModule);
		printf("��  %08X  ", (DWORD)module.hModule);
		_wsetlocale(LC_ALL, L"chs");
		wprintf(L"��  %-49s ��\n", module.szExePath);
		MYMODULEINFO MyModule = { 0 };
		WideCharToMultiByte(CP_ACP, 0, module.szModule, _countof(module.szModule),
			MyModule.ModuleName, MAX_PATH, NULL, NULL);
		MyModule.ModuleBaseAddr = module.modBaseAddr;
		ModuleInfo.push_back(MyModule);
		if (Sign = Module32Next(hSnap, &module))
		{
			LocationPos(nPosx, nPosy++);
			puts("����������������������������������������������������������������������������������������������");
		}
	} while (Sign);
	LocationPos(nPosx, nPosy++);
	printf("����������������������������������������������������������������������������������������������\n");
}
//��������ϵ�
void SetSoftBk(DWORD SoftBk)
{
	SOFTBKINFO Sbk = { 0 };
	SIZE_T dwRead = 0;
	if (!ReadProcessMemory(g_Process, (LPCVOID)SoftBk, &Sbk.oldData, 1, &dwRead))
	{
		puts("��ȡ�����ڴ�ʧ��!\n");
		exit(0);
	}
	if (!WriteProcessMemory(g_Process, (LPVOID)SoftBk, "\xCC", 1, &dwRead))
	{
		puts("д������ڴ�ʧ��!\n");
		exit(0);
	}
	for (auto vec : SoftInfo)
	{
		//�鿴�ϵ���û����ͬ���������ͬ�ĵ�ַ�¶ϵ㣬��ôֻ����һ��
		if (vec.address == Sbk.address)
			return;
	}
	Sbk.sign = 1;
	Sbk.address = (LPVOID)SoftBk;
	SoftInfo.push_back(Sbk);
}
//���õ���
void SetBkTf(void)
{
	CONTEXT ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(g_Thread, &ct))
	{
		puts("��ȡ����������ʧ��");
		exit(-1);
	}
	//EFLAGS�ṹ���а�������ϸ��Ϣ
	EFLAGS* pEflags = (EFLAGS*)&ct.EFlags;
	pEflags->TF = 1;
	if (!SetThreadContext(g_Thread, &ct))
	{
		puts("���ý���������ʧ��");
		exit(-1);
	}
}
//��������
void SetBkOv(void)
{
	CONTEXT ct = { CONTEXT_ALL };
	if (!GetThreadContext(g_Thread, &ct))
	{
		printf("��ȡ�̻߳������ƿ�ʧ��!\n");
		exit(-1);
	}
	//��ȡ����ָ��Ļ�����
	//15���ֽ�
	LPBYTE opcode = new BYTE[32];
	SIZE_T dwRead = 0;
	//1���õ�������
	if (!ReadProcessMemory(g_Process, (LPCVOID)ct.Eip, opcode, 32, &dwRead))
	{
		printf("��ȡ�ڴ�ʧ��!\n");
		exit(-1);
	}
	//2��ʹ�÷���������ȡ�������Ӧ�Ļ��ָ��
	DISASM dasm = { 0 };
	////opcode�Ļ�������ַ
	dasm.EIP = (UIntPtr)opcode;
	////ָ�����ڵĵ�ַ
	dasm.VirtualAddr = (UINT64)ct.Eip;
	////���ָ���ƽ̨
#ifdef _WIN64
	dasm.Archi = 64;
#else
	dasm.Archi = 0;
#endif
	////�������
	DWORD len = 2;
	char strArry[MAX_PATH] = { 0 };
	while (len--)
	{
		int nLen = Disasm(&dasm);//��ȡ�õ��Ļ��ָ��ĳ���
		if (-1 == nLen)//nLen==-1�����������޷��ҵ���Ӧ�Ļ��ָ��
			break;
		if (len == 1)
		{
			strcat_s(strArry, MAX_PATH, dasm.CompleteInstr);
			dasm.VirtualAddr += nLen;
			dasm.EIP += nLen;
		}
	}
	//��������
	//1����call����������һ��ָ���һ������ϵ�
	BYTE PreCode = 0;
	if (!strncmp(strArry, "call", 4) || !strncmp(strArry, "rep", 3))
	{
		//��ָ����call,�¶ϵ�
		//1���õ�������
		if (!ReadProcessMemory(g_Process, (LPCVOID)dasm.VirtualAddr, &PreCode, 1, &dwRead))
		{
			printf("��ȡ�ڴ�ʧ��!\n");
			exit(-1);
		}
		if (!WriteProcessMemory(g_Process, (LPVOID)dasm.VirtualAddr, "\xcc", 1, &dwRead))
		{
			printf("д���ڴ�ʧ��\n");
			exit(-1);
		}
		//
		for (auto vec : SoftInfo)
			if (vec.address == (LPVOID)dasm.VirtualAddr)
				return;
		SOFTBKINFO soft;
		soft.address = (LPVOID)dasm.VirtualAddr;
		soft.oldData = PreCode;
		soft.sign = FALSE;
		SoftInfo.push_back(soft);

		//SetBkTf();
		//Sign = TRUE;
	}
	else
	{
		//1������û��call���൱��һ������
		SetBkTf();
		Sign = FALSE;
		SignHard = true;
	}
}
//��ʱ�������ϵ㣬�Ա��ó������ִ��
void EraseBk(PVOID pAddress)
{
	SIZE_T dwWirte = 0;
	//����vector��������address
	for (auto &Sbk : SoftInfo)
	{
		if (Sbk.address == pAddress)
		{
			if (!WriteProcessMemory(g_Process, pAddress, &Sbk.oldData, 1, &dwWirte))
			{
				printf("д������ڴ�ʧ��\n");
				exit(-1);
			}
			CONTEXT ct = { CONTEXT_CONTROL };
			if (!GetThreadContext(g_Thread, &ct))
			{
				printf("��ȡ�߳�������ʧ��\n");
				exit(-1);
			}
			ct.Eip--;
			if (!SetThreadContext(g_Thread, &ct))
			{
				printf("�����߳�������ʧ��\n");
				exit(-1);
			}
			SetBkTf();
			Sign = TRUE;
		}
	}
}
//����Ӳ��ִ�жϵ�
BOOL SetBkHardExe(LPVOID pBkHard)
{
	CONTEXT ct = {0 };
	ct.ContextFlags= CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;

	if (!GetThreadContext(g_Thread, &ct))
	{
		printf("��ȡ�̻߳������ƿ�ʧ��!\n");
		exit(-1);
	}
	DBG_REG7 *pDr7 = (DBG_REG7*)&ct.Dr7;
	DWORD RegNum = 0;
	if (!ct.Dr0)
	{
		//DR0û�б�ʹ��
		ct.Dr0 = (DWORD)pBkHard;
		pDr7->RW0 = 0;
		pDr7->L0 = 1;
		pDr7->LEN0 = 0;
		RegNum = 0;
	}
	else if (!ct.Dr1)
	{
		//DR1û�б�ʹ��
		ct.Dr1 = (DWORD)pBkHard;
		pDr7->RW1 = 0;
		pDr7->L1 = 1;
		pDr7->LEN1 = 0;
		RegNum = 1;
	}
	else if (!ct.Dr2)
	{
		//DR2û�б�ʹ��
		ct.Dr2 = (DWORD)pBkHard;
		pDr7->RW2 = 0;
		pDr7->L2 = 1;
		pDr7->LEN2 = 0;
		RegNum = 2;
	}
	else if (!ct.Dr3)
	{
		//DR4û�б�ʹ��
		ct.Dr3 = (DWORD)pBkHard;
		pDr7->RW3 = 0;
		pDr7->L3 = 1;
		pDr7->LEN3 = 0;
		RegNum = 3;
	}
	else
	{
		printf("�޿���Ӳ���ϵ�Ĵ���\n");
		return FALSE;
	}
	if (!SetThreadContext(g_Thread, &ct))
	{
		printf("�����̻߳������ƿ�ʧ��!\n");
		exit(-1);
	}
	//�ߵ������óɹ��� ���б���
	HardPoint[RegNum].Address = (DWORD)pBkHard;//�����ַ
	HardPoint[RegNum].len = 1;//���泤��
	HardPoint[RegNum].type = 0;//��������
	return TRUE;
}
//����Ӳ����д�ϵ�
BOOL SetBkHardRw(DWORD pBkHard, char * type, DWORD len)
{
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL };
	if (!GetThreadContext(g_Thread, &ct))
	{
		printf("��ȡ�̻߳������ƿ�ʧ��!\n");
		exit(-1);
	}
	//�ȶ��ڴ����ȡ��
	if (len == 2)
		pBkHard = pBkHard - pBkHard % 2;
	else if (len == 4)
		pBkHard = pBkHard - pBkHard % 4;
	DWORD dwType = 0;
	//�Ƕ����Ƕ�д
	if (!_stricmp(type, "w"))
		dwType = 1;
	else if (!_stricmp(type, "rw"))
		dwType = 3;
	//�Ĵ������
	DWORD RegNum = 0;
	//�жϼĴ�����û�б�ʹ��
	DBG_REG7 *pDr7 = (DBG_REG7*)&ct.Dr7;
	if (!ct.Dr0)
	{
		//DR0û�б�ʹ��
		ct.Dr0 = (DWORD)pBkHard;
		pDr7->RW0 = dwType;
		pDr7->L0 = 1;
		pDr7->LEN0 = len - 1;
		RegNum = 0;
	}
	else if (!ct.Dr1)
	{
		//DR1û�б�ʹ��
		ct.Dr1 = (DWORD)pBkHard;
		pDr7->RW1 = dwType;
		pDr7->L1 = 1;
		pDr7->LEN1 = len - 1;
		RegNum = 1;
	}
	else if (!ct.Dr2)
	{
		//DR2û�б�ʹ��
		ct.Dr2 = (DWORD)pBkHard;
		pDr7->RW2 = dwType;
		pDr7->L2 = 1;
		pDr7->LEN2 = len - 1;
		RegNum = 2;
	}
	else if (!ct.Dr3)
	{
		//DR4û�б�ʹ��
		ct.Dr3 = (DWORD)pBkHard;
		pDr7->RW3 = dwType;
		pDr7->L3 = 1;
		pDr7->LEN3 = len - 1;
		RegNum = 3;
	}
	else
	{
		printf("�޿���Ӳ���ϵ�Ĵ���\n");
		return FALSE;
	}
	if (!SetThreadContext(g_Thread, &ct))
	{
		printf("�����̻߳������ƿ�ʧ��!\n");
		exit(-1);
	}
	//�ߵ������óɹ��� ���б���
	HardPoint[RegNum].Address = pBkHard;//�����ַ
	HardPoint[RegNum].len = len;//���泤��
	HardPoint[RegNum].type = dwType;//��������
	return TRUE;
}
//SetBkHard
//����1���ϵ��ַ
//����2���ϵ�����
//����3���ϵ㳤��
BOOL SetBkHard(LPVOID pBkHard, char *pKind, DWORD len)
{
	if (!_stricmp(pKind, "exc"))
	{
		//�����ִ�жϵ㣬�ȼ�ⳤ���Ƿ����Ҫ��
		if (1 != len)
			return FALSE;
		if (!SetBkHardExe(pBkHard))
			return FALSE;
	}
	else if (!_stricmp(pKind, "w") || !_stricmp(pKind, "rw"))
	{
		//�����д��ϵ�����Ƕ�д�ϵ�
		if (len > 4)
			return FALSE;
		if (!SetBkHardRw((DWORD)pBkHard, pKind, len))
			return FALSE;
	}
	else
		return FALSE;
	return TRUE;
}
//�ж������ϵ�
BOOL Deltrem(DWORD ExceptionAdd)
{
	//�ر��������ϵ�����
	CONTEXT ct = { CONTEXT_FULL };
	GetThreadContext(g_Thread, &ct);
	BOOL tremSign = FALSE;
	//������û�������ϵ�
	for (auto vec : termNood)
	{
		//�ҵ���
		if (vec.lpAddress == ExceptionAdd)
		{
			//��ȡ���ϵ�
			DWORD dwWrite = 0;
			if (!WriteProcessMemory(g_Process, (LPVOID)ExceptionAdd, &vec.OldCode, 1, &dwWrite))
			{
				printf("д���ڴ�ʧ��!\n");
				exit(-1);
			}
			ct.Eip--;
			if (!SetThreadContext(g_Thread, &ct))
			{
				printf("�����߳�������ʧ��\n");
				exit(-1);
			}
			tremSign = TRUE;
			if (!_stricmp(vec.buff, "EAX") && ct.Eax == vec.val || !_stricmp(vec.buff, "EBX") && ct.Ebx == vec.val ||
				!_stricmp(vec.buff, "ECX") && ct.Ecx == vec.val || !_stricmp(vec.buff, "EDX") && ct.Edx == vec.val ||
				!_stricmp(vec.buff, "ESI") && ct.Esi == vec.val || !_stricmp(vec.buff, "EDI") && ct.Edi == vec.val ||
				!_stricmp(vec.buff, "ESP") && ct.Esp == vec.val || !_stricmp(vec.buff, "EBP") && ct.Ebp == vec.val)
			{
				return TRUE;
			}
			else
			{
				//SetBkTf();
				//SignTerm = TRUE;
				return FALSE;
			}
		}
	}
	return FALSE;
}
//����ָ��ģ��ĵ�����
void ExportInfo(LPVOID lpAddress)
{	
	DWORD dwRead = 0;
	//���NTͷ�ĵ�ַ
	IMAGE_DOS_HEADER DosHead = { 0 };
	ReadProcessMemory(g_Process, lpAddress, &DosHead, sizeof(IMAGE_DOS_HEADER), &dwRead);
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(DosHead.e_lfanew + (DWORD)lpAddress);
	//��õ������ַ
	IMAGE_NT_HEADERS NtHead = { 0 };
	ReadProcessMemory(g_Process, pNt, &NtHead, sizeof(IMAGE_NT_HEADERS), &dwRead);
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(NtHead.OptionalHeader.DataDirectory[0].VirtualAddress + (DWORD)lpAddress);
	//��ȡ�����������
	IMAGE_EXPORT_DIRECTORY Export = { 0 };
	ReadProcessMemory(g_Process, pExport, &Export, sizeof(IMAGE_EXPORT_DIRECTORY), &dwRead);
	//��õ��˵�ַ����׵�ַ
	DWORD* funName = (DWORD*)((DWORD)lpAddress + Export.AddressOfNames);
	//�ҵ���ű���׵�ַ
	DWORD* NumAdress = (DWORD*)((DWORD)lpAddress + Export.AddressOfNameOrdinals);
	//�ҵ���ַ����׵�ַ
	DWORD* funAdress = (DWORD*)((DWORD)lpAddress + Export.AddressOfFunctions);
	//��������Ϣ
	printf("������������������������������������������������������������������������������������\n");
	printf("��   ���  ��                        ��������                        ��    RVA    ��\n");
	puts("������������������������������������������������������������������������������������");
	INT nCount = 0;
	for (DWORD n = 0; n < Export.NumberOfNames && n < 10; ++n)
	{
		//��ȡ��ַ������
		DWORD NameAddress = 0;
		ReadProcessMemory(g_Process, funName + n, &NameAddress, sizeof(DWORD), &dwRead);
		//���ֵĵ�ַ
		DWORD * True = (DWORD *)(NameAddress + (DWORD)lpAddress);
		char Name[MAX_PATH] = { 0 };
		ReadProcessMemory(g_Process, True, Name, MAX_PATH, &dwRead);
		//��ȡ���
		WORD num = 0;
		ReadProcessMemory(g_Process, NumAdress + n, &num, sizeof(WORD), &dwRead);
		//��ȡ������ַ
		DWORD ThefunAddress = 0;
		ReadProcessMemory(g_Process, funAdress + num, &ThefunAddress, sizeof(DWORD), &dwRead);
		++nCount;
		printf("��  %-04X   ��", nCount);
		printf("%-56s��", Name);
		printf("  %08X ��\n", ThefunAddress);
		if (n != Export.NumberOfNames - 1 && n != 9)
			puts("������������������������������������������������������������������������������������");
	}
	printf("������������������������������������������������������������������������������������\n");
}
//����ָ��ģ��ĵ����
void ImportInfo(LPVOID lpAddress)
{
	DWORD dwRead = 0;
	//���NTͷ�ĵ�ַ
	IMAGE_DOS_HEADER DosHead = { 0 };
	ReadProcessMemory(g_Process, lpAddress, &DosHead, sizeof(IMAGE_DOS_HEADER), &dwRead);
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(DosHead.e_lfanew + (DWORD)lpAddress);
	//��õ�����ַ
	IMAGE_NT_HEADERS NtHead = { 0 };
	ReadProcessMemory(g_Process, pNt, &NtHead, sizeof(IMAGE_NT_HEADERS), &dwRead);
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(NtHead.OptionalHeader.DataDirectory[1].VirtualAddress + (DWORD)lpAddress);
	//��ȡ����������
	IMAGE_IMPORT_DESCRIPTOR Import = { 0 };
	ReadProcessMemory(g_Process, pImport, &Import, sizeof(IMAGE_IMPORT_DESCRIPTOR), &dwRead);
	INT nCount = 0;
	printf("����������������������������������������������������������������������������������������������������\n");
	printf("��   ���  ��                  �ļ�����                ��                    ��������             ��\n");

	while (Import.Name)
	{
		//��ֵ
		LPVOID FileName = (LPVOID)((DWORD)lpAddress + Import.Name);
		char Name[MAX_PATH] = { 0 };
		ReadProcessMemory(g_Process, FileName, Name, MAX_PATH, &dwRead);
		PIMAGE_THUNK_DATA MyFirstThunk = (PIMAGE_THUNK_DATA)((DWORD)lpAddress + Import.OriginalFirstThunk);
		IMAGE_THUNK_DATA Thunk = { 0 };
		ReadProcessMemory(g_Process, MyFirstThunk, &Thunk, sizeof(IMAGE_THUNK_DATA), &dwRead);
		INT n = 0;
		while (Thunk.u1.AddressOfData)
		{
			//���ж��ǲ��Ǻ���������
			if (!IMAGE_SNAP_BY_ORDINAL(Thunk.u1.Function) && n < 10)
			{
				puts("����������������������������������������������������������������������������������������������������");
				PIMAGE_IMPORT_BY_NAME funAddress = (PIMAGE_IMPORT_BY_NAME)((DWORD)lpAddress + Thunk.u1.AddressOfData);
				//1�������ļ����Ƶ�ַ
				PBYTE MyName = (PBYTE)malloc(sizeof(IMAGE_IMPORT_BY_NAME) + 256);
				memset(MyName, 0, sizeof(IMAGE_IMPORT_BY_NAME) + 256);
				ReadProcessMemory(g_Process, funAddress, MyName, sizeof(IMAGE_IMPORT_BY_NAME) + 256, &dwRead);

				printf("��  %-04X   ��", nCount + 1);
				printf("%-42s��", Name);
				printf("%-41s��\n", MyName + 2);
				++nCount;
				++n;
				free(MyName);
			}
			//��ȡ��һ��
			++MyFirstThunk;
			ReadProcessMemory(g_Process, MyFirstThunk, &Thunk, sizeof(IMAGE_THUNK_DATA), &dwRead);
		}
		++pImport;
		ReadProcessMemory(g_Process, pImport, &Import, sizeof(IMAGE_IMPORT_DESCRIPTOR), &dwRead);
	}
	printf("����������������������������������������������������������������������������������������������������\n");
}
//�����ڴ�Ĵ���ջ
void ReShow(void)
{
	CONTEXT ct = { CONTEXT_ALL };
	if (!GetThreadContext(g_Thread, &ct))
	{
		printf("�̻߳�ȡ�߳�������ʧ�ܣ�\n");
		exit(-1);
	}
	//��ʾ�ڴ�����
	ShowMemory(&ct);
	//��ʾջ����
	ShowStack(&ct);
	//��ʾ�Ĵ�������
	ShowReg(&ct);
}
//�޸�int3�쳣
BOOL Repair(DWORD address, LPVOID &Recent)
{
	for (auto vec : SoftInfo)
	{
		if ((DWORD)vec.address == address)
		{
			Recent = vec.address;
			EraseBk(vec.address);
			return TRUE;
		}
	}
	return FALSE;
}
//����·�����
void ClearNextPut(void)
{
	for (int i = 50; i < 150; ++i)
	{
		for (int j = 0; j < 50; ++j)
		{
			LocationPos(j, i);
			puts("  ");
		}
	}
}






//-----------------------------------------------------------------------------
//
//
//
//                                   ���   
//
//
//
//-----------------------------------------------------------------------------
//�ȱ����ļ��м���dll
void AddDll(void)
{
	//
	CString str = _T("C:\\Users\\TopSk\\Desktop\\DEBUGGER - ����\\DEBUGGER");
	WIN32_FIND_DATA FileData = { 0 };

	HANDLE File = FindFirstFile(str + "\\*", &FileData);
	if (INVALID_HANDLE_VALUE == File)
		return;
	do
	{
		if (!_tcscmp(FileData.cFileName, _T(".")) || !_tcscmp(FileData.cFileName, _T("..")))
			continue;
		if (FileData.dwFileAttributes &FILE_ATTRIBUTE_DIRECTORY)
			continue;
		if (!_tcscmp(PathFindExtension(FileData.cFileName), _T(".dll")))
		{
			HINSTANCE hModule = LoadLibrary(FileData.cFileName);
			if (hModule)
				vecMou.push_back(hModule);
		}

	} while (FindNextFile(File, &FileData));
}
//����ͷ
void SoftPage(void)
{
	//
	AddDll();
	puts("\n\n\n");
	puts("\t\t\t\t\t\t\t\t\t\t\t������");
	puts("\t\t\t\t\t\t\t\t--------------------------------------------------");
	puts("\t\t\t\t\t\t\t\tA���������Խ���                    B�����ӻ����");
	printf("��ѡ��:");
}

//�����û������������Ӧ��API
void SelInvokApi(void)
{
	char ch = toupper(getchar());
	ClearLine();

	DWORD dwPid = 0;
	//�û�ѡ���˴������Խ���
	STARTUPINFOA si = { sizeof(STARTUPINFOA) };
	PROCESS_INFORMATION pi = { 0 };
	while (true)
	{
		if (ch == 'A')
		{
			wchar_t szFileName[MAX_PATH] = L"";
			OPENFILENAME ofn;

			ZeroMemory(&ofn, sizeof(OPENFILENAME));
			ofn.lStructSize = sizeof(OPENFILENAME);
			ofn.lpstrFile = szFileName;
			ofn.nMaxFile = MAX_PATH;
			ofn.lpstrFilter = L"Exe Files(*.exe)\0*.exe\0All Files(*.*)\0*.*\0\0";
			ofn.nFilterIndex = 1;
			GetOpenFileName(&ofn);
			WideCharToMultiByte(CP_ACP, 0, szFileName, _countof(szFileName), FilePath, MAX_PATH, NULL, NULL);
			BOOL bRet =
				CreateProcessA(FilePath, NULL, NULL, NULL, NULL, DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,/*���Խ��̱�־*/
					NULL, NULL, &si, &pi);
			if (bRet == FALSE) {
				printf("��������ʧ��");
			}
			else
				break;
		}
		else if (ch == 'B')
		{
			printf("������PID;");
			scanf_s("%d", &dwPid);
			ClearLine();
			if (!DebugActiveProcess(dwPid))
			{
				puts("���ӽ���ʧ��!\n");
				system("pause");
			}
			else
				break;
		}
	}
}

void RecvExceptionInfo(void);
//�����쳣��Ϣ
DWORD OnException(EXCEPTION_RECORD * pExcept)
{
	//______________________________________________________________________//
	CONTEXT ct = { CONTEXT_FULL };
	static LPVOID RecentInt3;
	static LPVOID RecentHardExc;
	switch (pExcept->ExceptionCode)
	{
		//int3�쳣
		//һ��ʼϵͳ���Զ����ã�֮����Ϊ�����쳣
	case EXCEPTION_BREAKPOINT:
	{
		ReShow();
		//����һ����̬������ϵͳint3�������޸Ĵ˱���
		static bool SignFirst = TRUE;
		if (SignFirst)
		{
			//HOOK�ؼ�API
			//�ֻ�ȡ�̻߳���������
			//printf("ϵͳ�ϵ�: %08X\n", (INT)pExcept->ExceptionAddress);
			SignFirst = FALSE;
			RePeb();
			//����PEB
			HidePeb();
		}
		else
		{

			//�ж������ϵ�
			if (Deltrem((DWORD)pExcept->ExceptionAddress))
				break;
			//�ж�����ϵ�
			else if (!Repair((DWORD)pExcept->ExceptionAddress, RecentInt3))
			{
				//�޸�int3�쳣
				return DBG_CONTINUE;
			}
		}
		break;
	}
	case EXCEPTION_ACCESS_VIOLATION://�ڴ�����쳣
	{
	
		//ȡ���ڴ�ϵ�
		VirtualProtectEx(g_Process, (LPVOID)MyMemory.lpAddress, 1, MyMemory.Old, &Old);
		SetBkTf();
		MemSign = TRUE;
		if ((ULONG_PTR)MyMemory.lpAddress == pExcept->ExceptionInformation[1])
		{	

			ReShow();
			break;
		}
		else
			return DBG_CONTINUE;
	}
	//Ӳ���ϵ��TF�����־�쳣
	case EXCEPTION_SINGLE_STEP:
	{
		ReShow();
		CONTEXT ct = { 0 };
		ct.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
		if (!GetThreadContext(g_Thread, &ct))
		{
			printf("��ȡ�̻߳������ƿ�ʧ��!\n");
			exit(-1);
		}
		if (MemSign)
		{
			//���������ڴ�ϵ�
			VirtualProtectEx(g_Process, (LPVOID)MyMemory.lpAddress, 1, Old, &MyMemory.Old);
			MemSign = FALSE;
			return DBG_CONTINUE;
		}
		if (Sign && RecentInt3)
		{
			Sign = FALSE;
			//��ԭint3
			DWORD dwWrite = 0;
			if (!WriteProcessMemory(g_Process, RecentInt3, "\xCC", 1, &dwWrite))
			{
				puts("д������ڴ�ʧ��");
				exit(-1);
			}
			goto _DONE;
		}
		//���ж��費��Ҫ��ԭint3�ϵ�Ӳ���ϵ�
		if (SignHard)
		{
			for (int i = 0; i < 4; ++i)
			{
				if (!HardPoint[i].Address)
					continue;
				if (!HardPoint[i].type)
				{
					//�öϵ�Ӧ�ñ���ԭ
					DBG_REG7 *pDr7 = (DBG_REG7*)&ct.Dr7;
					switch (i)
					{
					case 0:
						ct.Dr0 = (DWORD)HardPoint[i].Address;
						pDr7->RW0 = 0;
						pDr7->L0 = 1;
						pDr7->LEN0 = 0; break;

					case 1:
						ct.Dr0 = (DWORD)HardPoint[i].Address;
						pDr7->RW0 = 0;
						pDr7->L1 = 1;
						pDr7->LEN0 = 0; break;
					case 2:
						ct.Dr0 = (DWORD)HardPoint[i].Address;
						pDr7->RW0 = 0;
						pDr7->L2 = 1;
						pDr7->LEN0 = 0; break;
					case 3:
						ct.Dr0 = (DWORD)HardPoint[i].Address;
						pDr7->RW0 = 0;
						pDr7->L3 = 1;
						pDr7->LEN0 = 0; break;
					default:
						exit(-1);
					}
					if (!SetThreadContext(g_Thread, &ct))
					{
						printf("�����̻߳������ƿ�ʧ��!\n");
						exit(-1);
					}
				}
			}
			SignHard = FALSE;
		}
		DBG_REG6 * Reg6 = (DBG_REG6 *)&ct.Dr6;
		if (!Reg6->BS)
		{
			//Ӳ��������
			DWORD num = 0;
			if (Reg6->B0)
				num = 1;
			else if (Reg6->B1)
				num = 2;
			else if (Reg6->B2)
				num = 3;
			else if (Reg6->B3)
				num = 4;
			if (num)
			{
				//�ж��� dwDr6Low ָ����DRX�Ĵ������Ƿ���ִ�жϵ�
				//���ϵ�ȡ��
				if (HardPoint[num - 1].type == 0)
				{
					switch (num - 1)
					{
					case 0:
						ct.Dr7 &= 0xfffffffe;
						break;
					case 1:
						ct.Dr7 &= 0xfffffffb;
						break;
					case 2:
						ct.Dr7 &= 0xffffffef;
						break;
					case 3:
						ct.Dr7 &= 0xffffffbf;
						break;
					default:
						printf("Error!\r\n");
					}
					SetBkTf();
					if (!SetThreadContext(g_Thread, &ct))
					{
						printf("�����̻߳������ƿ�ʧ��!\n");
						exit(-1);
					}
					SignHard = TRUE;
				}
			}
		}
		break;
	}
	default:
	{
		printf("�����Խ������������쳣��%08X\n", (INT)pExcept->ExceptionAddress);
		break;
	}
	}
	//��ȡ�����쳣��������
	if (!GetThreadContext(g_Thread, &ct))
	{
		printf("�̻߳�ȡ�߳�������ʧ�ܣ�\n");
		exit(-1);
	}
	//��ʾ���
	ShowAsm((LPVOID)ct.Eip, 10);
	//���û����н���
	while (TRUE)
	{
		char Cmd[100] = { 0 };
		int posx = 0;
		int posy = 49;
		LocationPos(posx, posy);
		printf("����>>");
		scanf_s("%s", Cmd, 100);
		if (!_stricmp(Cmd, "rasm"))
		{
			//�޸Ļ��
			DWORD dwAddreass = 0;
			//����Ҫ�޸ĵĵ�ַ
			char opasm[MAX_PATH] = { 0 };
			scanf_s("%X", &dwAddreass);
			ClearLine();
			LocationPos(posx, ++posy);
			printf("������ָ��:");
			gets_s(opasm, MAX_PATH);
			//���л��
			Translate(opasm, (LPVOID)dwAddreass);
			//��ָ��λ�����
			ClearBlock();
		}
		else if (!_stricmp(Cmd, "asm"))
		{
			//�鿴���
			DWORD dwAddreass = 0;
			//����Ҫ�鿴�ĵ�ַ
			scanf_s("%X", &dwAddreass);
			ClearLine();
			ClearBlock();
			ShowAsm((LPVOID)dwAddreass, 10, 0, 51);
		}
		else if (!_stricmp(Cmd, "rmem"))
		{
			//�޸��ڴ�
			DWORD dwAddreass = 0;
			DWORD dwNewData = 0;
			//����Ҫ�鿴�ĵ�ַ
			scanf_s("%X %X", &dwAddreass, &dwNewData);
			ClearLine();
			ClearBlock();
			ShowNewMemory((DWORD)dwAddreass, dwNewData);
			ShowMemory(&ct);
		}
		else if (!_stricmp(Cmd, "rreg"))
		{
			//�޸ļĴ���
			char buff[MAX_PATH] = { 0 };
			DWORD dwNew = 0;
			scanf_s("%s %X", buff, MAX_PATH, &dwNew);
			ClearLine();
			ClearBlock();
			//�ԼĴ��������޸�
			ReReg(buff, dwNew, &ct);
			SetThreadContext(g_Thread, &ct);
			ShowReg(&ct);
		}
		else if (!_stricmp(Cmd, "module"))
		{
			//�鿴ģ����Ϣ
			LookForModule(&ct);
			ClearBlock();
		}
		else if (!_stricmp(Cmd, "bp"))
		{
			//��������ϵ�
			DWORD SoftBk = 0;
			scanf_s("%X", &SoftBk);
			ClearBlock();
			//��������ϵ�
			SetSoftBk(SoftBk);
		}
		//else if (!_stricmp(Cmd, "dbp"))
		//{
		//	//ɾ������ϵ�
		//	//1����������е�����ϵ�
		//	INT n = 0;
		//	for (auto vec : SoftInfo)
		//	{
		//		if (vec.sign)
		//			printf("%d	%08X\n", ++n, (INT)vec.address);
		//	}
		//	if (n == 0)
		//	{
		//		printf("�޿�ɾ����ѡ��!\n");
		//		continue;
		//	}
		//	DWORD num = 0;
		//	printf("ɾ�������:");
		//	scanf_s("%d", &num);
		//	//�Ƚ��˵�ַ��ԭ
		//	if (num <= SoftInfo.size())
		//	{
		//		DWORD dwWrite = 0;
		//		if (!WriteProcessMemory(g_Process, SoftInfo[num - 1].address, &SoftInfo[num - 1].oldData, 1, &dwWrite))
		//		{
		//			printf("ɾ���ϵ�ʧ��!\n");
		//			exit(-1);
		//		}
		//		auto Beg = SoftInfo.begin();
		//		SoftInfo.erase(Beg + num - 1);
		//		printf("ɾ���ɹ���\n");
		//	}
		//	else
		//		printf("�����������!");
		//}
		else if (!_stricmp(Cmd, "run"))
		{
			//SignHard = TRUE;
			//Sign = TRUE;
			//SetBkTf();
			ClearBlock();
			break;
		}
		else if (!_stricmp(Cmd, "t"))
		{
			SetBkTf();
			Sign = FALSE;
			SignHard = true;
			ClearBlock();
			break;
		}
		else if (!_stricmp(Cmd, "hard"))
		{
			//�ֻ�ȡ��ַ�����࣬����
			DWORD address = 0;
			char Kind[MAX_PATH] = { 0 };
			DWORD len = 0;
			//����
			printf("������ϵ��ַ���ϵ����ͣ��ϵ㳤��:");
			scanf_s("%08X %s %d%*c", &address, Kind, MAX_PATH, &len);
			if (!SetBkHard((LPVOID)address, Kind, len))
				printf("����Ӳ���ϵ�ʧ��\n");
			ClearBlock();
		}
		//else if (!_stricmp(Cmd, "dhard"))
		//{
		//	//ɾ��Ӳ���ϵ�
		//	//����ʾĿǰ��Ӳ���ϵ�
		//	DWORD nCount = 0;
		//	for (int i = 0; i < 4; ++i)
		//	{
		//		if (HardPoint[i].Address)
		//		{
		//			nCount += 1;
		//			printf("���:%d	��ַ:%d ", i, HardPoint[i].Address);
		//			switch (HardPoint[i].type)
		//			{
		//			case 0:
		//				printf("����:ִ�жϵ�\n");
		//				break;
		//			case 1:
		//				printf("����:д��ϵ�\n");
		//				break;
		//			case 2:
		//				printf("����:��д�ϵ�\n");
		//				break;
		//			}
		//		}
		//	}
		//	if (!nCount)
		//	{
		//		printf("û�жϵ�!\n");
		//		continue;
		//	}
		//	printf("������Ҫɾ�����±�:");
		//	DWORD num = 0;
		//	scanf_s("%d", &num);
		//	if (num < 4)
		//	{
		//		//��Ч������
		//		HardPoint[num].Address = 0;
		//		HardPoint[num].len = 0;
		//		HardPoint[num].type = 0;
		//		CONTEXT ct = { CONTEXT_FULL };
		//		GetThreadContext(g_Thread, &ct);
		//		ct.Dr0 = 0;
		//		DBG_REG7 *reg7 = (DBG_REG7*)&ct.Dr7;
		//		switch (num)
		//		{
		//		case 0:
		//			reg7->L0 = 0; break;
		//		case 1:
		//			reg7->L1 = 0; break;
		//		case 2:
		//			reg7->L2 = 0; break;
		//		case 3:
		//			reg7->L3 = 0; break;
		//		}
		//		SetThreadContext(g_Thread, &ct);
		//	}
		//	else
		//	{
		//		printf("��Ч�����룡\n");
		//	}
		//}
		else if (!_stricmp(Cmd, "p"))
		{
			//��������
			SetBkOv();
			ClearBlock();
			break;
		}
		else if (!_stricmp(Cmd, "pe"))
		{
			//����ģ������
			char exportTable[MAX_PATH] = { 0 };
			char importTable[MAX_PATH] = { 0 };
			getchar();
			printf("����ģ������:");
			scanf_s("%s %s", exportTable, MAX_PATH, importTable, MAX_PATH);
			for (auto vec : ModuleInfo)
			{
				if (!strcmp(vec.ModuleName, exportTable))
				{
					//����������
					ExportInfo(vec.ModuleBaseAddr);
				}
				else if (!strcmp(vec.ModuleName, importTable))
				{
					ImportInfo(vec.ModuleBaseAddr);
				}
			}
			ClearBlock();
		}
		else if (!_stricmp(Cmd, "term"))
		{
			//�����ϵ�
			printf("�������ַ,�Ĵ���,��ֵ:");
			NOOD term = { 0 };
			scanf_s("%08X %s %X%*c", &term.lpAddress, term.buff, 20, &term.val);
			//�������ַ����һ��int3�ϵ�
			DWORD dwRead = 0;
			if (!ReadProcessMemory(g_Process, (LPCVOID)term.lpAddress, &term.OldCode, 1, &dwRead))
			{
				printf("�ڴ��ȡʧ��!\n");
				exit(-1);
			}
			if (!WriteProcessMemory(g_Process, (LPVOID)term.lpAddress, "\xCC", 1, &dwRead))
			{
				printf("д���ڴ�ʧ��!\n");
				exit(-1);
			}
			termNood.push_back(term);
		}
		else if (!_stricmp(Cmd, "bkmem"))
		{
			printf("�����ڴ��ַ������:");
			if (MyMemory.Sign)
				printf("�����ڴ�ϵ㣬��ɾ��!");
			else
			{
				scanf_s("%08X %s%*c", &MyMemory.lpAddress, MyMemory.type, 20);
				//���öϵ�
				VirtualProtectEx(g_Process, (LPVOID)MyMemory.lpAddress, 1, PAGE_NOACCESS, &MyMemory.Old);
			}
			ClearBlock();
		}
		else if (!_stricmp(Cmd, "cls"))
		{
			system("cls");
			ReShow();
			ShowAsm((LPVOID)ct.Eip, 10);
			ClearBlock();
		}
		//�鿴DLL����
		else if (!_stricmp(Cmd, "sym"))
		{
			DWORD nAddress;
			scanf_s("%X", &nAddress);
			ShowSymbol(nAddress);
			ClearBlock();
		}
		else
		{
			typedef BOOL(*PFUN)(const char *, DWORD);
			for (auto vec : vecMou)
			{
				LPVOID lpvoid = GetProcAddress(vec, "TalkWithUser");
				if (lpvoid)
				{
					//�������ǿ�
					DWORD pId = GetCurrentProcessId();
					PFUN pfun = (PFUN)lpvoid;
					pfun(Cmd, pId);
				}
			}
			
		}
		ClearBlock();
	}
_DONE:
	return DBG_CONTINUE;
}


//���յ����¼�

void RecvExceptionInfo(void)
{
	DEBUG_EVENT dbgEvent = { 0 };
	DWORD dwRetCode = DBG_CONTINUE;
	while (TRUE)
	{
		//1���ȴ������¼�,һֱ����ȥ
		WaitForDebugEvent(&dbgEvent, -1);
		g_Process = OpenProcess(PROCESS_ALL_ACCESS, 0, dbgEvent.dwProcessId);
		g_Thread = OpenThread(THREAD_ALL_ACCESS, 0, dbgEvent.dwThreadId);

		switch (dbgEvent.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			dwRetCode = OnException(&dbgEvent.u.Exception.ExceptionRecord);
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			//printf("�����Խ����н��̱�����\n");
			break;
		case CREATE_THREAD_DEBUG_EVENT:

			//printf("�����Խ�����һ�����̱߳�����\n");
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			//printf("�����Խ�����һ�������˳�\n");
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			//printf("�����Խ�����һ���߳��˳�\n");
			break;
		case LOAD_DLL_DEBUG_EVENT:
			ProgModule.push_back(dbgEvent.u.LoadDll);
		case UNLOAD_DLL_DEBUG_EVENT:
		case OUTPUT_DEBUG_STRING_EVENT: break;
		case RIP_EVENT: break;

		}
		CloseHandle(g_Process);
		CloseHandle(g_Thread);
		ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, dwRetCode);
	}
}

