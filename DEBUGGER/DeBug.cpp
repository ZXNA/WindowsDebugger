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
//1. 包含头文件
#include "keystone/keystone.h"

//2. 包含静态库

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
//全局进程线程句柄
HANDLE g_Process = nullptr;
HANDLE g_Thread = nullptr;
//定义一个vector来保存程序模块信息
struct MYMODULEINFO
{
	char ModuleName[MAX_PATH] = { 0 };
	LPVOID ModuleBaseAddr = nullptr;
};
vector<MYMODULEINFO> ModuleInfo;
//程序自动加载的模块
vector<LOAD_DLL_DEBUG_INFO> ProgModule;
//保存软件断点
struct SOFTBKINFO {
	BOOL sign = TRUE;
	LPVOID address;
	BYTE   oldData;// 保存int3断点覆盖的1字节数据
};
vector<SOFTBKINFO> SoftInfo;//用来存放所有的软件断点
//一个标志，用来判断是单步还是还原int3断点
bool Sign = FALSE;
//一个结构体用来保存断点信息
struct HARDBK
{
	int len;//硬件断点的长度
	int type;//硬件断点的类型
	DWORD Address;//硬件断点的地址
};
//这个数组用来保存所下的断点
HARDBK HardPoint[4] = { 0 };
//这个标志用来表明需不需要还原硬件断点
BOOL SignHard = FALSE;
//定义一个结构体用来保存条件断点
struct NOOD
{
	DWORD lpAddress;
	char buff[20];
	int val;
	BYTE OldCode;
};
//定义一个结构体动态数组
vector<NOOD> termNood;
BOOL SignTerm = FALSE;
//定义一个结构体用来保存内存断点
struct MEMORY
{
	DWORD Old;
	DWORD lpAddress;
	char type[20];
	BOOL Sign = FALSE;
};
//定义一个来保存内存断点
MEMORY MyMemory;
//保存一个旧的内存断点，用来还原
DWORD Old = 0;
//标志内存断点需不需要重新设置
BOOL MemSign = FALSE;
//用于控制台句柄
HANDLE HandleOut = GetStdHandle(STD_OUTPUT_HANDLE);
//一个动态数组用来存放LOADLIBRARY模块句柄
vector<HINSTANCE> vecMou;



//反反调试，HOOK掉API:NtQueryInformationProcess
void RePeb(void)
{

	HMODULE hmodule = LoadLibrary(_T("ntdll.dll"));
	LPVOID lpvoid = GetProcAddress(hmodule, ("NtQueryInformationProcess"));
	BYTE byte[5] = { 0XE9 };
	//开辟进程空间
	BYTE byte1[33] = { 0X8B,0X44,0X24,0X08,0X83,0XF8,0X07,0X75,0X0D,0X8B,0X44,
		0X24,0X0C,0XC7,0X00,0X00, 0X00,0X00,0X00,0XC2,0X14,0X00, 0XB8,0X19,
		0X00,0X00, 0X00, 0X68, 0X75, 0XA3, 0X77, 0X77, 0XC3 };
	*(DWORD *)(byte1 + 28) = (DWORD)((DWORD)lpvoid + 5);
	LPVOID address = VirtualAllocEx(g_Process, NULL, 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(g_Process, address, byte1, 33, NULL);
	*(DWORD*)(byte + 1) = (DWORD)address - (DWORD)lpvoid - 5;
	WriteProcessMemory(g_Process, lpvoid, byte, 5, NULL);
	
}
//隐藏PEB
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

//符号
void ShowSymbol(DWORD address)
{
	if (!SymInitialize(g_Process, NULL, FALSE))
	{
		printf("初始化符号失败！\n");
		return;
	}
	//加载模块符号文件
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
//控制台。。。。。。。
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
	printf("┃                              ┃");
}
//将指定块清空
void ClearBlock()
{
	int nPosx = 0;
	int nPosy = 49;
	LocationPos(nPosx, nPosy++);
	printf("                                                 \n");
	LocationPos(nPosx, nPosy++);
	printf("                                                 \n");
}
//清空缓冲区
void ClearLine(void)
{
	while (getchar() != '\n')
		continue;
}
//清空FilePath数组
void ClearArray(char *pFiePath, int len)
{
	for (int i = 0; i < len; ++i)
		pFiePath[i] = '\0';
}
//获取机器指令
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
//显示汇编代码
void ShowAsm(LPVOID address, int len = 10, int posx = 0, int posy = 13)
{
	//150个字节
	LPBYTE opcode = new BYTE[len * 15];
	SIZE_T dwRead = 0;
	//1、得到机器码
	if (!ReadProcessMemory(g_Process, address, opcode, len * 15, &dwRead))
	{
		printf("读取内存失败!\n");
		exit(-1);
	}
	//2、使用反汇编引擎获取机器码对应的汇编指令
	DISASM dasm = { 0 };
	////opcode的缓冲区地址
	dasm.EIP = (UIntPtr)opcode;
	////指令所在的地址
	dasm.VirtualAddr = (UINT64)address;
	////汇编指令的平台
#ifdef _WIN64
	dasm.Archi = 64;
#else
	dasm.Archi = 0;
#endif
	////进行输出
	int sum = 0;
	LPBYTE buff = new BYTE[MAX_PATH];
	//显示汇编界面
	LocationPos(posx, posy++);
	printf("┎────────────────────────────────────────────");
	while (len--)
	{
		int nLen = Disasm(&dasm);//获取得到的汇编指令的长度
		if (-1 == nLen)//nLen==-1表明机器码无法找到对应的汇编指令
			break;
		//待完善

		LocationPos(posx, posy++);
		printf("┃%I64X  ┃ ", dasm.VirtualAddr);
		GetOpcode(buff, sum, sum + nLen, opcode);
		sum += nLen;
		printf("  ┃  %-39s", dasm.CompleteInstr);
		if (len)
		{
			LocationPos(posx, posy++);
			printf("┃ ");        
		}
		dasm.VirtualAddr += nLen;
		dasm.EIP += nLen;
	}
	LocationPos(posx, posy++);
	printf("┖────────────────────────────────────────────\n");
}
//转换为机器指令
void Translate(char *pOpasm, LPVOID opaddress)
{
	ks_engine *pengine = nullptr;
	if (KS_ERR_OK != ks_open(KS_ARCH_X86, KS_MODE_32, &pengine))
	{
		printf("汇编引擎初始化失败\n");
		return;
	}
	int nRet = 0; // 保存函数的返回值，用于判断函数是否执行成功
	unsigned char* opcode = NULL; // 汇编得到的opcode的缓冲区首地址
	unsigned int nOpcodeSize = 0; // 汇编出来的opcode的字节数
	size_t stat_count = 0; // 保存成功汇编的指令的条数
	nRet = ks_asm(pengine, /* 汇编引擎句柄，通过ks_open函数得到*/
		pOpasm, /*要转换的汇编指令*/
		0, /*汇编指令所在的地址*/
		&opcode,/*输出的opcode*/
		&nOpcodeSize,/*输出的opcode的字节数*/
		&stat_count /*输出成功汇编的指令的条数*/
	);
	if (nRet == -1)
	{
		printf("汇编失败!\n");
		return;
	}
	//转换成功，将汇编指令写入内存
	SIZE_T WriteCount = 0;
	if (!WriteProcessMemory(g_Process, opaddress, opcode, nOpcodeSize, &WriteCount))
	{
		printf("写入内存失败!");
		exit(-1);
	}
}
//显示内存数据
DWORD ShowMemory(CONTEXT *Pct)
{
	//查看内存
	BYTE memory[512] = { 0 };
	ReadProcessMemory(g_Process, (LPCVOID)Pct->Eip, memory, 512, NULL);
	int posx = 0;
	int posy = 34;
	LocationPos(posx, posy++);
	printf("┎───────────────────────────────────┐");
	LocationPos(posx, posy++);
	printf("┃     地址     ┃                        数据                          ┃");
	LocationPos(posx, posy++);
	puts("┃───────────────────────────────────┃");
	DWORD lpMemory = Pct->Eip;
	for (int i = 0, j = 0; i < 5; ++i)
	{
		LocationPos(posx, posy++);
		printf("┃   %08X   ┃", lpMemory + i * 16);
		printf("  %08X  ┃  %08X  ┃  %08X  ┃  %08X  ┃\n", ((DWORD *)memory)[j],
			((DWORD *)memory)[j + 1], ((DWORD *)memory)[j + 2], ((DWORD *)memory)[j + 3]);
		j += 4;
		if (i != 4)
		{
			LocationPos(posx, posy++);
			puts("┃───────────────────────────────────┃");
		}
	}
	LocationPos(posx, posy++);
	printf("┖───────────────────────────────────┚\n");
	return 0;
}
//修改内存数据
void ShowNewMemory(DWORD lpMemory, DWORD pNewData)
{
	DWORD dwRead = 0;
	if (!WriteProcessMemory(g_Process, (LPVOID)lpMemory, &pNewData, sizeof(DWORD), &dwRead))
	{
		printf("写入内存失败\n");
		exit(-1);
	}
}
//显示栈中的数据
DWORD ShowStack(CONTEXT *Pct)
{
	//显示栈数据
	BYTE stack[512] = { 0 };
	ReadProcessMemory(g_Process, (LPCVOID)Pct->Esp, stack, 512, NULL);
	int posx = 50;
	int posy = 32;
	LocationPos(posx, posy++);
	printf("┎─────────────┐");
	LocationPos(posx, posy++);
	printf("┃     ESP    ┃    stack   ┃");
	LocationPos(posx, posy++);
	printf("┃─────────────┃");
	DWORD lpEsp = Pct->Esp;
	for (int i = 0; i < 10; ++i)
	{
		LocationPos(posx, posy++);
		printf("┃  %08X  ┃  %08X  ┃\n", lpEsp, ((DWORD *)stack)[i]);
		lpEsp = lpEsp + 4;
		if (i != 9)
		{
			LocationPos(posx, posy++);
			printf("┃─────────────┃\n");
		}
	}
	LocationPos(posx, posy++);
	printf("┖─────────────┚\n");
	return 0;
}
//查看寄存器
DWORD ShowReg(CONTEXT *Pct)
{
	int posx = 50;
	int posy = 10;
	LocationPos(posx, posy++);
	printf("┎───────────────┐");
	LocationPos(posx, posy++);
	printf("┃EAX: %08X   EBX: %08X ┃", Pct->Eax, Pct->Ebx);
	PrintChange(posx, posy);
	LocationPos(posx, posy++);
	printf("┃ECX: %08X   EDX: %08X ┃", Pct->Ecx, Pct->Edx);
	PrintChange(posx, posy);
	LocationPos(posx, posy++);
	printf("┃ESI: %08X   EDI: %08X ┃", Pct->Esi, Pct->Edi);
	PrintChange(posx, posy);
	LocationPos(posx, posy++);
	printf("┃ESP: %08X   EBP: %08X ┃", Pct->Esp, Pct->Ebp);
	PrintChange(posx, posy);
	LocationPos(posx, posy++);
	printf("┃CS : %08X   SS : %08X ┃", Pct->SegCs, Pct->SegSs);
	PrintChange(posx, posy);
	LocationPos(posx, posy++);
	printf("┃DS : %08X   ES : %08X ┃", Pct->SegDs, Pct->SegEs);
	PrintChange(posx, posy);
	LocationPos(posx, posy++);
	printf("┃FS : %08X   GS : %08X ┃", Pct->SegFs, Pct->SegGs);
	PrintChange(posx, posy);
	LocationPos(posx, posy++);
	printf("┃EIP: %08X                 ┃", Pct->Eip);
	LocationPos(posx, posy++);
	printf("┖───────────────┚");
	LocationPos(posx, posy++);
	puts("┎─────────────────────────────────┐");
	LocationPos(posx, posy++);
	puts("┃    OF     DF     IF     SF     ZF     AF     PF     CF           ┃");
	LocationPos(posx, posy++);
	printf("┃    %d      %d      %d      %d      %d      %d      %d      %d            ┃",
		(bool)(Pct->EFlags & 0x0800),
		(bool)(Pct->EFlags & 0x0400),
		(bool)(Pct->EFlags & 0x0200),
		(bool)(Pct->EFlags & 0x0080),
		(bool)(Pct->EFlags & 0x0040),
		(bool)(Pct->EFlags & 0x0010),
		(bool)(Pct->EFlags & 0x0004),
		(bool)(Pct->EFlags & 0x0001));
	LocationPos(posx, posy++);
	printf("┖─────────────────────────────────┚\n");
	return 0;
}
//修改寄存器
void ReReg(char * pbuff, DWORD dwNum, CONTEXT *pCt)
{
	//修改通用寄存器
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
	//修改段寄存器
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
	//修改位寄存器
	else if (!_stricmp(pbuff, "OF"))
	{
		if (dwNum)
			//说明要修改成1
			pCt->EFlags |= 0x0800;
		else
			pCt->EFlags &= 0xF7FF;
	}
	else if (!_stricmp(pbuff, "DF"))
	{
		if (dwNum)
			//说明要修改成1
			pCt->EFlags |= 0x0400;
		else
			pCt->EFlags &= 0xFBFF;
	}
	else if (!_stricmp(pbuff, "IF"))
	{
		if (dwNum)
			//说明要修改成1
			pCt->EFlags |= 0x0200;
		else
			pCt->EFlags &= 0x0D00;
	}
	else if (!_stricmp(pbuff, "SF"))
	{
		if (dwNum)
			//说明要修改成1
			pCt->EFlags |= 0x0080;
		else
			pCt->EFlags &= 0xFF7F;
	}
	else if (!_stricmp(pbuff, "ZF"))
	{
		if (dwNum)
			//说明要修改成1
			pCt->EFlags |= 0x0040;
		else
			pCt->EFlags &= 0xFFBF;
	}
	else if (!_stricmp(pbuff, "AF"))
	{
		if (dwNum)
			//说明要修改成1
			pCt->EFlags |= 0x0010;
		else
			pCt->EFlags &= 0xFFEF;
	}
	else if (!_stricmp(pbuff, "PF"))
	{
		if (dwNum)
			//说明要修改成1
			pCt->EFlags |= 0x0004;
		else
			pCt->EFlags &= 0xFFFB;
	}
	else if (!_stricmp(pbuff, "CF"))
	{
		if (dwNum)
			//说明要修改成1
			pCt->EFlags |= 0x0001;
		else
			pCt->EFlags &= 0xFFFE;
	}
}
//查看模块信息
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
	printf("┎─────────────────────────────────────────────┐\n");
	LocationPos(nPosx, nPosy++);
	printf("┃        模块名字      ┃  模块句柄  ┃                      模块基址                      ┃\n");
	BOOL Sign = FALSE;
	do
	{
		_wsetlocale(LC_ALL, L"chs");
		LocationPos(nPosx, nPosy++);
		wprintf(L"┃  %-18s  ", module.szModule);
		printf("┃  %08X  ", (DWORD)module.hModule);
		_wsetlocale(LC_ALL, L"chs");
		wprintf(L"┃  %-49s ┃\n", module.szExePath);
		MYMODULEINFO MyModule = { 0 };
		WideCharToMultiByte(CP_ACP, 0, module.szModule, _countof(module.szModule),
			MyModule.ModuleName, MAX_PATH, NULL, NULL);
		MyModule.ModuleBaseAddr = module.modBaseAddr;
		ModuleInfo.push_back(MyModule);
		if (Sign = Module32Next(hSnap, &module))
		{
			LocationPos(nPosx, nPosy++);
			puts("┃─────────────────────────────────────────────┃");
		}
	} while (Sign);
	LocationPos(nPosx, nPosy++);
	printf("┖─────────────────────────────────────────────┚\n");
}
//设置软件断点
void SetSoftBk(DWORD SoftBk)
{
	SOFTBKINFO Sbk = { 0 };
	SIZE_T dwRead = 0;
	if (!ReadProcessMemory(g_Process, (LPCVOID)SoftBk, &Sbk.oldData, 1, &dwRead))
	{
		puts("读取进程内存失败!\n");
		exit(0);
	}
	if (!WriteProcessMemory(g_Process, (LPVOID)SoftBk, "\xCC", 1, &dwRead))
	{
		puts("写入进程内存失败!\n");
		exit(0);
	}
	for (auto vec : SoftInfo)
	{
		//查看断点有没有相同，如果在相同的地址下断点，那么只保存一个
		if (vec.address == Sbk.address)
			return;
	}
	Sbk.sign = 1;
	Sbk.address = (LPVOID)SoftBk;
	SoftInfo.push_back(Sbk);
}
//设置单步
void SetBkTf(void)
{
	CONTEXT ct = { CONTEXT_CONTROL };
	if (!GetThreadContext(g_Thread, &ct))
	{
		puts("获取进程上下文失败");
		exit(-1);
	}
	//EFLAGS结构体中包含着详细信息
	EFLAGS* pEflags = (EFLAGS*)&ct.EFlags;
	pEflags->TF = 1;
	if (!SetThreadContext(g_Thread, &ct))
	{
		puts("设置进程上下文失败");
		exit(-1);
	}
}
//单步步过
void SetBkOv(void)
{
	CONTEXT ct = { CONTEXT_ALL };
	if (!GetThreadContext(g_Thread, &ct))
	{
		printf("获取线程环境控制块失败!\n");
		exit(-1);
	}
	//获取该条指令的汇编代码
	//15个字节
	LPBYTE opcode = new BYTE[32];
	SIZE_T dwRead = 0;
	//1、得到机器码
	if (!ReadProcessMemory(g_Process, (LPCVOID)ct.Eip, opcode, 32, &dwRead))
	{
		printf("读取内存失败!\n");
		exit(-1);
	}
	//2、使用反汇编引擎获取机器码对应的汇编指令
	DISASM dasm = { 0 };
	////opcode的缓冲区地址
	dasm.EIP = (UIntPtr)opcode;
	////指令所在的地址
	dasm.VirtualAddr = (UINT64)ct.Eip;
	////汇编指令的平台
#ifdef _WIN64
	dasm.Archi = 64;
#else
	dasm.Archi = 0;
#endif
	////进行输出
	DWORD len = 2;
	char strArry[MAX_PATH] = { 0 };
	while (len--)
	{
		int nLen = Disasm(&dasm);//获取得到的汇编指令的长度
		if (-1 == nLen)//nLen==-1表明机器码无法找到对应的汇编指令
			break;
		if (len == 1)
		{
			strcat_s(strArry, MAX_PATH, dasm.CompleteInstr);
			dasm.VirtualAddr += nLen;
			dasm.EIP += nLen;
		}
	}
	//单步步过
	//1、有call，在它的下一条指令处下一个软件断点
	BYTE PreCode = 0;
	if (!strncmp(strArry, "call", 4) || !strncmp(strArry, "rep", 3))
	{
		//该指令有call,下断点
		//1、得到机器码
		if (!ReadProcessMemory(g_Process, (LPCVOID)dasm.VirtualAddr, &PreCode, 1, &dwRead))
		{
			printf("读取内存失败!\n");
			exit(-1);
		}
		if (!WriteProcessMemory(g_Process, (LPVOID)dasm.VirtualAddr, "\xcc", 1, &dwRead))
		{
			printf("写入内存失败\n");
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
		//1、正常没有call，相当于一个步入
		SetBkTf();
		Sign = FALSE;
		SignHard = true;
	}
}
//暂时清除软件断点，以便让程序继续执行
void EraseBk(PVOID pAddress)
{
	SIZE_T dwWirte = 0;
	//遍历vector查找它的address
	for (auto &Sbk : SoftInfo)
	{
		if (Sbk.address == pAddress)
		{
			if (!WriteProcessMemory(g_Process, pAddress, &Sbk.oldData, 1, &dwWirte))
			{
				printf("写入进程内存失败\n");
				exit(-1);
			}
			CONTEXT ct = { CONTEXT_CONTROL };
			if (!GetThreadContext(g_Thread, &ct))
			{
				printf("获取线程上下文失败\n");
				exit(-1);
			}
			ct.Eip--;
			if (!SetThreadContext(g_Thread, &ct))
			{
				printf("设置线程上下文失败\n");
				exit(-1);
			}
			SetBkTf();
			Sign = TRUE;
		}
	}
}
//设置硬件执行断点
BOOL SetBkHardExe(LPVOID pBkHard)
{
	CONTEXT ct = {0 };
	ct.ContextFlags= CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;

	if (!GetThreadContext(g_Thread, &ct))
	{
		printf("获取线程环境控制块失败!\n");
		exit(-1);
	}
	DBG_REG7 *pDr7 = (DBG_REG7*)&ct.Dr7;
	DWORD RegNum = 0;
	if (!ct.Dr0)
	{
		//DR0没有被使用
		ct.Dr0 = (DWORD)pBkHard;
		pDr7->RW0 = 0;
		pDr7->L0 = 1;
		pDr7->LEN0 = 0;
		RegNum = 0;
	}
	else if (!ct.Dr1)
	{
		//DR1没有被使用
		ct.Dr1 = (DWORD)pBkHard;
		pDr7->RW1 = 0;
		pDr7->L1 = 1;
		pDr7->LEN1 = 0;
		RegNum = 1;
	}
	else if (!ct.Dr2)
	{
		//DR2没有被使用
		ct.Dr2 = (DWORD)pBkHard;
		pDr7->RW2 = 0;
		pDr7->L2 = 1;
		pDr7->LEN2 = 0;
		RegNum = 2;
	}
	else if (!ct.Dr3)
	{
		//DR4没有被使用
		ct.Dr3 = (DWORD)pBkHard;
		pDr7->RW3 = 0;
		pDr7->L3 = 1;
		pDr7->LEN3 = 0;
		RegNum = 3;
	}
	else
	{
		printf("无可用硬件断点寄存器\n");
		return FALSE;
	}
	if (!SetThreadContext(g_Thread, &ct))
	{
		printf("设置线程环境控制块失败!\n");
		exit(-1);
	}
	//走到这设置成功， 进行保存
	HardPoint[RegNum].Address = (DWORD)pBkHard;//保存地址
	HardPoint[RegNum].len = 1;//保存长度
	HardPoint[RegNum].type = 0;//保存类型
	return TRUE;
}
//设置硬件读写断点
BOOL SetBkHardRw(DWORD pBkHard, char * type, DWORD len)
{
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL };
	if (!GetThreadContext(g_Thread, &ct))
	{
		printf("获取线程环境控制块失败!\n");
		exit(-1);
	}
	//先对内存进行取整
	if (len == 2)
		pBkHard = pBkHard - pBkHard % 2;
	else if (len == 4)
		pBkHard = pBkHard - pBkHard % 4;
	DWORD dwType = 0;
	//是读还是读写
	if (!_stricmp(type, "w"))
		dwType = 1;
	else if (!_stricmp(type, "rw"))
		dwType = 3;
	//寄存器标号
	DWORD RegNum = 0;
	//判断寄存器有没有被使用
	DBG_REG7 *pDr7 = (DBG_REG7*)&ct.Dr7;
	if (!ct.Dr0)
	{
		//DR0没有被使用
		ct.Dr0 = (DWORD)pBkHard;
		pDr7->RW0 = dwType;
		pDr7->L0 = 1;
		pDr7->LEN0 = len - 1;
		RegNum = 0;
	}
	else if (!ct.Dr1)
	{
		//DR1没有被使用
		ct.Dr1 = (DWORD)pBkHard;
		pDr7->RW1 = dwType;
		pDr7->L1 = 1;
		pDr7->LEN1 = len - 1;
		RegNum = 1;
	}
	else if (!ct.Dr2)
	{
		//DR2没有被使用
		ct.Dr2 = (DWORD)pBkHard;
		pDr7->RW2 = dwType;
		pDr7->L2 = 1;
		pDr7->LEN2 = len - 1;
		RegNum = 2;
	}
	else if (!ct.Dr3)
	{
		//DR4没有被使用
		ct.Dr3 = (DWORD)pBkHard;
		pDr7->RW3 = dwType;
		pDr7->L3 = 1;
		pDr7->LEN3 = len - 1;
		RegNum = 3;
	}
	else
	{
		printf("无可用硬件断点寄存器\n");
		return FALSE;
	}
	if (!SetThreadContext(g_Thread, &ct))
	{
		printf("设置线程环境控制块失败!\n");
		exit(-1);
	}
	//走到这设置成功， 进行保存
	HardPoint[RegNum].Address = pBkHard;//保存地址
	HardPoint[RegNum].len = len;//保存长度
	HardPoint[RegNum].type = dwType;//保存类型
	return TRUE;
}
//SetBkHard
//参数1：断点地址
//参数2：断点类型
//参数3：断点长度
BOOL SetBkHard(LPVOID pBkHard, char *pKind, DWORD len)
{
	if (!_stricmp(pKind, "exc"))
	{
		//如果是执行断点，先检测长度是否符合要求
		if (1 != len)
			return FALSE;
		if (!SetBkHardExe(pBkHard))
			return FALSE;
	}
	else if (!_stricmp(pKind, "w") || !_stricmp(pKind, "rw"))
	{
		//如果是写入断点或者是读写断点
		if (len > 4)
			return FALSE;
		if (!SetBkHardRw((DWORD)pBkHard, pKind, len))
			return FALSE;
	}
	else
		return FALSE;
	return TRUE;
}
//判断条件断点
BOOL Deltrem(DWORD ExceptionAdd)
{
	//县遍历条件断点数组
	CONTEXT ct = { CONTEXT_FULL };
	GetThreadContext(g_Thread, &ct);
	BOOL tremSign = FALSE;
	//查找有没有条件断点
	for (auto vec : termNood)
	{
		//找到了
		if (vec.lpAddress == ExceptionAdd)
		{
			//先取消断点
			DWORD dwWrite = 0;
			if (!WriteProcessMemory(g_Process, (LPVOID)ExceptionAdd, &vec.OldCode, 1, &dwWrite))
			{
				printf("写入内存失败!\n");
				exit(-1);
			}
			ct.Eip--;
			if (!SetThreadContext(g_Thread, &ct))
			{
				printf("设置线程上下文失败\n");
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
//解析指定模块的导出表
void ExportInfo(LPVOID lpAddress)
{	
	DWORD dwRead = 0;
	//获得NT头的地址
	IMAGE_DOS_HEADER DosHead = { 0 };
	ReadProcessMemory(g_Process, lpAddress, &DosHead, sizeof(IMAGE_DOS_HEADER), &dwRead);
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(DosHead.e_lfanew + (DWORD)lpAddress);
	//获得导出表地址
	IMAGE_NT_HEADERS NtHead = { 0 };
	ReadProcessMemory(g_Process, pNt, &NtHead, sizeof(IMAGE_NT_HEADERS), &dwRead);
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(NtHead.OptionalHeader.DataDirectory[0].VirtualAddress + (DWORD)lpAddress);
	//获取导出表的内容
	IMAGE_EXPORT_DIRECTORY Export = { 0 };
	ReadProcessMemory(g_Process, pExport, &Export, sizeof(IMAGE_EXPORT_DIRECTORY), &dwRead);
	//获得到了地址表的首地址
	DWORD* funName = (DWORD*)((DWORD)lpAddress + Export.AddressOfNames);
	//找到序号表的首地址
	DWORD* NumAdress = (DWORD*)((DWORD)lpAddress + Export.AddressOfNameOrdinals);
	//找到地址表的首地址
	DWORD* funAdress = (DWORD*)((DWORD)lpAddress + Export.AddressOfFunctions);
	//输出相关信息
	printf("┎────────────────────────────────────────┐\n");
	printf("┃   序号  ┃                        函数名称                        ┃    RVA    ┃\n");
	puts("┃────────────────────────────────────────┃");
	INT nCount = 0;
	for (DWORD n = 0; n < Export.NumberOfNames && n < 10; ++n)
	{
		//获取地址标内容
		DWORD NameAddress = 0;
		ReadProcessMemory(g_Process, funName + n, &NameAddress, sizeof(DWORD), &dwRead);
		//名字的地址
		DWORD * True = (DWORD *)(NameAddress + (DWORD)lpAddress);
		char Name[MAX_PATH] = { 0 };
		ReadProcessMemory(g_Process, True, Name, MAX_PATH, &dwRead);
		//获取序号
		WORD num = 0;
		ReadProcessMemory(g_Process, NumAdress + n, &num, sizeof(WORD), &dwRead);
		//获取函数地址
		DWORD ThefunAddress = 0;
		ReadProcessMemory(g_Process, funAdress + num, &ThefunAddress, sizeof(DWORD), &dwRead);
		++nCount;
		printf("┃  %-04X   ┃", nCount);
		printf("%-56s┃", Name);
		printf("  %08X ┃\n", ThefunAddress);
		if (n != Export.NumberOfNames - 1 && n != 9)
			puts("┃────────────────────────────────────────┃");
	}
	printf("┖────────────────────────────────────────┚\n");
}
//解析指定模块的导入表
void ImportInfo(LPVOID lpAddress)
{
	DWORD dwRead = 0;
	//获得NT头的地址
	IMAGE_DOS_HEADER DosHead = { 0 };
	ReadProcessMemory(g_Process, lpAddress, &DosHead, sizeof(IMAGE_DOS_HEADER), &dwRead);
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(DosHead.e_lfanew + (DWORD)lpAddress);
	//获得导入表地址
	IMAGE_NT_HEADERS NtHead = { 0 };
	ReadProcessMemory(g_Process, pNt, &NtHead, sizeof(IMAGE_NT_HEADERS), &dwRead);
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(NtHead.OptionalHeader.DataDirectory[1].VirtualAddress + (DWORD)lpAddress);
	//获取导入表的内容
	IMAGE_IMPORT_DESCRIPTOR Import = { 0 };
	ReadProcessMemory(g_Process, pImport, &Import, sizeof(IMAGE_IMPORT_DESCRIPTOR), &dwRead);
	INT nCount = 0;
	printf("┎────────────────────────────────────────────────┐\n");
	printf("┃   序号  ┃                  文件名称                ┃                    函数名称             ┃\n");

	while (Import.Name)
	{
		//有值
		LPVOID FileName = (LPVOID)((DWORD)lpAddress + Import.Name);
		char Name[MAX_PATH] = { 0 };
		ReadProcessMemory(g_Process, FileName, Name, MAX_PATH, &dwRead);
		PIMAGE_THUNK_DATA MyFirstThunk = (PIMAGE_THUNK_DATA)((DWORD)lpAddress + Import.OriginalFirstThunk);
		IMAGE_THUNK_DATA Thunk = { 0 };
		ReadProcessMemory(g_Process, MyFirstThunk, &Thunk, sizeof(IMAGE_THUNK_DATA), &dwRead);
		INT n = 0;
		while (Thunk.u1.AddressOfData)
		{
			//先判断是不是函数名导出
			if (!IMAGE_SNAP_BY_ORDINAL(Thunk.u1.Function) && n < 10)
			{
				puts("┃────────────────────────────────────────────────┃");
				PIMAGE_IMPORT_BY_NAME funAddress = (PIMAGE_IMPORT_BY_NAME)((DWORD)lpAddress + Thunk.u1.AddressOfData);
				//1、导入文件名称地址
				PBYTE MyName = (PBYTE)malloc(sizeof(IMAGE_IMPORT_BY_NAME) + 256);
				memset(MyName, 0, sizeof(IMAGE_IMPORT_BY_NAME) + 256);
				ReadProcessMemory(g_Process, funAddress, MyName, sizeof(IMAGE_IMPORT_BY_NAME) + 256, &dwRead);

				printf("┃  %-04X   ┃", nCount + 1);
				printf("%-42s┃", Name);
				printf("%-41s┃\n", MyName + 2);
				++nCount;
				++n;
				free(MyName);
			}
			//获取下一个
			++MyFirstThunk;
			ReadProcessMemory(g_Process, MyFirstThunk, &Thunk, sizeof(IMAGE_THUNK_DATA), &dwRead);
		}
		++pImport;
		ReadProcessMemory(g_Process, pImport, &Import, sizeof(IMAGE_IMPORT_DESCRIPTOR), &dwRead);
	}
	printf("┖────────────────────────────────────────────────┚\n");
}
//更新内存寄存器栈
void ReShow(void)
{
	CONTEXT ct = { CONTEXT_ALL };
	if (!GetThreadContext(g_Thread, &ct))
	{
		printf("线程获取线程上下文失败！\n");
		exit(-1);
	}
	//显示内存数据
	ShowMemory(&ct);
	//显示栈数据
	ShowStack(&ct);
	//显示寄存器数据
	ShowReg(&ct);
}
//修复int3异常
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
//清空下方输入
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
//                                   框架   
//
//
//
//-----------------------------------------------------------------------------
//先遍历文件夹加载dll
void AddDll(void)
{
	//
	CString str = _T("C:\\Users\\TopSk\\Desktop\\DEBUGGER - 副本\\DEBUGGER");
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
//界面头
void SoftPage(void)
{
	//
	AddDll();
	puts("\n\n\n");
	puts("\t\t\t\t\t\t\t\t\t\t\t调试器");
	puts("\t\t\t\t\t\t\t\t--------------------------------------------------");
	puts("\t\t\t\t\t\t\t\tA：创建调试进程                    B：附加活动进程");
	printf("请选择:");
}

//根据用户的输入调用相应的API
void SelInvokApi(void)
{
	char ch = toupper(getchar());
	ClearLine();

	DWORD dwPid = 0;
	//用户选择了创建调试进程
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
				CreateProcessA(FilePath, NULL, NULL, NULL, NULL, DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,/*调试进程标志*/
					NULL, NULL, &si, &pi);
			if (bRet == FALSE) {
				printf("创建进程失败");
			}
			else
				break;
		}
		else if (ch == 'B')
		{
			printf("请输入PID;");
			scanf_s("%d", &dwPid);
			ClearLine();
			if (!DebugActiveProcess(dwPid))
			{
				puts("附加进程失败!\n");
				system("pause");
			}
			else
				break;
		}
	}
}

void RecvExceptionInfo(void);
//处理异常信息
DWORD OnException(EXCEPTION_RECORD * pExcept)
{
	//______________________________________________________________________//
	CONTEXT ct = { CONTEXT_FULL };
	static LPVOID RecentInt3;
	static LPVOID RecentHardExc;
	switch (pExcept->ExceptionCode)
	{
		//int3异常
		//一开始系统会自动调用，之后人为引发异常
	case EXCEPTION_BREAKPOINT:
	{
		ReShow();
		//定义一个静态变量，系统int3触发后，修改此变量
		static bool SignFirst = TRUE;
		if (SignFirst)
		{
			//HOOK关键API
			//现获取线程环境上下文
			//printf("系统断点: %08X\n", (INT)pExcept->ExceptionAddress);
			SignFirst = FALSE;
			RePeb();
			//隐藏PEB
			HidePeb();
		}
		else
		{

			//判断条件断点
			if (Deltrem((DWORD)pExcept->ExceptionAddress))
				break;
			//判断软件断点
			else if (!Repair((DWORD)pExcept->ExceptionAddress, RecentInt3))
			{
				//修复int3异常
				return DBG_CONTINUE;
			}
		}
		break;
	}
	case EXCEPTION_ACCESS_VIOLATION://内存访问异常
	{
	
		//取消内存断点
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
	//硬件断点和TF陷阱标志异常
	case EXCEPTION_SINGLE_STEP:
	{
		ReShow();
		CONTEXT ct = { 0 };
		ct.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
		if (!GetThreadContext(g_Thread, &ct))
		{
			printf("获取线程环境控制块失败!\n");
			exit(-1);
		}
		if (MemSign)
		{
			//重新设置内存断点
			VirtualProtectEx(g_Process, (LPVOID)MyMemory.lpAddress, 1, Old, &MyMemory.Old);
			MemSign = FALSE;
			return DBG_CONTINUE;
		}
		if (Sign && RecentInt3)
		{
			Sign = FALSE;
			//还原int3
			DWORD dwWrite = 0;
			if (!WriteProcessMemory(g_Process, RecentInt3, "\xCC", 1, &dwWrite))
			{
				puts("写入进程内存失败");
				exit(-1);
			}
			goto _DONE;
		}
		//先判断需不需要还原int3断点硬件断点
		if (SignHard)
		{
			for (int i = 0; i < 4; ++i)
			{
				if (!HardPoint[i].Address)
					continue;
				if (!HardPoint[i].type)
				{
					//该断点应该被还原
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
						printf("设置线程环境控制块失败!\n");
						exit(-1);
					}
				}
			}
			SignHard = FALSE;
		}
		DBG_REG6 * Reg6 = (DBG_REG6 *)&ct.Dr6;
		if (!Reg6->BS)
		{
			//硬件断下来
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
				//判断由 dwDr6Low 指定的DRX寄存器，是否是执行断点
				//将断点取消
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
						printf("设置线程环境控制块失败!\n");
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
		printf("被调试进程自身触发了异常：%08X\n", (INT)pExcept->ExceptionAddress);
		break;
	}
	}
	//获取产生异常的上下文
	if (!GetThreadContext(g_Thread, &ct))
	{
		printf("线程获取线程上下文失败！\n");
		exit(-1);
	}
	//显示汇编
	ShowAsm((LPVOID)ct.Eip, 10);
	//与用户进行交互
	while (TRUE)
	{
		char Cmd[100] = { 0 };
		int posx = 0;
		int posy = 49;
		LocationPos(posx, posy);
		printf("命令>>");
		scanf_s("%s", Cmd, 100);
		if (!_stricmp(Cmd, "rasm"))
		{
			//修改汇编
			DWORD dwAddreass = 0;
			//输入要修改的地址
			char opasm[MAX_PATH] = { 0 };
			scanf_s("%X", &dwAddreass);
			ClearLine();
			LocationPos(posx, ++posy);
			printf("输入汇编指令:");
			gets_s(opasm, MAX_PATH);
			//进行汇编
			Translate(opasm, (LPVOID)dwAddreass);
			//将指定位置清空
			ClearBlock();
		}
		else if (!_stricmp(Cmd, "asm"))
		{
			//查看汇编
			DWORD dwAddreass = 0;
			//输入要查看的地址
			scanf_s("%X", &dwAddreass);
			ClearLine();
			ClearBlock();
			ShowAsm((LPVOID)dwAddreass, 10, 0, 51);
		}
		else if (!_stricmp(Cmd, "rmem"))
		{
			//修改内存
			DWORD dwAddreass = 0;
			DWORD dwNewData = 0;
			//输入要查看的地址
			scanf_s("%X %X", &dwAddreass, &dwNewData);
			ClearLine();
			ClearBlock();
			ShowNewMemory((DWORD)dwAddreass, dwNewData);
			ShowMemory(&ct);
		}
		else if (!_stricmp(Cmd, "rreg"))
		{
			//修改寄存器
			char buff[MAX_PATH] = { 0 };
			DWORD dwNew = 0;
			scanf_s("%s %X", buff, MAX_PATH, &dwNew);
			ClearLine();
			ClearBlock();
			//对寄存器进行修改
			ReReg(buff, dwNew, &ct);
			SetThreadContext(g_Thread, &ct);
			ShowReg(&ct);
		}
		else if (!_stricmp(Cmd, "module"))
		{
			//查看模块信息
			LookForModule(&ct);
			ClearBlock();
		}
		else if (!_stricmp(Cmd, "bp"))
		{
			//设置软件断点
			DWORD SoftBk = 0;
			scanf_s("%X", &SoftBk);
			ClearBlock();
			//设置软件断点
			SetSoftBk(SoftBk);
		}
		//else if (!_stricmp(Cmd, "dbp"))
		//{
		//	//删除软件断点
		//	//1、先输出所有的软件断点
		//	INT n = 0;
		//	for (auto vec : SoftInfo)
		//	{
		//		if (vec.sign)
		//			printf("%d	%08X\n", ++n, (INT)vec.address);
		//	}
		//	if (n == 0)
		//	{
		//		printf("无可删除的选项!\n");
		//		continue;
		//	}
		//	DWORD num = 0;
		//	printf("删除的序号:");
		//	scanf_s("%d", &num);
		//	//先将此地址还原
		//	if (num <= SoftInfo.size())
		//	{
		//		DWORD dwWrite = 0;
		//		if (!WriteProcessMemory(g_Process, SoftInfo[num - 1].address, &SoftInfo[num - 1].oldData, 1, &dwWrite))
		//		{
		//			printf("删除断点失败!\n");
		//			exit(-1);
		//		}
		//		auto Beg = SoftInfo.begin();
		//		SoftInfo.erase(Beg + num - 1);
		//		printf("删除成功！\n");
		//	}
		//	else
		//		printf("序号输入有误!");
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
			//现获取地址，种类，长度
			DWORD address = 0;
			char Kind[MAX_PATH] = { 0 };
			DWORD len = 0;
			//输入
			printf("请输入断点地址，断点类型，断点长度:");
			scanf_s("%08X %s %d%*c", &address, Kind, MAX_PATH, &len);
			if (!SetBkHard((LPVOID)address, Kind, len))
				printf("设置硬件断点失败\n");
			ClearBlock();
		}
		//else if (!_stricmp(Cmd, "dhard"))
		//{
		//	//删除硬件断点
		//	//先显示目前的硬件断点
		//	DWORD nCount = 0;
		//	for (int i = 0; i < 4; ++i)
		//	{
		//		if (HardPoint[i].Address)
		//		{
		//			nCount += 1;
		//			printf("序号:%d	地址:%d ", i, HardPoint[i].Address);
		//			switch (HardPoint[i].type)
		//			{
		//			case 0:
		//				printf("类型:执行断点\n");
		//				break;
		//			case 1:
		//				printf("类型:写入断点\n");
		//				break;
		//			case 2:
		//				printf("类型:读写断点\n");
		//				break;
		//			}
		//		}
		//	}
		//	if (!nCount)
		//	{
		//		printf("没有断点!\n");
		//		continue;
		//	}
		//	printf("请输入要删除的下标:");
		//	DWORD num = 0;
		//	scanf_s("%d", &num);
		//	if (num < 4)
		//	{
		//		//有效的输入
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
		//		printf("无效的输入！\n");
		//	}
		//}
		else if (!_stricmp(Cmd, "p"))
		{
			//单步步过
			SetBkOv();
			ClearBlock();
			break;
		}
		else if (!_stricmp(Cmd, "pe"))
		{
			//输入模块名字
			char exportTable[MAX_PATH] = { 0 };
			char importTable[MAX_PATH] = { 0 };
			getchar();
			printf("输入模块名字:");
			scanf_s("%s %s", exportTable, MAX_PATH, importTable, MAX_PATH);
			for (auto vec : ModuleInfo)
			{
				if (!strcmp(vec.ModuleName, exportTable))
				{
					//解析导出表
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
			//条件断点
			printf("请输入地址,寄存器,数值:");
			NOOD term = { 0 };
			scanf_s("%08X %s %X%*c", &term.lpAddress, term.buff, 20, &term.val);
			//在这个地址上下一个int3断点
			DWORD dwRead = 0;
			if (!ReadProcessMemory(g_Process, (LPCVOID)term.lpAddress, &term.OldCode, 1, &dwRead))
			{
				printf("内存读取失败!\n");
				exit(-1);
			}
			if (!WriteProcessMemory(g_Process, (LPVOID)term.lpAddress, "\xCC", 1, &dwRead))
			{
				printf("写入内存失败!\n");
				exit(-1);
			}
			termNood.push_back(term);
		}
		else if (!_stricmp(Cmd, "bkmem"))
		{
			printf("输入内存地址与类型:");
			if (MyMemory.Sign)
				printf("已有内存断点，请删除!");
			else
			{
				scanf_s("%08X %s%*c", &MyMemory.lpAddress, MyMemory.type, 20);
				//设置断点
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
		//查看DLL函数
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
					//函数不是空
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


//接收调试事件

void RecvExceptionInfo(void)
{
	DEBUG_EVENT dbgEvent = { 0 };
	DWORD dwRetCode = DBG_CONTINUE;
	while (TRUE)
	{
		//1、等待调试事件,一直等下去
		WaitForDebugEvent(&dbgEvent, -1);
		g_Process = OpenProcess(PROCESS_ALL_ACCESS, 0, dbgEvent.dwProcessId);
		g_Thread = OpenThread(THREAD_ALL_ACCESS, 0, dbgEvent.dwThreadId);

		switch (dbgEvent.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			dwRetCode = OnException(&dbgEvent.u.Exception.ExceptionRecord);
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			//printf("被调试进程有进程被创建\n");
			break;
		case CREATE_THREAD_DEBUG_EVENT:

			//printf("被调试进程有一个新线程被创建\n");
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			//printf("被调试进程有一个进程退出\n");
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			//printf("被调试进程有一个线程退出\n");
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

