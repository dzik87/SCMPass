// 
// Generate superadmin password for SCM Maestro software
// 
// Reversed and coded by:
// Wojciech (dzik) Ankiersztejn
// 2022.04.14
//

#include <iostream>
#include <windows.h>

typedef DWORD (__cdecl* GetFuncs)(int nIdx);
typedef uint32_t(__cdecl* GetKey)(int nXor, int nModule);
typedef uint32_t(__cdecl* GetKey1)(int nXor, int nKey, int nModule);

void(__cdecl* GetFunc1_GenPassword)(int nXor, int nKey, int nModule, int nTimeout, byte* numArray, int nArrayLength);

// d2lua
static BOOL WriteBytes(LPVOID pAddr, VOID* pData, DWORD dwLen)
{
	DWORD dwOld;

	if (!VirtualProtect(pAddr, dwLen, PAGE_READWRITE, &dwOld))
		return FALSE;

	::memcpy(pAddr, pData, dwLen);
	return VirtualProtect(pAddr, dwLen, dwOld, &dwOld);
}

// stackoverflow
void SaveClipboard(char* text)
{
	HGLOBAL global = GlobalAlloc(GMEM_FIXED, strlen(text) + 1); //text size + \0 character
	if (global) {
		memcpy(global, text, strlen(text));  //text size + \0 character
		if (OpenClipboard(NULL))
		{
			EmptyClipboard();
			SetClipboardData(CF_TEXT, global);
			CloseClipboard();
		}
	}
}

enum Modules {
	module_MaestroWD = 0xA54F23,
	module_MaestroXCab = 0xE12A15,
	module_MaestroWDBase = 0x52A791,
	module_Maestro = 0xB43E32,
	module_MaestroWatch = 0xB43E25,
	module_Simulator = 0xDBD577,
	module_XilogParrot = 0x57DBD7,
	module_Xilog = 0x647C0A,
	module_HmiCnc = 0x297C1E,
	module_PassLogin = 0x63B8A2,
	module_PassGen = 0x419680,
	module_PassCheck32 = 0x63B832,
	module_PassCheck64 = 0x419664
};

// We need to return correct validating value for internal functions
int32_t __cdecl GetKey1Replacement(int nXor, int nKey, int nModule) {
	return 0x22AB69;
}

int main()
{
	// Load module
	HMODULE base = GetModuleHandleA("OptionsLog.dll");
	if (!base) {
		base = LoadLibraryA("OptionsLog.dll");
	}
	if (!base) {
		return 0;
	}

	// Use dll export to get function pointer
	GetFuncs getFuncs = (GetFuncs)GetProcAddress(base, "GetFuncs");
	if (!getFuncs)
		return 2;

	// Use dll export to get genetare key function
	GetKey getKey = (GetKey)GetProcAddress(base, "GetKey");
	if (!getKey)
		return 3;

	// Get
	DWORD getKey1 = (DWORD)GetProcAddress(base, "GetKey1");
	if (!getKey1)
		return 4;

	// Replace validating function
	byte PUSH = 0x68;
	WriteBytes((LPVOID)(getKey1 + 0), &PUSH, 1);
	DWORD ptr = (DWORD)(&GetKey1Replacement);
	WriteBytes((LPVOID)(getKey1 + 1), &ptr, 4);
	byte RET = 0xC3;
	WriteBytes((LPVOID)(getKey1 + 5), &RET, 1);

	// 0 - StartAutomation			void __cdecl GetFunc0_StartAutomation(int nXor,int nKey,int nModule)
	// 1 - GenPassword				void __cdecl GetFunc1_GenPassword(int nXor,int nKey,int nModule, int nTimeout, byte * numArray, int nArrayLength)
	// 2 - Login					void __cdecl GetFunc2_Login(int nXor,int nKey,int nModule, byte * pPassword, size_t nPasswordLength)
	// 3 - Logout					void __cdecl GetFunc3_Logout(int nXor,int nKey,int nModule)
	// 4 - WriteLog
	// 5 - ValidateFormatPassword
	// 6 - RefreshCounter
	*(DWORD*)&GetFunc1_GenPassword = getFuncs(1);

	// initialize function arguments
	const uint32_t nXor		= 12345;
	const uint32_t nModule	= module_PassGen;
	const uint32_t nKey		= getKey(nXor, nModule);

	// Prepare result buffer as per original app
	byte numArray[31];
	memset(numArray, 0, sizeof(numArray));

	// Generate password
  	GetFunc1_GenPassword(nXor, nKey, nModule, 0, numArray, sizeof(numArray));

	// Copy password to clipboard
	SaveClipboard((char*)&numArray);

	return 1;
}