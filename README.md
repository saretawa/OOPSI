Patches AMSI and ETW in your parent shell process so Defender stops seeing what you run.

How it works

Walks the PEB to find `LoadLibrary` and `GetProcAddress`, uses those to resolve everything else at runtime no suspicious imports. Finds the parent shell via process snapshot, opens it, and patches `AmsiScanBuffer` and `EtwEventWrite` with ret instructions. All cross-process, all in memory.

Bypasses Windows Defender as of November 2026.

Build

Open in Visual Studio → Release x64 → Build or just go into releases and just download it.

Run from `cmd` or `PowerShell` it patches whichever shell launched it.

```
.\OOPSI.exe
```

That's it.

Test AMSI with this sample in powershell:
```
'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'
```
if AMSI is still enabled it should trigger
