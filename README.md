# Remote-IAT-Parser

Parsing the Import Address Table (IAT) of a running process



## Usage

```bash
Usage: parse_remote_iat.exe <process name>
```


**Example**

```bash
parse_remote_iat.exe notepad.exe

============= DLL: KERNEL32.dll =============

GetProcAddress:  0x7ffa3a44aec0
CreateMutexExW:  0x7ffa3a454990
AcquireSRWLockShared:  0x7ffa3a7d1760
DeleteCriticalSection:  0x7ffa3a7c0fc0
GetCurrentProcessId:  0x7ffa3a454890

***
***
```





