#pragma once
#include <ntddk.h>
#include <wdf.h>

typedef struct _LDR_DATA_TABLE_ENTRY_LOAD {
	PVOID Reserved1[2];
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_LOAD, *PLDR_DATA_TABLE_ENTRY_LOAD;


typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef void(__stdcall * PPS_POST_PROCESS_INIT_ROUTINE)();

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	BYTE                          Reserved4[104];
	PVOID                         Reserved5[52];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE                          Reserved6[128];
	PVOID                         Reserved7[1];
	ULONG                         SessionId;
} PEB, *PPEB;

ULONG64 GetKernel32Base() {
	ULONG64 tib = __readgsqword(0x30);
	PPEB peb = *(PPEB*)(tib + 0x60);
	// process owner, ntdll, kernel32
	PLDR_DATA_TABLE_ENTRY_LOAD entry = (PLDR_DATA_TABLE_ENTRY_LOAD)peb->Ldr->InLoadOrderModuleList.Flink->Flink->Flink;
	return (ULONG64)entry->DllBase;
}