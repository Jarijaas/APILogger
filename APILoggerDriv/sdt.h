#pragma once

// Based on https://github.com/conix-security/zer0m0n
// Some changes were made to get it working on Win 10 Build 17134 RS4

#include "ntfill.h"

#include <intrin.h> // cr0 read/write
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Unsets WP bit of CR0 register (allows writing into SSDT).
//		See http://en.wikipedia.org/wiki/Control_register#CR0
//	Parameters :
//		None
//	Return value :
//		KIRQL : current IRQL value
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
KIRQL WPOFF()
{
	KIRQL Irql = KeRaiseIrqlToDpcLevel();
	UINT_PTR cr0 = __readcr0();

	cr0 &= ~0x10000; // Set 16th LSB bit to 0
	__writecr0(cr0);
	_disable();

	return Irql;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Sets WP bit of CR0 register.
//	Parameters :
//		None
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID WPON(KIRQL Irql)
{
	UINT_PTR cr0 = __readcr0();

	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);

	KeLowerIrql(Irql);
}


/* The structure representing the System Service Table. */
typedef struct SystemServiceTable {
	UINT32* 	ServiceTable;
	UINT64* 	CounterTable;
	UINT64		ServiceLimit;
	UINT64*     ArgumentTable;
} SST;


SST *g_sst = NULL;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieve KeServiceDescriptorTable address
//	Parameters :
//		None
//	Return value :
//		ULONGLONG : The service descriptor table address 
//	Process :
//		Since KeServiceDescriptorTable isn't an exported symbol anymore, we have to retrieve it. 
//		When looking at the disassembly version of nt!KiSystemServiceRepeat, we can see interesting instructions :
//			4c8d15c7202300	lea r10, [nt!KeServiceDescriptorTable (addr)]    => it's the address we are looking for (:
//			4c8d1d00212300	lea r11, [nt!KeServiceDescriptorTableShadow (addr)]
//			f7830001000080  test dword ptr[rbx+100h], 80h
//
//		Furthermore, the LSTAR MSR value (at 0xC0000082) is initialized with nt!KiSystemCall64, which is a function 
//		close to nt!KiSystemServiceRepeat. We will begin to search from this address, the opcodes 0x83f7, the ones 
//		after the two lea instructions, once we get here, we can finally retrieve the KeServiceDescriptorTable address 
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONGLONG GetKeServiceDescriptorTable64()
{
	PUCHAR      pStartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR      pEndSearchAddress = (PUCHAR)(((ULONG_PTR)pStartSearchAddress - 1028 * PAGE_SIZE) & (~(PAGE_SIZE - 1)));
	PULONG      pFindCodeAddress = NULL;
	ULONG_PTR   pKeServiceDescriptorTable;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "pStartSearchAddress is %x.\r\n", pStartSearchAddress));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "pEndSearchAddress is %x.\r\n", pEndSearchAddress));

	while (--pStartSearchAddress > pEndSearchAddress)
	{

		//KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Search %x.\r\n", pStartSearchAddress));
		if (*(PULONG)pStartSearchAddress == 0x807843F7)
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Found at %x.\r\n", pStartSearchAddress));
			UINT32 relAddr = *(PUINT32)(pStartSearchAddress - 14 + 3);
			UINT64 absAddr = (UINT64)(pStartSearchAddress - 7 + relAddr);
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "relAddress is %x.\r\n", relAddr));
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "absAddress is %x.\r\n", absAddr));
			return absAddr;
		}
	}
	return 0;
}


ULONG64 GetNtFuncByServiceIndex(UINT16 serviceIndex) {
	return (ULONG64)(g_sst->ServiceTable[serviceIndex] >> 4) + (ULONG64)g_sst->ServiceTable;
}



typedef struct _SYSTEM_MODULE
{
	PVOID Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

// https://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FSYSTEM_MODULE_INFORMATION.html
typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG ModulesCount;
	SYSTEM_MODULE Modules[];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

#define SystemModuleInformation 11



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Retrieve kernel base address
//	Parameters :
//		None
//	Return value :
//		PVOID : the kernel base address
//	Process :
//		Retrieve the ntoskrnl module and returns its base address
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////   
UINT64 GetKernelBase()
{
	UNICODE_STRING funcAddr;
	ULONG ulNeededSize = 0, ModuleCount;
	PVOID pBuffer;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation = NULL;
	PSYSTEM_MODULE pSystemModule = NULL;
	PVOID imgBaseAddr;

	ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, &ulNeededSize, 0, &ulNeededSize);
	if (ulNeededSize)
	{
		pBuffer = ExAllocatePoolWithTag(NonPagedPool, ulNeededSize, 'klmP');
		if (NT_SUCCESS(ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, pBuffer, ulNeededSize, &ulNeededSize)))
		{
			pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
			pSystemModule = &pSystemModuleInformation->Modules[0];
			return (UINT64)pSystemModule->Base;
		}
		else
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ZwQuerySystemInformation failed !\n"));
	}
	else
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ZwQuerySystemInformation failed !\n"));
	return 0;
}

UINT16 GetServiceIndex(PVOID zwFunc) {
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "zw addr %x.\r\n", zwFunc));
	return *(PUINT16)((UINT64)zwFunc + 21);
}


/*
 * Required information for hooking ZwQuerySystemInformation.
 */

typedef NTSTATUS(*ZwQuerySystemInformationPrototype)(
	ULONG SystemInformationCLass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

ZwQuerySystemInformationPrototype oldZwQuerySystemInformation = NULL;


/*
 * Hook Function.
 */
NTSTATUS Hook_ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
	/* local variables */
	NTSTATUS status;

	/* calling new instructions */
	// KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ZwQuerySystemInformation hook called.\r\n"));

	/* calling old function */
	status = oldZwQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "The call to original ZwQuerySystemInformation did not succeed.\r\n"));
	}
	return status;
}

#define CC_PADDING 0xCCCCCCCC

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Retrieve 12 bytes of free space in order to use that space as trampoline 
//	Parameters :
//		PUCHAR pStartSearchAddress : address where we will begin to search for 12 bytes of code cave
//	Return value :
//		PVOID : address of the code cave found
//	Process :
//		Search for 12 successive bytes at 0x00 from the address given in argument and returns the address found
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
UINT64 SearchCodeCave(UINT64 pStartSearchAddress)
{
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "searchCodeCave pStartSearchAddress : %llx\n", pStartSearchAddress));

	while (pStartSearchAddress++)
	{
		if (MmIsAddressValid((PVOID)pStartSearchAddress))
		{
			if (*(PULONG)pStartSearchAddress == CC_PADDING
				&& *(PULONG)(pStartSearchAddress + 4) == CC_PADDING
				&& *(PULONG)(pStartSearchAddress + 8) == CC_PADDING)
				return pStartSearchAddress - 1;
		}
	}
	return 0;
}

/*
 * SSDT HOOK POC using ZwQuerySystemInformation
 * Tested on Win 10 Build 17134 RS4
 */
void SSDTHookPOC(UINT64 hookAddr) {
	/* local variables */
	PUINT32 ssdt;

	UINT16 serviceIndex = GetServiceIndex(ZwQuerySystemInformation);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Syscall index is %x.\r\n", serviceIndex));

	SST *KeServiceDescriptorTable = (SST*)GetKeServiceDescriptorTable64();
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "KeServiceDescriptorTable is %llx.\r\n", KeServiceDescriptorTable));

	/* identify the address of SSDT table */
	ssdt = KeServiceDescriptorTable->ServiceTable;
	g_sst = KeServiceDescriptorTable;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ssdt is %llx.\r\n", ssdt));

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "The system call address is %llx.\r\n", syscall));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "The hook function address is %llx.\r\n", hookAddr));

	UINT64 kernelBase = GetKernelBase();
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Kernel base at %llx.\r\n", kernelBase));

	UINT64 searchAddr = 0;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Found kernel text section at %llx.\r\n", searchAddr));

	UINT64 ntFuncAddr = GetNtFuncByServiceIndex(serviceIndex);
	oldZwQuerySystemInformation = (ZwQuerySystemInformationPrototype)ntFuncAddr;

	searchAddr = ntFuncAddr - 0x20;

	UINT64 codeCaveAddr = SearchCodeCave(searchAddr);
	// UINT64 codeCaveAddr = ntFuncAddr - 0x10;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Found code cave at %llx.\r\n", codeCaveAddr));

	UCHAR jmp_to_newFunction[] = "\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xE0"; //mov rax, xxx ; jmp rax

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Found nt function at %llx.\r\n", ntFuncAddr));

	// mov rax, @NewFunc; jmp rax
	*(PULONGLONG)(jmp_to_newFunction + 2) = hookAddr;

	PMDL mdl = IoAllocateMdl((PVOID)codeCaveAddr, 12, FALSE, FALSE, NULL);
	if (mdl == NULL)
	{
#ifdef DEBUG
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IoAllocateMdl failed !!\n"));
#endif
	}

	MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
	PVOID memAddr = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
	if (memAddr == NULL)
	{
#ifdef DEBUG
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "MmMapLockedPagesSpecifyCache failed !!\n"));
#endif
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Mem addr at %llx.\r\n", ntFuncAddr));

	// Disable write protection
	KIRQL irql = WPOFF();
	RtlMoveMemory(memAddr, jmp_to_newFunction, 12);

	/* identify 'syscall' index into the SSDT table */
	/*index = *((PULONG)(syscall + 0x1));
	DbgPrint("The index into the SSDT table is: %d.\r\n", index);*/

	UINT32 *ssdtEntry = &ssdt[serviceIndex];
	UINT64 offset = (codeCaveAddr - (UINT64)ssdt) << 4;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Offset is %llx.\r\n", offset));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Offset32 is %llx.\r\n", (UINT32)offset));

	UINT64 addr = (offset >> 4) + (ULONG64)g_sst->ServiceTable;
	UINT64 addr2 = (((UINT32)offset) >> 4) + (ULONG64)g_sst->ServiceTable;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Decoded code cave addr: %llx.\r\n", addr));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Decoded code cave addr 32: %llx.\r\n", addr2));
	// *ssdtEntry = ((*ssdtEntry + 0x2F) & 0xFFFFFFF0) | (*ssdtEntry & 0xF);
	ssdt[serviceIndex] = offset | ssdt[serviceIndex] & 0x0F;
	// InterlockedExchange(&ssdt[serviceIndex], offset | ssdt[serviceIndex] & 0x0F);

	// Enable write protection
	WPON(irql);
}
