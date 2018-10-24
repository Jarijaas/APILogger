#include <Fltkernel.h>
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include <wdm.h>

#include <intrin.h> // cr0 read/write

#include "ntfill.h"
#include "peb.h"
#include "sdt.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD APILoggerEvtDeviceAdd;

/* Compile directives. */
#pragma alloc_text(INIT, DriverEntry)

NTSYSAPI NTSTATUS NTAPI ZwCreateProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ BOOLEAN InheritObjectTable,
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE ExceptionPort
);

typedef NTSTATUS(*ZwCreateProcessPrototype)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ BOOLEAN InheritObjectTable,
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE ExceptionPort
    );

typedef PPEB(*PsGetProcessPEBPrototype)(
    _In_ PEPROCESS Process
    );

PsGetProcessPEBPrototype PsGetProcessPEB = NULL;



#define DEBUG

FLT_REGISTRATION reg = { 0 };

typedef LONG(*LoadLibraryA)(
    PCHAR DllName
    );

typedef struct _LOAD_LIB {
    LoadLibraryA load;
    CHAR DllName[255];
} LOAD_LIB, *PLOAD_LIB;


// DISABLE CONTROL FLOW GUARD OR VIRTUAL CALLS ARE INDIRECT CAUSING A CRASH
// WHEN EXECUTING THE CODE IN THE TARGET PROCESS
// https://docs.microsoft.com/en-us/windows/desktop/secbp/control-flow-guard
VOID UserAPC(PLOAD_LIB context, PVOID sysarg1, PVOID sysarg2)
{
    context->load(context->DllName);
}

VOID UserAPC_end()
{}

ULONG CalcApcSize()
{
    return ((ULONG_PTR)UserAPC_end - (ULONG_PTR)UserAPC);
}


VOID KernelAPC(PVOID context, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4)
{
    // Here you can free the APC argument since you're done with it now
    // ExFreePool(context);
}


ULONG64 GetProcAddress(
    _In_ ULONG64 module,
    _In_ const char* name
) {
    PIMAGE_DOS_HEADER peHdr = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS hdrs = (PIMAGE_NT_HEADERS)(module + peHdr->e_lfanew);

    IMAGE_DATA_DIRECTORY dataDir = hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(module + dataDir.VirtualAddress);

    for (ULONG i = 0; i < exportDir->NumberOfNames; ++i) {
        const char *funcName = (const char*)(module + *(ULONG32*)(module + exportDir->AddressOfNames + i * 4));
        if (strcmp(funcName, name) == 0) {
            ULONG64 funcAddr = (module + *(ULONG32*)(module + exportDir->AddressOfFunctions + i * 4));
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "APILogger: found exported function %s at %llx\n", funcName, funcAddr));
            return funcAddr;
        }
    }
    return NULL;
}

#define MAX_PID_COUNT 0xFFFF

volatile HANDLE pids[MAX_PID_COUNT];
volatile int currentPidCount = 0;

// Todo: remove exited processes from the array
BOOLEAN PidSeen(HANDLE pid) {
    if (currentPidCount == MAX_PID_COUNT) {
        for (int i = 100; i < currentPidCount; ++i) {
            pids[i - 100] = pids[i];
        }
        currentPidCount -= 100;
    }

    for (int i = 0; i < currentPidCount; ++i) {
        if (pids[i] == pid) {
            return TRUE;
        }
    }
    return FALSE;
}

UINT64 loadLibAddr = NULL;

/*
This routine is executed on the created thread
*/
VOID CreateThreadNotifyRoutine(
    IN HANDLE  ProcessId,
    IN HANDLE  ThreadId,
    IN BOOLEAN  Create
)
{
    if (!Create) {
        return; // Thread was deleted
    }

    if (PidSeen(ProcessId)) {
        return;
    }

    pids[currentPidCount++] = ProcessId;

    PKAPC_STATE apc = ExAllocatePool(NonPagedPool, sizeof(KAPC_STATE));

    PVOID libMem = NULL;
    PVOID apcMem = NULL;

    SIZE_T libSize = sizeof(LOAD_LIB);
    SIZE_T apcSize = CalcApcSize();

    BOOLEAN shouldInject = FALSE;

    // Attach current thread to the process address space
    KeStackAttachProcess(PsGetCurrentProcess(), apc);
    __try {
        if (IoIs32bitProcess(NULL)) {
            goto end; // 32 bit dll injection isn't supported
        }

        ULONG64 tib = __readgsqword(0x30);
        PPEB peb = *(PPEB*)(tib + 0x60);

        // PE loader hasn't loaded modules yet
        if (peb->Ldr == NULL) {
            currentPidCount--;
            goto end;
        }

        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "APILogger: Process %d is injectable\n", ProcessId));

        if (loadLibAddr == NULL) {
            PLDR_DATA_TABLE_ENTRY_LOAD entry = (PLDR_DATA_TABLE_ENTRY_LOAD)peb->Ldr->InLoadOrderModuleList.Flink->Flink->Flink;
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Kernel32: %llx\n", entry->DllBase));
            loadLibAddr = GetProcAddress(entry->DllBase, "LoadLibraryA");
        }

        NTSTATUS status;
        status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &libMem, NULL, &libSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Couldn't allocate mem for lib struct: code %x\n", status));
            goto end;
        }

        // Some processes are protected causing a STATUS_DYNAMIC_CODE_BLOCKED (0xC0000604) error code
        // See https://www.countercraft.eu/blog/post/arbitrary-vs-kernel/ for how to bypass this
        status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &apcMem, NULL, &apcSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(status)) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Couldn't allocate mem for apc code: %x.\n", status));
            ZwFreeVirtualMemory(ZwCurrentProcess(), &libMem, NULL, MEM_RELEASE);
            goto end;
        }

        LOAD_LIB lib = { loadLibAddr, "APILoggerDll.dll" };

        RtlCopyMemory(apcMem, UserAPC, apcSize);
        RtlCopyMemory(libMem, &lib, sizeof(LOAD_LIB));
        shouldInject = TRUE;
    }  __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Couldn't inject dll to the process %d. Reason: %x\n", ProcessId, GetExceptionCode()));
    }

    end:
    KeUnstackDetachProcess(apc);
    ExFreePool(apc);

    if (shouldInject) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "APC addr: %llx, lib addr: %llx\n", apcMem, libMem));

        // PETHREAD thread = KeGetCurrentThread();
        /*if (!NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &thread))) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Thread lookup by thread id failed\n"));
            return;
        }*/

        PKAPC apc2 = ExAllocatePool(NonPagedPool, sizeof(KAPC));
        KeInitializeApc(apc2, KeGetCurrentThread(), OriginalApcEnvironment, KernelAPC, NULL, apcMem, UserMode, libMem);
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Queue APC\n"));
        if (!KeInsertQueueApc(apc2, NULL, NULL, 0)) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Couldn't queue APC\n"));
        }
        //  ObDereferenceObject(thread);
    }
}

VOID LoadImageNotifyRoutine(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
)
{
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "APILogger: Process %d loaded %wZ\n", ProcessId, FullImageName));
}

VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "APILogger: Unload\n"));
    PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
    PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
}

NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
    PIO_STACK_LOCATION io;
    NTSTATUS status = STATUS_SUCCESS;

    io = IoGetCurrentIrpStackLocation(irp);
    irp->IoStatus.Information = 0;

    switch (io->MajorFunction)
    {
    case IRP_MJ_CREATE:
        status = STATUS_SUCCESS;
        break;
    case IRP_MJ_CLOSE:
        status = STATUS_SUCCESS;
        break;
    case IRP_MJ_READ:
        status = STATUS_SUCCESS;
        break;
    case IRP_MJ_WRITE:
        status = STATUS_SUCCESS;
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    irp->IoStatus.Status = status;

    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT     DriverObject,
    _In_ PUNICODE_STRING    RegistryPath
)
{
    // NTSTATUS variable to record success or failure
    NTSTATUS status = STATUS_SUCCESS;

    // Allocate the driver configuration object
    WDF_DRIVER_CONFIG config;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "APILogger: DriverEntry\n"));

    // Initialize the driver configuration object to register the
    // entry point for the EvtDeviceAdd callback, KmdfHelloWorldEvtDeviceAdd
    WDF_DRIVER_CONFIG_INIT(&config,
        APILoggerEvtDeviceAdd
    );

    DriverObject->DriverUnload = DriverUnload;

    DriverObject->MajorFunction[IRP_MJ_CREATE] =
        DriverObject->MajorFunction[IRP_MJ_CLOSE] =
        DriverObject->MajorFunction[IRP_MJ_READ] =
        DriverObject->MajorFunction[IRP_MJ_WRITE] =
        DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] =
        DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] =
        DriverObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] =
        DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] =
        DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] =
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
        DriverObject->MajorFunction[IRP_MJ_LOCK_CONTROL] =
        DriverObject->MajorFunction[IRP_MJ_CLEANUP] =
        DriverObject->MajorFunction[IRP_MJ_PNP] =
        DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = (PDRIVER_DISPATCH)DriverDispatch;

    // Finally, create the driver object
    status = WdfDriverCreate(DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        WDF_NO_HANDLE
    );
    return status;
}

#define KLIB_POOL_TAG "KLIB"

NTSTATUS IterateKernelModulesTest() {
    NTSTATUS status;
    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "APILogger: Could not initialize AuxKlib: code %x\n", status));
        return status;
    }

    ULONG moduleBuffSize = 0;
    status = AuxKlibQueryModuleInformation(&moduleBuffSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "APILogger: Could not required buff size for AuxKlib module info: code %x\n", status));
        return status;
    }

    AUX_MODULE_EXTENDED_INFO *modules = ExAllocatePoolWithTag(PagedPool, moduleBuffSize, KLIB_POOL_TAG);
    if (modules == NULL) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "APILogger: Could not alloc pool for modules\n"));
        return status;
    }

    status = AuxKlibQueryModuleInformation(&moduleBuffSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "APILogger: Could not retrieve AuxKlib module info: code %x\n", status));
        ExFreePoolWithTag(modules, KLIB_POOL_TAG);
        return status;
    }

    ULONG nModules = moduleBuffSize / sizeof(AUX_MODULE_EXTENDED_INFO);
    for (ULONG i = 0; i < nModules; ++i) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "Found module %d: %s\n", i, modules[i].FullPathName));
    }

    ExFreePoolWithTag(modules, KLIB_POOL_TAG);
    return 0;
}

NTSTATUS
APILoggerEvtDeviceAdd(
    _In_    WDFDRIVER       Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
)
{
    // We're not using the driver object,
    // so we need to mark it as unreferenced
    UNREFERENCED_PARAMETER(Driver);

    NTSTATUS status;

    // Allocate the device object
    WDFDEVICE hDevice;

    // Create the device object
    status = WdfDeviceCreate(&DeviceInit,
        WDF_NO_OBJECT_ATTRIBUTES,
        &hDevice
    );

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "APILogger: Could not create device: code %x\n", status));
        return status;
    }

    status = PsSetCreateThreadNotifyRoutineEx(PsCreateThreadNotifyNonSystem, CreateThreadNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "APILogger: Could not register thread notify routine: code %x\n", status));
        return status;
    }

    /*status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "APILogger: Could not register load image notify routine: code %x\n", status));
    }*/


    // SSDTHookPOC(Hook_ZwQuerySystemInformation);
    return status;
}