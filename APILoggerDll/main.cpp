/*
Copyright 2018 Jari J‰‰skel‰

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom
the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <Shlwapi.h>
#include <unordered_set>
#include <mutex>

#pragma comment(lib, "Shlwapi.lib")

#include "function_hooks.h"


using std::cout;
using std::wcout;
using std::endl;
using std::hex;
using std::dec;
using std::string;

#define DEBUG

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


bool CreateConsole() {
    if (AllocConsole()) {
        freopen("CONOUT$", "w", stdout);
        return true;
    }
    return false;
}

std::unordered_map<uint32_t, string> kImportsByHookId;
std::unordered_map<uint32_t, string> kProcAddressHooksByHookId;

std::unordered_map<string, std::unordered_map<uint64_t, string>> kImportsByAddrModule;
std::unordered_map<string, std::unordered_map<string, uint64_t>> kImportsByNameModule;

std::unordered_set<string> kBlacklist = {
    "ntdll.dll!RtlRunOnceExecuteOnce",
    "ntdll.dll!NtWaitForSingleObject",
    "ntdll.dll!NtRemoveIoCompletionEx",
    "ntdll.dll!RtlNtStatusToDosError",
    "ntdll.dll!NtReleaseSemaphore",
    "ntdll.dll!NtWriteFile",
    "ntdll.dll!RtlSetLastWin32Error",
    "ntdll.dll!RtlProcessFlsData",
    "WINMM.dll!timeGetTime",
    "KERNEL32.dll!HeapSize",
    "KERNEL32.dll!QueryPerformanceCounter",
    "KERNEL32.dll!EnterCriticalSection",
    "KERNEL32.dll!LeaveCriticalSection",
    "api-ms-win-core-rtlsupport-l1-1-0.dll!RtlPcToFileHeader",
    "api-ms-win-core-errorhandling-l1-1-0.dll!RaiseException",
    "ntdll.dll!memcpy",
    "ntdll.dll!RtlRaiseException",
    "api-ms-win-core-errorhandling-l1-1-0.dll!GetLastError",
    "api-ms-win-core-synch-l1-2-0.dll!InitOnceExecuteOnce",
    "ntdll.dll!memset",
    "ntdll.dll!LdrResFindResourceDirectory",
    "ntdll.dll!RtlDeregisterWaitEx"
};

std::ofstream out;

uint64_t _GetProcAddress(uint64_t module, const char* name) {
    PIMAGE_DOS_HEADER peHdr = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS hdrs = (PIMAGE_NT_HEADERS)(module + peHdr->e_lfanew);

    IMAGE_DATA_DIRECTORY dataDir = hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(module + dataDir.VirtualAddress);

    uint16_t *ordinals = reinterpret_cast<uint16_t*>(module + exportDir->AddressOfNameOrdinals);
    uint32_t *name_offsets = reinterpret_cast<uint32_t*>(module + exportDir->AddressOfNames);

    for (uint32_t i = 0; i < exportDir->NumberOfNames; ++i) {
        const char *funcName = (const char*)(module + name_offsets[i]);
        uint64_t funcAddr = (module + *(uint32_t*)(module + exportDir->AddressOfFunctions + ordinals[i] * 4));
        if (strcmp(funcName, name) == 0) {
            return funcAddr;
        }
    }
    return 0;
}


const char* GetProcNameByOrdinal(uint64_t module, uint16_t ordinal) {
    PIMAGE_DOS_HEADER peHdr = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS hdrs = (PIMAGE_NT_HEADERS)(module + peHdr->e_lfanew);

    IMAGE_DATA_DIRECTORY dataDir = hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(module + dataDir.VirtualAddress);

    uint16_t *ordinals = reinterpret_cast<uint16_t*>(module + exportDir->AddressOfNameOrdinals);
    uint32_t *name_offsets = reinterpret_cast<uint32_t*>(module + exportDir->AddressOfNames);

    for (uint32_t i = 0; i < exportDir->NumberOfNames; ++i) {
        if ((ordinals[i + 1]) == ordinal) {
            return (const char*)(module + name_offsets[i]);
        }
    }
    return nullptr;
}


std::unordered_map<uint64_t, string> &GetImports(uint64_t module) {
    TCHAR full_name[MAX_PATH] = {};
    GetModuleFileNameA(reinterpret_cast<HMODULE>(module), full_name, sizeof(full_name));
    LPSTR module_name = PathFindFileName(full_name); //e.g. ntdll.dll

    PIMAGE_DOS_HEADER peHdr = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS hdrs = (PIMAGE_NT_HEADERS)(module + peHdr->e_lfanew);

    IMAGE_DATA_DIRECTORY dataDir = hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dataDir.VirtualAddress == NULL) {
        return kImportsByAddrModule[module_name];
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescs = (PIMAGE_IMPORT_DESCRIPTOR)(module + dataDir.VirtualAddress);
    while (importDescs->OriginalFirstThunk != NULL) {
        PIMAGE_THUNK_DATA origFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(module + importDescs->OriginalFirstThunk);
        PIMAGE_THUNK_DATA firstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(module + importDescs->FirstThunk);

        const char *mod_name = (const char*)(module + importDescs->Name);
        HMODULE hMod = GetModuleHandle(mod_name);

        while (origFirstThunk->u1.AddressOfData != NULL) {
            string full_fn_name; // e.g. ntdll.dll!LoadLibraryA
            if (origFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                //Import by ordinal
                uint16_t ordinal = origFirstThunk->u1.Ordinal & 0xFFFF;
                const char* name = GetProcNameByOrdinal((uint64_t)hMod, ordinal);
                string fn_name = name != nullptr ? name : "ordinal_" + std::to_string(ordinal);
                full_fn_name = string(mod_name) + "!" + fn_name;
            } else {
                //Import by name
                PIMAGE_IMPORT_BY_NAME imp = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(module + origFirstThunk->u1.AddressOfData);
                full_fn_name = string(mod_name) + "!" + string(imp->Name);
            }
            kImportsByAddrModule[module_name][(uint64_t)(firstThunk)] = full_fn_name;
            kImportsByNameModule[module_name][full_fn_name] = (uint64_t)(firstThunk);

            ++origFirstThunk;
            ++firstThunk;
        }
        ++importDescs;
    }
    return kImportsByAddrModule[module_name];
}


std::mutex kImportsByHookIdM;

void __fastcall ImportHook(fn_hooks::Registers2 regs, uint32_t hook_id) {

    /*cout << "RCX: " << hex << regs.RCX << endl;
    cout << "RSP: " << hex << regs.RSP << endl;
    cout << "Ret addr: " << hex << (*(uint64_t*)regs.RSP) << endl;*/

    // Prevent deadlocks cause the hook is called from multiple threads
    static std::mutex m;
    {
        std::lock_guard<std::mutex> lk(m);
        std::lock_guard<std::mutex> lk2(kImportsByHookIdM);
        out << kImportsByHookId[hook_id] << endl;
    }
    // out << kImportsByHookId[hook_id] << endl;
    // printf("%d\n", hook_id);
    // cout << "Ret addr: " << hex << (*(uint64_t*)regs.RSP) << endl;
}

FARPROC WINAPI GetProcAddressHook(HMODULE hModule, uint64_t lpProcName) {
    bool is_ordinal = (lpProcName >> 16) == 0;

    TCHAR full_name[MAX_PATH] = {};
    GetModuleFileNameA(hModule, full_name, sizeof(full_name));
    LPSTR name = PathFindFileName(full_name);

    FARPROC proc_addr = GetProcAddress(hModule, (LPCSTR)lpProcName);
    uint64_t orig_addr = reinterpret_cast<uint64_t>(proc_addr);

    uint32_t hook_id;
    uint64_t new_addr;

    std::string fn_name = is_ordinal ? std::to_string(lpProcName) : reinterpret_cast<const char*>(lpProcName);

    cout << "Module name: " << name << endl;
    cout << "GetProcAddress(0x" << hex << hModule << ", \"" << fn_name.c_str() << "\")" << endl;

    if (!fn_hooks::GenericHook<void(fn_hooks::Registers2, uint32_t)>(orig_addr, ImportHook, &new_addr, &hook_id)) {
        cout << "Couldn't replace GetProcAddress result" << endl;
        return proc_addr;
    }
    cout << "hook_id: " << dec << hook_id << endl;

    if (hook_id != NULL) {
        std::lock_guard<std::mutex> lk2(kImportsByHookIdM);
        kImportsByHookId[hook_id] = std::string(name) + "!" + fn_name;
    }
    return reinterpret_cast<FARPROC>(new_addr);
}

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT * Buffer;
#else // MIDL_PASS
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;



// https://doxygen.reactos.org/d7/d55/ldrapi_8c_source.html
typedef NTSTATUS(*LdrLoadDllPrototype)(
    IN PWSTR SearchPath OPTIONAL,
    IN PULONG DllCharacteristics OPTIONAL,
    IN PUNICODE_STRING DllName,
    OUT PVOID *BaseAddress
    );
LdrLoadDllPrototype kOrigLdrLoadDll = nullptr;


typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef NTSTATUS(*LdrGetProcedureAddressForCallerPrototype)
(
    IN  HMODULE			ModuleHandle,
    IN	PANSI_STRING	FunctionName OPTIONAL,
    IN	WORD			Ordinal OPTIONAL,
    OUT PVOID			*FunctionAddress,
    IN  BOOL			bValue,
    IN  PVOID			*CallbackAddress
    );

LdrGetProcedureAddressForCallerPrototype kOrigLdrGetProcAddressForCaller;

NTSTATUS NTAPI LdrGetProcedureAddressForCallerHook(
    IN  HMODULE			ModuleHandle,
    IN	PANSI_STRING	FunctionName OPTIONAL,
    IN	WORD			Ordinal OPTIONAL,
    OUT PVOID			*FunctionAddress,
    IN  BOOL			bValue,
    IN  PVOID			*CallbackAddress
)
{
    NTSTATUS status = kOrigLdrGetProcAddressForCaller(ModuleHandle, FunctionName, Ordinal, FunctionAddress, bValue, CallbackAddress);;

    if (FunctionName != NULL) {
        uint64_t orig_addr = reinterpret_cast<uint64_t>(*FunctionAddress);
        uint64_t new_addr;
        uint32_t hook_id;

        TCHAR full_name[MAX_PATH] = {};
        GetModuleFileNameA(ModuleHandle, full_name, sizeof(full_name));
        LPSTR name = PathFindFileName(full_name);

        string full_fn_name = std::string(name) + "!" + std::string(FunctionName->Buffer);

        if (kBlacklist.find(full_fn_name) != kBlacklist.end()) {
            return status;
        }

        if (!fn_hooks::GenericHook<void(fn_hooks::Registers2, uint32_t)>(orig_addr, ImportHook, &new_addr, &hook_id)) {
            cout << "Couldn't replace LdrGetProcedureAddressForCaller return value" << endl;
            return status;
        };
        if (hook_id != NULL) {
            std::lock_guard<std::mutex> lk2(kImportsByHookIdM);
            kImportsByHookId[hook_id] = full_fn_name;
            cout << "Hooked " << full_fn_name << " via LdrGetProcedureAddressForCaller" << endl;
        }
        *FunctionAddress = reinterpret_cast<PVOID>(new_addr);
    }
    return status;
}

NTSTATUS
NTAPI
LdrLoadDllHook(
    IN PWSTR SearchPath_ OPTIONAL,
    IN PULONG DllCharacteristics OPTIONAL,
    IN PUNICODE_STRING DllName,
    OUT PVOID *BaseAddress) {

    NTSTATUS status = kOrigLdrLoadDll(SearchPath_, DllCharacteristics, DllName, BaseAddress);
    wcout << L"LdrLoadDll: " << DllName->Buffer << ", base: 0x" << hex << *BaseAddress << endl;

    if (NT_SUCCESS(status)) {
        auto &imports = GetImports(reinterpret_cast<uint64_t>(*BaseAddress));
        uint32_t hook_id;
        for (const auto &imp : imports) {
            if (kBlacklist.find(imp.second) != kBlacklist.end()) {
                continue;
            }
            
            // cout << "Hook " << imp.second;
            if (!fn_hooks::TableHook<void(fn_hooks::Registers2, uint32_t)>(imp.first, ImportHook, &hook_id)) {
                break;
            }
            cout << "Hooked " << imp.second << ", id: " << dec << hook_id << " via LdrLoadDllHook" << endl;
        }
    }
    return status;
}


void Initialize() {
#ifdef DEBUG
    CreateConsole();
#endif // DEBUG

    TCHAR full_name[MAX_PATH] = {};
    GetModuleFileNameA(NULL, full_name, sizeof(full_name));
    LPSTR name = PathFindFileName(full_name);

    DWORD timestamp = GetCurrentTime();

    // Todo: write to easily parsable format like JSON
    std::string log_path("H:\\logs\\APILogger_" + std::string(name) + "_" + std::to_string(timestamp) + ".log");
    out.open(log_path, std::ofstream::out);
    out << "Filename: " << full_name << endl;

    GetImports((uint64_t)GetModuleHandle(NULL));
    GetImports((uint64_t)GetModuleHandle("kernelbase.dll"));


    cout << "LdrLoadDll: " << hex << kImportsByNameModule["KERNELBASE.dll"]["ntdll.dll!LdrLoadDll"] << endl;
    cout << "LdrGetProcedureAddressForCaller: " << hex << kImportsByNameModule["KERNELBASE.dll"]["ntdll.dll!LdrGetProcedureAddressForCaller"] << endl;

    /*if (!fn_hooks::TableHookDirect<FARPROC(HMODULE,uint64_t)>(kImportsByNameModule[name]["GetProcAddress"], GetProcAddressHook, &orig_addr)) {
        cout << "Couldn't set hook" << endl;
    }*/

    if (!fn_hooks::TableHookDirect<NTSTATUS(HMODULE, PANSI_STRING, WORD, PVOID*, BOOL, PVOID*)>(
        kImportsByNameModule["KERNELBASE.dll"]["ntdll.dll!LdrGetProcedureAddressForCaller"], LdrGetProcedureAddressForCallerHook,
        reinterpret_cast<uint64_t*>(&kOrigLdrGetProcAddressForCaller))) {
        cout << "Couldn't set hook" << endl;
    }
    if (!fn_hooks::TableHookDirect<NTSTATUS(PWSTR, PULONG, PUNICODE_STRING, PVOID*)>(
        kImportsByNameModule["KERNELBASE.dll"]["ntdll.dll!LdrLoadDll"], LdrLoadDllHook,
        reinterpret_cast<uint64_t*>(&kOrigLdrLoadDll))) {
        cout << "Couldn't set hook" << endl;
    }

    for (const auto impsByName : kImportsByNameModule) {
        // cout << "Hooking in " << impsByName.first << endl;
        for (const auto imp : impsByName.second) {
            if (imp.second == NULL) {
                continue;
            }

            if (kBlacklist.find(imp.first) != kBlacklist.end()) {
                continue;
            }

            uint32_t hook_id = 0;
            if (!fn_hooks::TableHook<void(fn_hooks::Registers2, uint32_t)>(imp.second, ImportHook, &hook_id)) {
                // cout << "Couldn't set hook" << endl;
                continue;
            }

            cout << "Hooking " << imp.first << ", " << hex << imp.second << "id: " << hex << hook_id << endl;

            kImportsByHookId[hook_id] = imp.first;
        }
    }
}

BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH: {
        // Usually dll code should be executed on a new thread
        // but in this case it should block until hooks are set
        Initialize();

        // CreateThread(NULL, 0, MainThread, nullptr, 0, &thdId);
        break;
    }
    case DLL_PROCESS_DETACH:
        fn_hooks::Unhook();
        // out.close();
    default:
        break;
    }
    return TRUE;
}