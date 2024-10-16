#pragma once

bool EmuReadNullTermString(uc_engine *uc, uint64_t address, std::string &str);
bool EmuReadNullTermUnicodeString(uc_engine *uc, uint64_t address, std::wstring &str);
uint64_t EmuReadReturnAddress(uc_engine *uc);

void EmuGetSystemTimeAsFileTime(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuGetCurrentThreadId(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuGetCurrentProcessId(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuGetCurrentProcess(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuQueryPerformanceCounter(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuLoadLibraryExW(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuLoadLibraryA(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuGetProcAddress(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuGetModuleHandleA(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuGetLastError(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuInitializeCriticalSectionAndSpinCount(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuInitializeCriticalSectionEx(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuTlsAlloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuTlsSetValue(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuTlsFree(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuDeleteCriticalSection(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuLocalAlloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuRtlIsProcessorFeaturePresent(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuNtProtectVirtualMemory(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuVirtualProtect(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuGetProcessAffinityMask(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuVirtualQueryEx(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuVirtualQuery(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

void EmuGetSystemInfo(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuExAllocatePool(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuNtQuerySystemInformation(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuExFreePool(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuExFreePoolWithTag(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuIoAllocateMdl(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuMmProbeAndLockPages(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuMmMapLockedPagesSpecifyCache(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuKeQueryActiveProcessors(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuKeSetSystemAffinityThread(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuKeRevertToUserAffinityThread(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuMmUnlockPages(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuIoFreeMdl(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuRtlGetVersion(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuDbgPrint(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuKeInitializeMutex(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuRtlInitUnicodeString(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuKeWaitForSingleObject(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuKeReleaseMutex(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void Emusrand(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void Emurand(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuRtlZeroMemory(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuRtlCopyMemory(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuRtlFillMemory(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void Emuwcsstr(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuMmIsAddressValid(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuExGetPreviousMode(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void Emu__C_specific_handler(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);