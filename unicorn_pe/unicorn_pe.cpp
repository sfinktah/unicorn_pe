﻿#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <BlackBone/Process/Process.h>
#include <BlackBone/ManualMap/MMap.h>

#include <iostream>
#include <sstream>
#include <fstream>
#include <functional>
#include <vector>
#include <set>
#include <intrin.h>
#include <regex>

#include "buffer.h"
#include "encode.h"
#include "nativestructs.h"
#include "ucpe.h"
#include "emuapi.h"

// #include <curl/curl.h>
//#include <restclient-cpp/restclient.h>
#include "util.hpp"
#include <fmt/format.h>

#include "./argh.h"
#include "../vendor/mem/include/mem/mem.h"
#include "../vendor/mem/include/mem/module.h"
#include "../vendor/mem/include/mem/pattern.h"
#include <nlohmann/json.hpp>
#include "sniffing/HexDump.h"
#include "membricksafe.hpp"
#include "../vendor/lodash/001_each.h"
#include "../vendor/lodash/024_keys.h"
#include "../vendor/lodash/095_uniq.h"

using json = nlohmann::json;
using namespace blackbone;
using mbs = membricksafe::memBrickSafe;

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Wldap32.Lib")
#pragma comment(lib, "Crypt32.Lib")
std::ostream* outs;

extern "C" {
NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(IN PVOID BaseAddress);

NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
    PVOID BaseAddress,
    BOOLEAN MappedAsImage,
    USHORT Directory,
    PULONG Size);
}

uint64_t EmuReadReturnAddress(uc_engine* uc);
bool EmuReadNullTermUnicodeString(uc_engine* uc, uint64_t address, std::wstring& str);
bool EmuReadNullTermString(uc_engine* uc, uint64_t address, std::string& str);

static ULONG ExtractEntryPointRva(PVOID ModuleBase) {
    return RtlImageNtHeader(ModuleBase)->OptionalHeader.AddressOfEntryPoint;
}
std::map<uint64_t, std::string> megaFuncFull;

template <typename Container>
uc_err uc_mem_write(uc_engine* uc, uint64_t address, const Container& obj) {
    using value_t = typename Container::value_type;
    using size_e  = sizeof value_t;
    return uc_mem_write(uc, uint64_t address, std::data(obj), size_e & std::size(obj));
}

blackbone::LoadData ManualMapCallback(blackbone::CallbackType type, void* context, blackbone::Process& /*process*/, const blackbone::ModuleData& modInfo) {
    PeEmulation* ctx = (PeEmulation*)context;
    if (type == blackbone::PreCallback) {
        uint64_t desiredBase         = ctx->m_LoadModuleBase;
        uint64_t desiredNextLoadBase = PAGE_ALIGN_64k((uint64_t)ctx->m_LoadModuleBase + (uint64_t)modInfo.size + 0x10000ull);
        ctx->m_LoadModuleBase        = desiredNextLoadBase;

        return blackbone::LoadData(blackbone::MT_Default, blackbone::Ldr_None, ctx->m_LoadModuleBase);
    } else if (type == blackbone::PostCallback) {
        ctx->MapImageToEngine(modInfo.name, (PVOID)modInfo.imgPtr, modInfo.size, modInfo.baseAddress,
                              (ULONG64)modInfo.baseAddress + ExtractEntryPointRva((PVOID)modInfo.imgPtr));
    }

    return blackbone::LoadData(blackbone::MT_Default, blackbone::Ldr_None, 0);
};

void PeEmulation::AddAPIEmulation(FakeAPI_t* r, void* callback, int argsCount) {
    r->EmuCallback = callback;

    if (callback) {
        uc_err err;

        unsigned char code[] = "\xC3";
        err                  = uc_mem_write(m_uc, r->VirtualAddress, code, sizeof(code));
    }
}

bool PeEmulation::RegisterAPIEmulation(const std::wstring& DllName, const char* ProcedureName, void* callback, int argsCount) {
    FakeAPI_t* r = NULL;
    for (size_t i = 0; i < m_FakeModules.size(); ++i) {
        auto& m = m_FakeModules[i];
        if (!_wcsicmp(m->DllName.c_str(), DllName.c_str())) {
            for (size_t j = 0; j < m->FakeAPIs.size(); ++j) {
                if (m->FakeAPIs[j].ProcedureName == ProcedureName) {
                    AddAPIEmulation(&m->FakeAPIs[j], callback, argsCount);
                    return true;
                }
            }
            *outs << "failed to register API emulation for " << ProcedureName << "\n";
            return false;
        }
    }
    return false;
}

uintptr_t PeEmulation::NormaliseBase(ULONG64 address) const {
    auto i = m_FakeModules.size() - 1;
    if (address >= m_FakeModules[i]->ImageBase && address < m_FakeModules[i]->ImageBase + m_FakeModules[i]->ImageSize) {
        address = address - m_FakeModules[i]->ImageBase + 0x140000000;
    }
    return address;
}

bool PeEmulation::FindAddressInRegion(ULONG64 address, std::stringstream& RegionName) {
    for (size_t i = 0; i < m_FakeModules.size(); ++i) {
        if (address >= m_FakeModules[i]->ImageBase && address < m_FakeModules[i]->ImageBase + m_FakeModules[i]->ImageSize) {
            std::string dllname;
            UnicodeToANSI(m_FakeModules[i]->DllName, dllname);
            RegionName << dllname << "+" << std::hex << (address - m_FakeModules[i]->ImageBase);
            return true;
        }
    }

    if (address >= m_StackBase && address < m_StackEnd) {
        RegionName << "StackBase+" << std::hex << (address - m_StackBase);
        return true;
    }

    if (address >= m_HeapBase && address < m_HeapEnd) {
        RegionName << "HeapBase+" << std::hex << (address - m_HeapBase);
        return true;
    }

    if (!m_IsKernel) {
        if (address >= m_PebBase && address < m_PebEnd) {
            RegionName << "Peb+" << std::hex << (address - m_PebBase);
            return true;
        }

        if (address >= m_TebBase && address < m_TebEnd) {
            RegionName << "Teb+" << std::hex << (address - m_TebBase);
            return true;
        }
    } else {
        if (address >= m_DriverObjectBase && address < m_DriverObjectBase + sizeof(DRIVER_OBJECT)) {
            RegionName << "DriverObject+" << std::hex << (address - m_DriverObjectBase);
            return true;
        }
    }

    if (address >= m_KSharedUserDataBase && address < m_KSharedUserDataEnd) {
        RegionName << "KSharedUserData+" << std::hex << (address - m_KSharedUserDataBase);
        return true;
    }

    return false;
}

bool PeEmulation::FindAPIByAddress(ULONG64 address, std::wstring& DllName, FakeAPI_t** api) {
    for (size_t i = 0; i < m_FakeModules.size(); ++i) {
        auto& m = m_FakeModules[i];
        if (address >= m->ImageBase && address < m->ImageBase + m->ImageSize) {
            DllName = m->DllName;

            for (size_t j = 0; j < m->FakeAPIs.size(); ++j) {
                auto r = &m->FakeAPIs[j];
                if (r->VirtualAddress == address) {
                    *api = r;
                    return true;
                }
            }

            break;
        }
    }
    return false;
}

bool PeEmulation::FindSectionByAddress(ULONG64 address, FakeSection_t** section) {
    for (size_t i = 0; i < m_FakeModules.size(); ++i) {
        auto& m = m_FakeModules[i];
        if (address >= m->ImageBase && address < m->ImageBase + m->ImageSize) {
            for (size_t j = 0; j < m->FakeSections.size(); ++j) {
                auto r = &m->FakeSections[j];
                if (address >= m->ImageBase + r->SectionBase && address < m->ImageBase + r->SectionBase + r->SectionSize) {
                    *section = r;
                    return true;
                }
            }

            break;
        }
    }
    return false;
}

bool PeEmulation::FindModuleByAddress(ULONG64 address, ULONG64& DllBase) {
    if (address >= m_ImageBase && address < m_ImageEnd) {
        DllBase = m_ImageBase;
        return true;
    }

    for (size_t i = 0; i < m_FakeModules.size(); ++i) {
        auto& m = m_FakeModules[i];
        if (address >= m->ImageBase && address < m->ImageBase + m->ImageSize) {
            DllBase = m->ImageBase;
            return true;
        }
    }
    return false;
}

ULONG64 PeEmulation::LdrGetProcAddress(ULONG64 ImageBase, const char* ProcedureName) {
    if (!strcmp(ProcedureName, "FlsAlloc")) {
        return 0;
    }
    if (!strcmp(ProcedureName, "FlsSetValue")) {
        return 0;
    }
    if (!strcmp(ProcedureName, "FlsFree")) {
        return 0;
    }

    for (size_t i = 0; i < m_FakeModules.size(); ++i) {
        auto& m = m_FakeModules[i];
        if (m->ImageBase == ImageBase) {
            for (size_t j = 0; j < m->FakeAPIs.size(); ++j) {
                auto& r = m->FakeAPIs[j];
                if (r.ProcedureName == ProcedureName) {
                    return r.VirtualAddress;
                }
            }
        }
    }

    return 0;
}

VOID PeEmulation::LdrResolveExportTable(FakeModule_t* module, PVOID ImageBase, ULONG64 MappedBase) {
    DWORD uExportSize                             = 0;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
        RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &uExportSize);

    if (!pImageExportDirectory)
        return;

    DWORD dwNumberOfNames        = (DWORD)(pImageExportDirectory->NumberOfNames);
    DWORD* pAddressOfFunction    = (DWORD*)((PUCHAR)ImageBase + pImageExportDirectory->AddressOfFunctions);
    DWORD* pAddressOfNames       = (DWORD*)((PUCHAR)ImageBase + pImageExportDirectory->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((PUCHAR)ImageBase + pImageExportDirectory->AddressOfNameOrdinals);

    for (size_t i = 0; i < dwNumberOfNames; i++) {
        char* strFunction = (char*)((PUCHAR)ImageBase + pAddressOfNames[i]);

        DWORD functionRva = pAddressOfFunction[pAddressOfNameOrdinals[i]];
        //forward
        if ((PUCHAR)ImageBase + functionRva >= (PUCHAR)pImageExportDirectory &&
            (PUCHAR)ImageBase + functionRva < (PUCHAR)pImageExportDirectory + uExportSize) {
            char* strForward         = (char*)ImageBase + functionRva;
            char* strForwardFunction = strchr(strForward, '.');
            if (strForwardFunction) {
                std::string strForwardDll(strForward, strForwardFunction - strForward);
                strForwardDll += ".dll";
                ULONG64 ForwardDllBase = 0;
                std::wstring wszForwardDll;
                ANSIToUnicode(strForwardDll, wszForwardDll);
                if (NT_SUCCESS(LdrFindDllByName(wszForwardDll, &ForwardDllBase, NULL, true))) {
                    ULONG64 ForwardFunction = LdrGetProcAddress(ForwardDllBase, strForwardFunction + 1);
                    if (ForwardFunction)
                        module->FakeAPIs.emplace_back(strFunction, ForwardFunction);
                }
            }
        } else {
            module->FakeAPIs.emplace_back(strFunction, MappedBase + functionRva);
        }
    }
}

NTSTATUS PeEmulation::LdrFindDllByName(const std::wstring& DllName, ULONG64* ImageBase, ULONG* ImageSize, bool LoadIfNotExist) {
    using namespace blackbone;

    std::wstring newDllName = DllName;

    if (!_wcsicmp(newDllName.c_str(), L"NTOSKRNL.DLL")) {
        newDllName = L"NTOSKRNL.EXE";
    }

    if (newDllName.find(L'.') == std::wstring::npos) {
        if (m_IsKernel)
            newDllName += L".SYS";
        else
            newDllName += L".DLL";
    }

    auto moduleptr = thisProc.modules().GetModule(newDllName, blackbone::eModSeachType::PEHeaders, mt_default);

    if (moduleptr) {
        if (ImageBase)
            *ImageBase = moduleptr->baseAddress;
        if (ImageSize)
            *ImageSize = moduleptr->size;

        return STATUS_SUCCESS;
    }

    if (LoadIfNotExist)
        return LdrLoadDllByName(newDllName, ImageBase, ImageSize);

    return STATUS_OBJECT_NAME_NOT_FOUND;
}

NTSTATUS PeEmulation::LdrLoadDllByName(const std::wstring& DllName, ULONG64* ImageBase, ULONG* ImageSize) {
    using namespace blackbone;

    auto MapResult = thisProc.mmap().MapImage(DllName,
                                              ManualImports | NoSxS | NoDelayLoad | NoExceptions | NoTLS | NoExceptions,
                                              ManualMapCallback, this);

    if (!MapResult.success()) {
        printf("LdrLoadDllByName failed to MapImage %ws, status %08X\n", DllName.c_str(), MapResult.status);
        return MapResult.status;
    }

    return STATUS_SUCCESS;
}

static void RwxCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);

static void EmuUnknownAPI(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);

void PeEmulation::MapImageToEngine(const std::wstring& ImageName, PVOID ImageBase, ULONG ImageSize, ULONG64 MappedBase, ULONG64 EntryPoint) {
    FakeModule_t* mod = new FakeModule_t(MappedBase, ImageSize, EntryPoint, ImageName);

    if (!_wcsicmp(ImageName.c_str(), L"ntoskrnl.exe"))
        mod->Priority = 100;
    else if (!_wcsicmp(ImageName.c_str(), L"hal.dll"))
        mod->Priority = 99;

    auto ExceptionTable = RtlImageDirectoryEntryToData(ImageBase,
                                                       TRUE,
                                                       IMAGE_DIRECTORY_ENTRY_EXCEPTION,
                                                       &mod->ExceptionTableSize);

    mod->ExceptionTable = MappedBase + ((PUCHAR)ExceptionTable - (PUCHAR)ImageBase);

    RtlInsertInvertedFunctionTable(&m_PsInvertedFunctionTable, MappedBase, ImageBase, ImageSize);

    m_FakeModules.push_back(mod);

    LdrResolveExportTable(mod, ImageBase, MappedBase);

    uint64_t image_base = (uint64_t)MappedBase;
    uint64_t image_end  = PAGE_ALIGN_64(image_base + ImageSize);

    if (image_end != image_base)
        uc_mem_map(m_uc, image_base, (size_t)(image_end - image_base), UC_PROT_READ);
    else
        uc_mem_map(m_uc, image_base, PAGE_SIZE, UC_PROT_READ);

    uc_mem_write(m_uc, image_base, ImageBase, ImageSize);

    auto ntheader = (PIMAGE_NT_HEADERS)RtlImageNtHeader(ImageBase);

    DWORD SectionAlignment;

    if (ntheader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        auto ntheader64  = (PIMAGE_NT_HEADERS64)ntheader;
        SectionAlignment = ntheader64->OptionalHeader.SectionAlignment;
    } else {
        SectionAlignment = ntheader->OptionalHeader.SectionAlignment;
    }

    auto SectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)ntheader + sizeof(ntheader->Signature) +
                                                 sizeof(ntheader->FileHeader) + ntheader->FileHeader.SizeOfOptionalHeader);

    for (WORD i = 0; i < ntheader->FileHeader.NumberOfSections; i++) {
        int prot = UC_PROT_READ | UC_PROT_WRITE;
        if (SectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            prot |= UC_PROT_EXEC;
        if (SectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
            prot |= UC_PROT_WRITE;

        auto SectionSize = AlignSize(
            max(SectionHeader[i].Misc.VirtualSize, SectionHeader[i].SizeOfRawData),
            SectionAlignment);

        uc_mem_protect(m_uc, image_base + SectionHeader[i].VirtualAddress, SectionSize, prot);

        if (SectionHeader[i].Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)) {
            bool bIsUnknownSection = (0 == memcmp((char*)SectionHeader[i].Name, ".text\0\0\0", 8) || 0 == memcmp((char*)SectionHeader[i].Name, "INIT\0\0\0\0", 8) || 0 == memcmp((char*)SectionHeader[i].Name, "PAGE\0\0\0\0", 8)) ? false : true;

            mod->FakeSections.emplace_back(SectionHeader[i].VirtualAddress, SectionSize, (char*)SectionHeader[i].Name, bIsUnknownSection);

            uc_hook trace3;
            uc_hook_add(m_uc, &trace3, UC_HOOK_CODE, EmuUnknownAPI,
                        this, image_base + SectionHeader[i].VirtualAddress,
                        image_base + SectionHeader[i].VirtualAddress + SectionSize - 1);
        }
    }
}

static void CodeCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    static std::set<uintptr_t> visited;
    PeEmulation* ctx = (PeEmulation*)user_data;

    /*uc_reg_read(uc, UC_X86_REG_EFLAGS, &ctx->m_InitReg.EFlags);
	ctx->m_InitReg.EFlags |= (1 << 8);
	uc_reg_write(uc, UC_X86_REG_EFLAGS, &ctx->m_InitReg.EFlags);*/

    ctx->FlushMemMapping();

    if (ctx->m_DisplayDisasm) {
        auto [it, suc] = visited.emplace(address);
        if (suc) {
            unsigned char codeBuffer[15];
            uc_mem_read(uc, address, codeBuffer, size);

            cs_insn insn;
            memset(&insn, 0, sizeof(insn));

            int64_t rsp;
            uc_reg_read(uc, UC_X86_REG_RSP, &rsp);

            uint64_t virtualBase = ctx->NormaliseBase(address);
            uint8_t* code        = codeBuffer;
            size_t codeSize      = size;
            cs_disasm_iter(ctx->m_cs, (const uint8_t**)&code, &codeSize, &virtualBase, &insn);
            std::stringstream region2;

            std::string op_string = insn.op_str;

            op_string = regex_replace(op_string, std::regex(R"(\b0x14[0-9a-fA-F]{7})"), [=](const std::smatch& m) {
                auto match = m.str();
                auto index = m.position();

                char* errch       = NULL;
                uintptr_t _offset = strtoull(match.c_str(), &errch, 16);
                if (*errch != '\0') {
                    *outs << "string couldn't be converted to ll: " << match << "\n";
                }

                if (auto it = megaFuncFull.find(_offset - 0x140000000); it != megaFuncFull.end()) {
                    return it->second;
                }

                return match;
            });

            if (1 && ctx->FindAddressInRegion(address, region2)) {
                *outs << std::hex << region2.str() << "\t\t" << std::hex << 0x50000 - rsp << "\t" << std::dec << insn.mnemonic << "\t\t" << op_string << "\n";
            } else {
                *outs << std::hex << virtualBase << "\t\t" << std::hex << 0x50000 - rsp << "\t" << std::dec << insn.mnemonic << "\t\t" << insn.op_str << "\n";
            }
        }
    }

    ctx->m_LastRip = address;
    ctx->m_ExecCodeCount++;

    if (ctx->m_ExecCodeCount % 100000 == 0) {
        outs->flush();
    }
}

static void IntrCallback(uc_engine* uc, int exception, void* user_data) {
    PeEmulation* ctx = (PeEmulation*)user_data;

    int64_t rsp;
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);

    int64_t rip;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);

    *outs << "exception #" << std::hex << exception << " at " << ctx->NormaliseBase(rip) << "\n";

    if (exception == EXCP01_DB) {
        ctx->m_LastException = STATUS_SINGLE_STEP;
    } else if (exception == EXCP03_INT3) {
        ctx->m_LastException = STATUS_BREAKPOINT;
    } else {
        ctx->m_LastException = STATUS_SUCCESS;
    }
    uc_emu_stop(uc);
}

static bool InvalidRwxCallback(uc_engine* uc, uc_mem_type type,
                               uint64_t address, int size, int64_t value, void* user_data) {
    PeEmulation* ctx = (PeEmulation*)user_data;

    switch (type) {
        case UC_MEM_FETCH_PROT: {
            uint64_t rip;
            uc_reg_read(uc, UC_X86_REG_RIP, &rip);

            std::stringstream region;
            if (ctx->FindAddressInRegion(address, region))
                *outs << "UC_MEM_FETCH_PROT reading from " << region.str() << "\n";
            else
                *outs << "UC_MEM_FETCH_PROT from " << address << "\n";

            std::stringstream region2;
            if (ctx->FindAddressInRegion(rip, region2))
                *outs << "UC_MEM_FETCH_PROT while running " << region2.str() << "\n";
            else
                *outs << "UC_MEM_FETCH_PROT rip at " << rip << "\n";

            //return true;
            uc_emu_stop(uc);
            break;
        }
        case UC_MEM_WRITE_PROT: {
            uint64_t rip;
            uc_reg_read(uc, UC_X86_REG_RIP, &rip);

            std::stringstream region;
            if (ctx->FindAddressInRegion(address, region))
                *outs << "UC_MEM_WRITE_PROT from " << region.str() << "\n";
            else
                *outs << "UC_MEM_WRITE_PROT from " << address << "\n";

            //RestClient::Response r = RestClient::get("http://127.0.0.1:2020/ida/api/v1.0/name?ea=0x140000000");
            //if (r.code == 200) {
            //    auto name = string_between("'", "'", r.body);
            //    if (name.size()) {
            //        *outs << "UC_MEM_WRITE_PROT: name: " << name << "\n";
            //    }
            //}

            *outs << "UC_MEM_WRITE_PROT: address 0x" << std::hex << ctx->NormaliseBase(address) << std::dec << "\n";
            *outs << "UC_MEM_WRITE_PROT: size 0x" << std::hex << size << std::dec << "\n";
            *outs << "UC_MEM_WRITE_PROT: value 0x" << std::hex << value << std::dec << "\n";

            std::stringstream region2;
            if (ctx->FindAddressInRegion(rip, region2))
                *outs << "UC_MEM_WRITE_PROT rip at " << region2.str() << "\n";
            else
                *outs << "UC_MEM_WRITE_PROT rip at " << rip << "\n";

            //return true;
            uc_emu_stop(uc);
            break;
        }
        case UC_MEM_FETCH_UNMAPPED: {
            uint64_t rip;
            uc_reg_read(uc, UC_X86_REG_RIP, &rip);

            std::stringstream region;
            if (ctx->FindAddressInRegion(address, region))
                *outs << "UC_MEM_FETCH_UNMAPPED from " << region.str() << "\n";
            else
                *outs << "UC_MEM_FETCH_UNMAPPED from " << address << "\n";

            std::stringstream region2;
            if (ctx->FindAddressInRegion(rip, region2))
                *outs << "UC_MEM_FETCH_UNMAPPED rip at " << region2.str() << "\n";
            else
                *outs << "UC_MEM_FETCH_UNMAPPED rip at " << rip << "\n";

            //return true;
            uc_emu_stop(uc);
            break;
        }
        case UC_MEM_READ_UNMAPPED: {
            uint64_t rip;
            uc_reg_read(uc, UC_X86_REG_RIP, &rip);

            std::stringstream region;
            if (ctx->FindAddressInRegion(address, region))
                *outs << "UC_MEM_READ_UNMAPPED from " << region.str() << "\n";
            else
                *outs << "UC_MEM_READ_UNMAPPED from " << address << "\n";

            std::stringstream region2;
            if (ctx->FindAddressInRegion(rip, region2))
                *outs << "UC_MEM_READ_UNMAPPED rip at " << region2.str() << "\n";
            else
                *outs << "UC_MEM_READ_UNMAPPED rip at " << rip << "\n";

            //return true;
            uc_emu_stop(uc);
            break;
        }
        case UC_MEM_WRITE_UNMAPPED: {
            uint64_t rip;
            uc_reg_read(uc, UC_X86_REG_RIP, &rip);

            std::stringstream region;
            if (ctx->FindAddressInRegion(address, region))
                *outs << "UC_MEM_WRITE_UNMAPPED from " << region.str() << "\n";
            else
                *outs << "UC_MEM_WRITE_UNMAPPED from " << address << "\n";
            //uint64_t address, int size, int64_t value
            *outs << "UC_MEM_WRITE_UNMAPPED: address 0x" << std::hex << address << std::dec << "\n";
            *outs << "UC_MEM_WRITE_UNMAPPED: size 0x" << std::hex << size << std::dec << "\n";
            *outs << "UC_MEM_WRITE_UNMAPPED: value 0x" << std::hex << value << std::dec << "\n";
            std::stringstream region2;
            if (ctx->FindAddressInRegion(rip, region2))
                *outs << "UC_MEM_WRITE_UNMAPPED rip at " << region2.str() << "\n";
            else
                *outs << "UC_MEM_WRITE_UNMAPPED rip at " << rip << "\n";

            //return true;
            uc_emu_stop(uc);
            break;
        }
    }
    return false;
}

static void RwxCallback(uc_engine* uc, uc_mem_type type,
                        uint64_t address, int size, int64_t value, void* user_data) {
    PeEmulation* ctx = (PeEmulation*)user_data;

    switch (type) {
        case UC_MEM_READ: {
            if (!ctx->m_SaveRead.empty()) {
                if (address > 0x50000) {
                    switch (size) {
                        case 1:
                            ctx->m_Read.emplace_back(ctx->NormaliseBase(address), (uint8_t)value);
                            break;
                        case 2:
                            ctx->m_Read.emplace_back(ctx->NormaliseBase(address), (uint8_t)(value >> 0));
                            ctx->m_Read.emplace_back(ctx->NormaliseBase(address + 1), (uint8_t)(value >> 8));
                        case 4:
                            ctx->m_Read.emplace_back(ctx->NormaliseBase(address), (uint8_t)(value >> 0));
                            ctx->m_Read.emplace_back(ctx->NormaliseBase(address + 1), (uint8_t)(value >> 8));
                            ctx->m_Read.emplace_back(ctx->NormaliseBase(address + 2), (uint8_t)(value >> 16));
                            ctx->m_Read.emplace_back(ctx->NormaliseBase(address + 3), (uint8_t)(value >> 24));
                            break;
                        case 8:
                            ctx->m_Read.emplace_back(ctx->NormaliseBase(address), (uint8_t)(value >> 0));
                            ctx->m_Read.emplace_back(ctx->NormaliseBase(address + 1), (uint8_t)(value >> 8));
                            ctx->m_Read.emplace_back(ctx->NormaliseBase(address + 2), (uint8_t)(value >> 16));
                            ctx->m_Read.emplace_back(ctx->NormaliseBase(address + 3), (uint8_t)(value >> 24));
                            ctx->m_Read.emplace_back(ctx->NormaliseBase(address + 4), (uint8_t)(value >> 32));
                            ctx->m_Read.emplace_back(ctx->NormaliseBase(address + 5), (uint8_t)(value >> 40));
                            ctx->m_Read.emplace_back(ctx->NormaliseBase(address + 6), (uint8_t)(value >> 48));
                            ctx->m_Read.emplace_back(ctx->NormaliseBase(address + 7), (uint8_t)(value >> 56));
                            break;

                        default:
                            std::stringstream region;
                            *outs << "UC_MEM_READ cannot handle size " << size << " to "
                                  << "0x" << std::hex << ctx->NormaliseBase(address) << std::dec << "\n";
                            uint64_t rip;
                            uc_reg_read(uc, UC_X86_REG_RIP, &rip);
                            if (ctx->FindAddressInRegion(rip, region))
                                *outs << "UC_MEM_READ rip at " << region.str() << "\n";
                    }
                    //*outs << "UC_MEM_WRITE: " << std::hex << ctx->NormaliseBase(address) << "\n";

                    //uc_emu_stop(uc);
                }

                break;
            }
        }
        case UC_MEM_WRITE: {
            if (!ctx->m_SaveWritten.empty()) {
                if (ctx->m_Bitmap && address >= ctx->m_ImageBase && address < ctx->m_ImageEnd) {
                    address -= 0x140000000;
                    while (size-- > 0) {
                        ctx->m_WrittenBitmap[address++] = true;
                    }
                } else if (address > 0x50000) {
                    switch (size) {
                        case 1:
                            ctx->m_Written.emplace_back(ctx->NormaliseBase(address), (uint8_t)value);
                            break;
                        case 2:
                            ctx->m_Written.emplace_back(ctx->NormaliseBase(address), (uint8_t)(value >> 0));
                            ctx->m_Written.emplace_back(ctx->NormaliseBase(address + 1), (uint8_t)(value >> 8));
                            break;
                        case 4:
                            ctx->m_Written.emplace_back(ctx->NormaliseBase(address), (uint8_t)(value >> 0));
                            ctx->m_Written.emplace_back(ctx->NormaliseBase(address + 1), (uint8_t)(value >> 8));
                            ctx->m_Written.emplace_back(ctx->NormaliseBase(address + 2), (uint8_t)(value >> 16));
                            ctx->m_Written.emplace_back(ctx->NormaliseBase(address + 3), (uint8_t)(value >> 24));
                            break;
                        case 8:
                            ctx->m_Written.emplace_back(ctx->NormaliseBase(address), (uint8_t)(value >> 0));
                            ctx->m_Written.emplace_back(ctx->NormaliseBase(address + 1), (uint8_t)(value >> 8));
                            ctx->m_Written.emplace_back(ctx->NormaliseBase(address + 2), (uint8_t)(value >> 16));
                            ctx->m_Written.emplace_back(ctx->NormaliseBase(address + 3), (uint8_t)(value >> 24));
                            ctx->m_Written.emplace_back(ctx->NormaliseBase(address + 4), (uint8_t)(value >> 32));
                            ctx->m_Written.emplace_back(ctx->NormaliseBase(address + 5), (uint8_t)(value >> 40));
                            ctx->m_Written.emplace_back(ctx->NormaliseBase(address + 6), (uint8_t)(value >> 48));
                            ctx->m_Written.emplace_back(ctx->NormaliseBase(address + 7), (uint8_t)(value >> 56));
                            break;
                        default:
                            std::stringstream region;
                            *outs << "UC_MEM_WRITE cannot handle size " << size << " to "
                                  << "0x" << std::hex << ctx->NormaliseBase(address) << std::dec << "\n";
                            uint64_t rip;
                            uc_reg_read(uc, UC_X86_REG_RIP, &rip);
                            if (ctx->FindAddressInRegion(rip, region))
                                *outs << "UC_MEM_WRITE rip at " << region.str() << "\n";
                    }
                    //*outs << "UC_MEM_WRITE: " << std::hex << ctx->NormaliseBase(address) << "\n";
                    //uc_emu_stop(uc);
                }
                //else if (address > 0x40000 && address < 0x50000 && value > 0x140000000) {
                //                uint64_t result_rsp = 0;
                //                uc_reg_read(uc, UC_X86_REG_RSP, &result_rsp);
                //                ptrdiff_t i = address - result_rsp;
                //                *outs << "WROTE TO RSP " << i << " VALUE: " << std::hex << value << std::dec << "\n";
                //            }
            }
            if (ctx->WriteMemMapping(address, value, size)) {
                //*outs << "write to mapping address " << address << "\n";
            }

            break;
        }
        case UC_MEM_FETCH: {

            break;
        }
    }
}

static void EmuUnknownAPI(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    PeEmulation* ctx = (PeEmulation*)user_data;

    std::wstring DllName;
    FakeAPI_t* api = NULL;

    uint64_t currentModule = 0;
    ctx->FindModuleByAddress(address, currentModule);

    if (currentModule != ctx->m_LastRipModule) {
        if (ctx->m_LastRipModule == ctx->m_ImageBase) {
            if (ctx->FindAPIByAddress(address, DllName, &api)) {
                if (!api->EmuCallback) {
                    std::string aDllName;
                    UnicodeToANSI(DllName, aDllName);
                    *outs << "API emulation callback not registered: " << aDllName << "!" << api->ProcedureName << "\n";
                    auto retaddr = EmuReadReturnAddress(uc);
                    if (retaddr >= ctx->m_ImageBase && retaddr < ctx->m_ImageEnd)
                        *outs << "called from imagebase+0x" << std::hex << (ULONG)(retaddr - ctx->m_ImageBase) << "\n";
                    uc_emu_stop(uc);
                } else {
                    void (*callback)(uc_engine * uc, uint64_t address, uint32_t size, void* user_data) = (decltype(callback))api->EmuCallback;

                    callback(uc, address, size, user_data);
                }
            } else {
                *outs << "unknown API called\n";
                auto retaddr = EmuReadReturnAddress(uc);
                if (retaddr >= ctx->m_ImageBase && retaddr < ctx->m_ImageEnd)
                    *outs << "called from imagebase+0x" << std::hex << (ULONG)(retaddr - ctx->m_ImageBase) << "\n";
                uc_emu_stop(uc);
            }
        }
        ctx->m_LastRipModule = currentModule;
    } else if (currentModule != ctx->m_ImageBase) {
        if (ctx->FindAPIByAddress(address, DllName, &api)) {
            _CrtDbgBreak();
        }
    }

    if (currentModule == ctx->m_ImageBase && ctx->m_IsPacked && !ctx->m_ImageRealEntry) {
        FakeSection_t* section = NULL;
        if (ctx->FindSectionByAddress(address, &section) && !section->IsUnknownSection) {
            ctx->m_ImageRealEntry = address;
        }
    }
}

static void init_descriptor64(SegmentDesctiptorX64* desc, uint64_t base, uint64_t limit, bool is_code, bool is_long_mode) {
    desc->descriptor.all              = 0;  //clear the descriptor
    desc->descriptor.fields.base_low  = base;
    desc->descriptor.fields.base_mid  = (base >> 16) & 0xff;
    desc->descriptor.fields.base_high = base >> 24;
    desc->base_upper32                = base >> 32;

    if (limit > 0xfffff) {
        limit >>= 12;
        desc->descriptor.fields.gran = 1;
    }

    desc->descriptor.fields.limit_low  = limit & 0xffff;
    desc->descriptor.fields.limit_high = limit >> 16;

    desc->descriptor.fields.dpl     = 0;
    desc->descriptor.fields.present = 1;
    desc->descriptor.fields.db      = 1;  //64 bit
    desc->descriptor.fields.type    = is_code ? 0xb : 3;
    desc->descriptor.fields.system  = 1;  //code or data
    desc->descriptor.fields.l       = is_long_mode ? 1 : 0;
}

typedef struct _KPCR {
    SegmentDesctiptorX64 gdt[8];
} KPCR;

void PeEmulation::InitProcessorState() {
    uc_x86_mmr gdtr;

    uint64_t kpcr_base = 0xfffff00000000000ull;

    KPCR kpcr;

    memset(&kpcr, 0, sizeof(KPCR));

    gdtr.base  = kpcr_base + offsetof(KPCR, gdt);
    gdtr.limit = sizeof(kpcr.gdt) - 1;

    init_descriptor64(&kpcr.gdt[1], 0, 0xffffffffffffffff, true, true);
    init_descriptor64(&kpcr.gdt[2], 0, 0xffffffffffffffff, false, true);

    auto err = uc_mem_map(m_uc, kpcr_base, PAGE_SIZE, UC_PROT_READ);
    err      = uc_mem_write(m_uc, kpcr_base, &kpcr, sizeof(KPCR));
    err      = uc_reg_write(m_uc, UC_X86_REG_GDTR, &gdtr);

    SegmentSelector cs = {0};
    cs.fields.index    = 1;
    uc_reg_write(m_uc, UC_X86_REG_CS, &cs.all);

    SegmentSelector ds = {0};
    ds.fields.index    = 2;
    uc_reg_write(m_uc, UC_X86_REG_DS, &ds.all);

    SegmentSelector ss = {0};
    ss.fields.index    = 2;
    uc_reg_write(m_uc, UC_X86_REG_SS, &ss.all);

    SegmentSelector es = {0};
    es.fields.index    = 2;
    uc_reg_write(m_uc, UC_X86_REG_ES, &es.all);

    SegmentSelector gs = {0};
    gs.fields.index    = 2;
    uc_reg_write(m_uc, UC_X86_REG_GS, &gs.all);

    FlagRegister eflags     = {0};
    eflags.fields.id        = 1;
    eflags.fields.intf      = 1;
    eflags.fields.reserved1 = 1;

    uc_reg_write(m_uc, UC_X86_REG_EFLAGS, &eflags.all);

    uint64_t cr8 = 0;
    uc_reg_write(m_uc, UC_X86_REG_CR8, &cr8);
}

void PeEmulation::InitTebPeb() {
    PEB peb = {0};

    m_PebBase = 0x90000ull;
    m_PebEnd  = m_PebBase + AlignSize(sizeof(PEB), PAGE_SIZE);

    uc_mem_map(m_uc, m_PebBase, m_PebEnd - m_PebBase, UC_PROT_READ);
    uc_mem_write(m_uc, m_PebBase, &peb, sizeof(PEB));

    m_TebBase = 0x80000ull;
    m_TebEnd  = m_TebBase + AlignSize(sizeof(TEB), PAGE_SIZE);

    TEB teb = {0};

    teb.ProcessEnvironmentBlock = (PPEB)m_PebBase;

    uc_mem_map(m_uc, m_TebBase, m_TebEnd - m_TebBase, UC_PROT_READ);
    uc_mem_write(m_uc, m_TebBase, &teb, sizeof(TEB));

    uc_x86_msr msr;
    msr.rid   = (uint32_t)Msr::kIa32GsBase;
    msr.value = m_TebBase;

    uc_reg_write(m_uc, UC_X86_REG_MSR, &msr);
}

void PeEmulation::InitKTHREAD() {
    //todo
    m_KThreadBase = HeapAlloc(1234);

    uc_x86_msr msr;
    msr.rid   = (uint32_t)Msr::kIa32GsBase;
    msr.value = m_KThreadBase;

    uc_reg_write(m_uc, UC_X86_REG_MSR, &msr);
}

void PeEmulation::SortModuleList() {
    std::sort(m_FakeModules.begin(), m_FakeModules.end(),
              [](const FakeModule_t* value1, const FakeModule_t* value2) {
                  return value1->Priority > value2->Priority;
              });
}

void PeEmulation::InsertTailList(
    IN ULONG64 ListHeadAddress,
    IN ULONG64 EntryAddress) {
    PLIST_ENTRY Blink;

    //Blink = ListHead->Blink;
    uc_mem_read(m_uc, ListHeadAddress + offsetof(LIST_ENTRY, Blink), &Blink, sizeof(Blink));

    //Entry->Flink = (PLIST_ENTRY)ListHeadAddress;

    uc_mem_write(m_uc, EntryAddress + offsetof(LIST_ENTRY, Flink), &ListHeadAddress, sizeof(ListHeadAddress));

    //Entry->Blink = Blink;

    uc_mem_write(m_uc, EntryAddress + offsetof(LIST_ENTRY, Blink), &Blink, sizeof(Blink));

    //Blink->Flink = (PLIST_ENTRY)EntryAddress;

    uc_mem_write(m_uc, (uint64_t)Blink + offsetof(LIST_ENTRY, Flink), &EntryAddress, sizeof(EntryAddress));

    //ListHead->Blink = (PLIST_ENTRY)EntryAddress;

    uc_mem_write(m_uc, ListHeadAddress + offsetof(LIST_ENTRY, Blink), &EntryAddress, sizeof(EntryAddress));
}

void PeEmulation::InitPsLoadedModuleList() {
    m_PsLoadedModuleListBase = HeapAlloc(sizeof(LIST_ENTRY));

    LIST_ENTRY PsLoadedModuleList = {0};
    PsLoadedModuleList.Blink = PsLoadedModuleList.Flink = (PLIST_ENTRY)m_PsLoadedModuleListBase;

    uc_mem_write(m_uc, m_PsLoadedModuleListBase, &PsLoadedModuleList, sizeof(PsLoadedModuleList));

    for (size_t i = 0; i < m_FakeModules.size(); ++i) {
        auto LdrEntryBase = HeapAlloc(sizeof(KLDR_DATA_TABLE_ENTRY));

        KLDR_DATA_TABLE_ENTRY LdrEntry = {0};
        LdrEntry.DllBase               = (PVOID)m_FakeModules[i]->ImageBase;
        LdrEntry.LoadCount             = 1;
        LdrEntry.EntryPoint            = (PVOID)m_FakeModules[i]->ImageEntry;
        LdrEntry.SizeOfImage           = m_FakeModules[i]->ImageSize;

        auto fullname                      = L"\\SystemRoot\\system32\\drivers\\" + m_FakeModules[i]->DllName;
        LdrEntry.FullDllName.Length        = (USHORT)fullname.length() * sizeof(WCHAR);
        LdrEntry.FullDllName.MaximumLength = ((USHORT)fullname.length() + 1) * sizeof(WCHAR);
        auto FullDllNameBase               = HeapAlloc(LdrEntry.FullDllName.MaximumLength);
        LdrEntry.FullDllName.Buffer        = (PWSTR)FullDllNameBase;

        LdrEntry.BaseDllName.Length        = (USHORT)fullname.length() - (_countof(L"\\SystemRoot\\system32\\drivers\\") - 1) * sizeof(WCHAR);
        LdrEntry.BaseDllName.MaximumLength = ((USHORT)fullname.length() + 1 - (_countof(L"\\SystemRoot\\system32\\drivers\\") - 1)) * sizeof(WCHAR);
        auto BaseDllNameBase               = FullDllNameBase + (_countof(L"\\SystemRoot\\system32\\drivers\\") - 1) * sizeof(WCHAR);
        LdrEntry.BaseDllName.Buffer        = (PWSTR)BaseDllNameBase;

        LdrEntry.ExceptionTable     = (PVOID)m_FakeModules[i]->ExceptionTable;
        LdrEntry.ExceptionTableSize = m_FakeModules[i]->ExceptionTableSize;

        uc_mem_write(m_uc, FullDllNameBase, fullname.data(), LdrEntry.FullDllName.MaximumLength);

        uc_mem_write(m_uc, LdrEntryBase, &LdrEntry, sizeof(LdrEntry));

        if (m_FakeModules[i]->ImageBase == m_ImageBase) {
            m_DriverLdrEntry  = LdrEntryBase;
            m_MainModuleIndex = (int)i;
        }

        InsertTailList(m_PsLoadedModuleListBase, LdrEntryBase);
    }
}

void PeEmulation::InitDriverObject() {
    m_DriverObjectBase = HeapAlloc(sizeof(DRIVER_OBJECT));

    DRIVER_OBJECT DriverObject = {0};
    DriverObject.DriverSize    = (ULONG)(m_ImageEnd - m_ImageBase);
    DriverObject.DriverStart   = (PVOID)m_ImageBase;
    DriverObject.DriverInit    = (PVOID)m_ImageEntry;
    DriverObject.Size          = sizeof(DRIVER_OBJECT);
    DriverObject.DriverSection = (PVOID)m_DriverLdrEntry;

    uc_mem_write(m_uc, m_DriverObjectBase, &DriverObject, sizeof(DriverObject));
}

void PeEmulation::InitKSharedUserData() {
    if (m_IsKernel) {
        m_KSharedUserDataBase = 0xfffff78000000000ull;
        m_KSharedUserDataEnd  = 0xfffff78000001000ull;
    } else {
        m_KSharedUserDataBase = 0x7FFE0000;
        m_KSharedUserDataEnd  = 0x7FFF0000;
    }

    uc_mem_map(m_uc, m_KSharedUserDataBase, PAGE_SIZE, UC_PROT_READ);
    uc_mem_write(m_uc, m_KSharedUserDataBase, (void*)0x7FFE0000, PAGE_SIZE);
}

ULONG64 PeEmulation::StackAlloc(ULONG AllocBytes) {
    uint64_t rsp;
    uc_reg_read(m_uc, UC_X86_REG_RSP, &rsp);
    rsp -= AllocBytes;
    uc_reg_write(m_uc, UC_X86_REG_RSP, &rsp);
    return rsp;
}

VOID PeEmulation::StackFree(ULONG AllocBytes) {
    uint64_t rsp;
    uc_reg_read(m_uc, UC_X86_REG_RSP, &rsp);
    rsp += AllocBytes;
    uc_reg_write(m_uc, UC_X86_REG_RSP, &rsp);
}

ULONG64 PeEmulation::HeapAlloc(ULONG AllocBytes, bool IsPageAlign) {
    ULONG64 alloc = 0;

    for (size_t i = 0; i < m_HeapAllocs.size(); ++i) {
        if (m_HeapAllocs[i].free && m_HeapAllocs[i].size >= AllocBytes) {
            m_LastHeapAllocBytes = AllocBytes;
            m_HeapAllocs[i].free = false;
            alloc                = m_HeapAllocs[i].base;
            break;
        }
    }

    if (!alloc) {
        for (size_t i = 0; i < m_HeapAllocs.size(); ++i) {
            if (alloc < m_HeapAllocs[i].base + m_HeapAllocs[i].size)
                alloc = m_HeapAllocs[i].base + m_HeapAllocs[i].size;
        }

        if (!alloc)
            alloc = m_HeapBase;

        if (IsPageAlign) {
            alloc      = (alloc % 0x1000ull == 0) ? alloc : AlignSize(alloc, 0x1000ull);
            AllocBytes = (AllocBytes % 0x1000 == 0) ? AllocBytes : (ULONG)AlignSize(AllocBytes, 0x1000);
        }

        if (alloc + AllocBytes > m_HeapEnd) {
            m_LastHeapAllocBytes = 0;
            return 0;
        }

        m_LastHeapAllocBytes = AllocBytes;
        m_HeapAllocs.emplace_back(alloc, AllocBytes);
    }

    return alloc;
}

bool PeEmulation::HeapFree(ULONG64 FreeAddress) {
    ULONG64 maxaddr = 0;

    for (size_t i = 0; i < m_HeapAllocs.size(); ++i) {
        if (maxaddr < m_HeapAllocs[i].base)
            maxaddr = m_HeapAllocs[i].base;
    }

    for (size_t i = 0; i < m_HeapAllocs.size(); ++i) {
        if (!m_HeapAllocs[i].free && m_HeapAllocs[i].base == FreeAddress) {
            if (maxaddr == FreeAddress)
                m_HeapAllocs.erase(m_HeapAllocs.begin() + i);
            else
                m_HeapAllocs[i].free = true;
            return true;
        }
    }
    return false;
}

bool PeEmulation::CreateMemMapping(ULONG64 BaseAddress, ULONG64 MapAddress, ULONG Bytes) {
    Bytes = AlignSize(Bytes, 0x1000ull);

    virtual_buffer_t buf(Bytes);
    uc_mem_read(m_uc, BaseAddress, buf.GetBuffer(), Bytes);
    uc_mem_write(m_uc, MapAddress, buf.GetBuffer(), Bytes);

    m_MemMappings.emplace_back(BaseAddress, MapAddress, Bytes);

    return true;
}

void PeEmulation::DeleteMemMapping(ULONG64 MapAddress) {
    for (auto itor = m_MemMappings.begin(); itor != m_MemMappings.end();) {
        if (itor->mappedva == MapAddress) {
            itor = m_MemMappings.erase(itor);
            return;
        } else {
            itor++;
        }
    }
}

bool PeEmulation::WriteMemMapping(ULONG64 baseaddress, ULONG64 value, ULONG size) {
    for (size_t i = 0; i < m_MemMappings.size(); ++i) {
        if (baseaddress >= m_MemMappings[i].mappedva && baseaddress < m_MemMappings[i].mappedva + m_MemMappings[i].size) {
            auto mapaddress = m_MemMappings[i].baseva + (baseaddress - m_MemMappings[i].mappedva);
            m_MemMappings[i].blocks.emplace_back(mapaddress, value, size);
            return true;
        }
    }
    return false;
}

void PeEmulation::FlushMemMapping(void) {
    for (size_t i = 0; i < m_MemMappings.size(); ++i) {
        for (size_t j = 0; j < m_MemMappings[i].blocks.size(); ++j) {
            uc_mem_write(m_uc, m_MemMappings[i].blocks[j].va, &m_MemMappings[i].blocks[j].value, m_MemMappings[i].blocks[j].size);
        }
        m_MemMappings[i].blocks.clear();
    }
}
void WriteMemoryBitmapAccesses(uc_engine* uc, const std::vector<bool>& vec, const std::string& filename, const std::string& prefix) {
    std::vector<uint8_t> buf;
    uintptr_t base = 0x140000000;
    auto begin     = vec.begin();
    auto end       = vec.end();
    auto it        = std::find(begin, end, true);
    while (it != end) {
        uintptr_t start_ea = base + std::distance(begin, it);
        auto end_it        = std::find(it, end, false);
        if (end_it != end) {
            size_t len     = std::distance(it, end_it);
            std::string fn = fmt::format("{}_{:x}_{:x}_{}.bin", prefix, start_ea, len, filename);
            buf.resize(len);
            uc_mem_read(uc, start_ea, buf.data(), len);
            //*outs << "Writing to '" << fn << "'\n";
            file_put_contents(spread_filename(smart_path(fn)).string(), (char*)buf.data(), buf.size(), 1);
        }
        it = std::find(end_it, end, true);
    }
}

void WriteMemoryAccesses(std::vector<std::tuple<uintptr_t, uint8_t>>& vec, const std::string& filename, const std::string& prefix) {
    if (vec.size()) {
        std::sort(vec.begin(), vec.end(), [](const auto& lhs, const auto& rhs) { return std::get<0>(lhs) < std::get<0>(rhs); });
        auto last = std::unique(vec.begin(), vec.end(), [](const auto& lhs, const auto& rhs) { return std::get<0>(lhs) == std::get<0>(rhs); });
        vec.erase(last, vec.end());
        auto len_read                 = vec.size();
        uintptr_t last_address        = 0;
        uintptr_t range_start_address = 0;
        uintptr_t range_start_index   = 0;
        std::vector<uint8_t> to_write;
        for (size_t i = 0; i < len_read; ++i) {
            auto [address, data] = vec[i];
            if (!last_address || last_address + 1 == address) {
                if (!last_address) {
                    range_start_index   = i;
                    range_start_address = address;
                }
                to_write.emplace_back(data);
            } else if (last_address + 1 > address) {
                *outs << "error (unsorted or non-unique list): last_address: " << std::hex << last_address << " address: " << address << "\n";
            } else {
                if (i > range_start_index && !to_write.empty()) {
                    std::string fn = fmt::format("{}_{:x}_{:x}_{}.bin", prefix, range_start_address, to_write.size(), filename);
                    //*outs << "Writing to '" << fn << "'\n";
                    file_put_contents(spread_filename(fn).string(), (char*)to_write.data(), to_write.size(), 1);
                }
                to_write.clear();
                range_start_address = address;
                range_start_index   = i;
                to_write.emplace_back(data);
            }

            last_address = address;
        }
        vec.clear();
    }
}

uc_err patch_nops(uc_engine* uc, uint64_t address, size_t count) {
    // stored as an array of [9][8] (not ragged)
    const unsigned char nop_bytes[][8] = {
        {},
        {0x90},
        {0x66, 0x90},
        {0x0f, 0x1f, 0x00},
        {0x0f, 0x1f, 0x40, 0x00},
        {0x0f, 0x1f, 0x44, 0x00, 0x00},
        {0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00},
        {0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00},
        {0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
    };

    uc_err err = UC_ERR_OK;
    while (err == UC_ERR_OK && count) {
        size_t size = count > 8 ? 8 : count;
        err         = uc_mem_write(uc, address, nop_bytes[size], size);
        count       = count - size;
        address     = address + size;
    }
    return err;
}

void* uc_memcpy(
    uc_engine* uc,
    uintptr_t _Dst,
    void const* _Src,
    size_t _Size) {
    return (void*)((UC_ERR_OK == uc_mem_write(uc, _Dst, _Src, _Size)) ? _Dst : 0);
}

int uc_memcmp(
    uc_engine* uc,
    uintptr_t _Dst,
    void const* _Src,
    size_t _Size) {
    std::vector<uint8_t> buf;
    buf.resize(_Size);
    uc_mem_read(uc, _Dst, buf.data(), buf.size());
    return std::memcmp(buf.data(), _Src, _Size);
}

void* uc_memset(
    uc_engine* uc,
    uintptr_t _Dst,
    int _Val,
    size_t _Size) {
    for (size_t i = 0; i < _Size; ++i) {
        if (UC_ERR_OK != uc_mem_write(uc, _Dst + i, (unsigned char*)(&_Val), 1)) {
            return nullptr;
        }
    }
    return (void*)(_Dst);
}

PeEmulation g_ctx;

int main(int argc, char** argv) {
    using namespace blackbone;

    Timer timer;

    PeEmulation& ctx = g_ctx;

	auto cmdl = argh::parser(argc, argv);
    outs = &std::cout;

    if (!cmdl(1)) {
        printf("usage: unicorn_pe (filename) [--find] [--disasm] [--dump] [--bitmap] [--save-written=PATH] [--save-read=PATH]\n");
        return 0;
    }

    *outs << "Positional args:\n";
    for (auto& pos_arg : cmdl.pos_args())
        *outs << '\t' << pos_arg << '\n';

    *outs << "\nFlags:\n";
    for (auto& flag : cmdl.flags())
        *outs << '\t' << flag << '\n';

    *outs << "\nParameters:\n";
    for (auto& param : cmdl.params())
        *outs << '\t' << param.first << " : " << param.second << '\n';

    *outs << "\nValues for all `--ea` parameters:\n";
    for (auto& param : cmdl.params("ea"))  // iterate on all params called "input"
        *outs << '\t' << param.first << " : " << param.second << '\n';

    *outs << "\nValues for all multiple-use parameters:\n";
    for (const auto& param : _::uniq _VECTOR(std::string) (_::keys2(cmdl.params())))
        if (cmdl.params(param).size() > 1) {
            for (auto& param2 : cmdl.params(param))  // iterate on all params called "input"
                *outs << '\t' << param2.first << " : " << param2.second << '\n';
            *outs << '\n';
        }

    std::string filename;
    cmdl(1) >> filename;
    std::wstring wfilename;
    ANSIToUnicode(smart_path(filename), wfilename);

    bool bKernel = true;
    ctx.m_IsKernel      = cmdl["k"];
    ctx.m_DisplayDisasm = cmdl["disasm"];
    ctx.m_Bitmap        = cmdl["bitmap"];
    ctx.m_IsPacked      = cmdl["packed"];
    ctx.m_BoundCheck    = cmdl["boundcheck"];
    ctx.m_Dump          = cmdl["dump"];
    ctx.m_FindChecks    = cmdl["find"];
    if (cmdl["save-written"]) {
        cmdl("save-written") >> ctx.m_SaveWritten;
        if (!fs::is_directory(ctx.m_SaveWritten)) {
            *outs << "Not a directory: " << ctx.m_SaveWritten << "\n";
            return 0;
        }
        *outs << "Saving memory writes to " << ctx.m_SaveWritten << "\n";
        make_spread_folders(ctx.m_SaveWritten);
    }
    if (cmdl["save-read"]) {
        cmdl("save-read") >> ctx.m_SaveRead;
        if (!fs::is_directory(ctx.m_SaveRead)) {
            *outs << "Not a directory: " << ctx.m_SaveRead << "\n";
            return 0;
        }
        *outs << "Saving memory reads to " << ctx.m_SaveRead << "\n";
        make_spread_folders(ctx.m_SaveRead);
    }

    uc_engine* uc = NULL;
    auto err      = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        printf("failed to uc_open %d\n", err);
        return 0;
    }

    auto err2 = cs_open(CS_ARCH_X86, ctx.m_IsWin64 ? CS_MODE_64 : CS_MODE_32, &ctx.m_cs);
    if (err2) {
        printf("failed to cs_open %d\n", err2);
        return 0;
    }

    ctx.m_uc = uc;
    ctx.thisProc.Attach(GetCurrentProcessId());

    uc_hook trace, trace2, trace3;

    uint64_t stack    = (!ctx.m_IsKernel) ? 0x40000 : 0xFFFFFC0000000000ull;
    size_t stack_size = 0x10000;

    virtual_buffer_t stack_buf;
    if (!stack_buf.GetSpace(stack_size)) {
        printf("failed to allocate virtual stack\n");
        return 0;
    }

    //allocate virtual stack for execution
    memset(stack_buf.GetBuffer(), 0, stack_buf.GetLength());
    uc_mem_map(uc, stack, stack_size, UC_PROT_READ | UC_PROT_WRITE);
    uc_mem_write(uc, stack, stack_buf.GetBuffer(), stack_size);

    ctx.m_StackBase      = stack;
    ctx.m_StackEnd       = stack + stack_size;
    ctx.m_LoadModuleBase = (!ctx.m_IsKernel) ? 0x180000000ull : 0xFFFFF80000000000ull;
    ctx.m_HeapBase       = (!ctx.m_IsKernel) ? 0x10000000ull : 0xFFFFFA0000000000ull;
    ctx.m_HeapEnd        = ctx.m_HeapBase + 0x1000000ull;

    printf("ctx.m_StackBase: 0x%llx\n", ctx.m_StackBase);
    printf("ctx.m_StackEnd: 0x%llx\n", ctx.m_StackEnd);
    printf("ctx.m_LoadModuleBase: 0x%llx\n", ctx.m_LoadModuleBase);
    printf("ctx.m_HeapBase: 0x%llx\n", ctx.m_HeapBase);
    printf("ctx.m_HeapEnd: 0x%llx\n", ctx.m_HeapEnd);

    uc_mem_map(uc, ctx.m_HeapBase, ctx.m_HeapEnd - ctx.m_HeapBase, (ctx.m_IsKernel) ? UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC : UC_PROT_READ | UC_PROT_WRITE);

    auto MapResult = ctx.thisProc.mmap().MapImage(wfilename,
                                                  ManualImports | NoSxS | NoExceptions | NoDelayLoad | NoTLS | NoExceptions | NoExec,
                                                  ManualMapCallback, &ctx, 0, 0x140000000);

    if (!MapResult.success()) {
        printf("failed to MapImage\n");
        return 0;
    }

    auto res = MapResult.result();
    // LDR_DATA_TABLE_ENTRY_BASE_T* p = res->
    ctx.m_ImageBase      = res->baseAddress;
    ctx.m_ImageEnd       = res->baseAddress + res->size;
    ctx.m_ImageEntry     = ctx.m_ImageBase + ExtractEntryPointRva((PVOID)res->imgPtr);
    ctx.m_LastRipModule  = ctx.m_ImageBase;
    ctx.m_ExecuteFromRip = ctx.m_ImageEntry;
    // 143E5F107
    printf("ctx.m_ImageBase: 0x%llx\n", ctx.m_ImageBase);
    printf("ctx.m_ImageEnd: 0x%llx\n", ctx.m_ImageEnd);
    printf("ctx.m_ImageEntry: 0x%llx\n", ctx.m_ImageEntry);
    printf("ctx.m_LastRipModule: 0x%llx\n", ctx.m_LastRipModule);
    printf("ctx.m_ExecuteFromRip: 0x%llx\n", ctx.m_ExecuteFromRip);

    if (!ctx.m_IsKernel) {
        ctx.RegisterAPIEmulation(L"kernel32.dll", "GetSystemTimeAsFileTime", EmuGetSystemTimeAsFileTime, 1);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "GetCurrentThreadId", EmuGetCurrentThreadId, 0);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "GetCurrentProcessId", EmuGetCurrentProcessId, 0);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "QueryPerformanceCounter", EmuQueryPerformanceCounter, 1);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "LoadLibraryExW", EmuLoadLibraryExW, 3);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "LoadLibraryA", EmuLoadLibraryA, 1);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "GetProcAddress", EmuGetProcAddress, 2);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "GetModuleHandleA", EmuGetModuleHandleA, 1);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "GetLastError", EmuGetLastError, 0);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "InitializeCriticalSectionAndSpinCount", EmuInitializeCriticalSectionAndSpinCount, 2);

        if (!ctx.RegisterAPIEmulation(L"kernelbase.dll", "InitializeCriticalSectionEx", EmuInitializeCriticalSectionEx, 3))
            ctx.RegisterAPIEmulation(L"kernel32.dll", "InitializeCriticalSectionEx", EmuInitializeCriticalSectionEx, 3);

        ctx.RegisterAPIEmulation(L"ntdll.dll", "RtlDeleteCriticalSection", EmuDeleteCriticalSection, 1);
        ctx.RegisterAPIEmulation(L"ntdll.dll", "RtlIsProcessorFeaturePresent", EmuRtlIsProcessorFeaturePresent, 1);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "GetProcessAffinityMask", EmuGetProcessAffinityMask, 1);

        ctx.RegisterAPIEmulation(L"kernel32.dll", "TlsAlloc", EmuTlsAlloc, 0);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "TlsSetValue", EmuTlsSetValue, 2);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "TlsFree", EmuTlsFree, 1);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "LocalAlloc", EmuLocalAlloc, 2);
        ctx.RegisterAPIEmulation(L"ntdll.dll", "NtProtectVirtualMemory", EmuNtProtectVirtualMemory, 5);
    } else {
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "ExAllocatePool", EmuExAllocatePool, 2);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "ExAllocatePoolWithTag", EmuExAllocatePool, 3);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "NtQuerySystemInformation", EmuNtQuerySystemInformation, 4);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "ZwQuerySystemInformation", EmuNtQuerySystemInformation, 4);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "ExFreePool", EmuExFreePool, 1);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "ExFreePoolWithTag", EmuExFreePoolWithTag, 2);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "IoAllocateMdl", EmuIoAllocateMdl, 5);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "MmProbeAndLockPages", EmuMmProbeAndLockPages, 3);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "MmMapLockedPagesSpecifyCache", EmuMmMapLockedPagesSpecifyCache, 6);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "KeQueryActiveProcessors", EmuKeQueryActiveProcessors, 0);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "KeSetSystemAffinityThread", EmuKeSetSystemAffinityThread, 1);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "KeRevertToUserAffinityThread", EmuKeRevertToUserAffinityThread, 0);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "MmUnlockPages", EmuMmUnlockPages, 1);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "IoFreeMdl", EmuIoFreeMdl, 1);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "RtlGetVersion", EmuRtlGetVersion, 1);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "DbgPrint", EmuDbgPrint, 1);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "KeInitializeMutex", EmuKeInitializeMutex, 2);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "RtlInitUnicodeString", EmuRtlInitUnicodeString, 2);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "KeWaitForSingleObject", EmuKeWaitForSingleObject, 5);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "KeWaitForMutexObject", EmuKeWaitForSingleObject, 5);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "KeReleaseMutex", EmuKeReleaseMutex, 2);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "srand", Emusrand, 1);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "rand", Emurand, 0);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "RtlZeroMemory", EmuRtlZeroMemory, 2);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "RtlCopyMemory", EmuRtlCopyMemory, 3);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "RtlFillMemory", EmuRtlFillMemory, 3);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "wcsstr", Emuwcsstr, 2);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "MmIsAddressValid", EmuMmIsAddressValid, 1);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "ExGetPreviousMode", EmuExGetPreviousMode, 1);
        ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "__C_specific_handler", Emu__C_specific_handler, 4);
    }

    memset(&ctx.m_InitReg, 0, sizeof(ctx.m_InitReg));
    ctx.m_InitReg.Rsp = ctx.m_StackEnd - 64;

    ctx.InitProcessorState();

    if (!ctx.m_IsKernel) {
        ctx.InitTebPeb();

        ctx.m_InitReg.Rcx = ctx.m_ImageBase;
        ctx.m_InitReg.Rdx = DLL_PROCESS_ATTACH;
        ctx.m_InitReg.R8  = 0;
    } else {
        ctx.SortModuleList();
        ctx.InitPsLoadedModuleList();
        ctx.InitDriverObject();

        ctx.m_InitReg.Rcx = ctx.m_DriverObjectBase;
        ctx.m_InitReg.Rdx = 0;
    }

    ctx.InitKSharedUserData();

    //return to image end when entrypoint is executed
    uc_mem_write(uc, ctx.m_InitReg.Rsp, &ctx.m_ImageEnd, sizeof(ctx.m_ImageEnd));
    uc_mem_map(uc, ctx.m_ImageEnd, 0x1000, UC_PROT_EXEC | UC_PROT_READ);

    uc_reg_write(uc, UC_X86_REG_RAX, &ctx.m_InitReg.Rax);
    uc_reg_write(uc, UC_X86_REG_RBX, &ctx.m_InitReg.Rbx);
    uc_reg_write(uc, UC_X86_REG_RCX, &ctx.m_InitReg.Rcx);
    uc_reg_write(uc, UC_X86_REG_RDX, &ctx.m_InitReg.Rdx);
    uc_reg_write(uc, UC_X86_REG_RSI, &ctx.m_InitReg.Rsi);
    uc_reg_write(uc, UC_X86_REG_RDI, &ctx.m_InitReg.Rdi);
    uc_reg_write(uc, UC_X86_REG_R8, &ctx.m_InitReg.R8);
    uc_reg_write(uc, UC_X86_REG_R9, &ctx.m_InitReg.R9);
    uc_reg_write(uc, UC_X86_REG_R10, &ctx.m_InitReg.R10);
    uc_reg_write(uc, UC_X86_REG_R11, &ctx.m_InitReg.R11);
    uc_reg_write(uc, UC_X86_REG_R12, &ctx.m_InitReg.R12);
    uc_reg_write(uc, UC_X86_REG_R13, &ctx.m_InitReg.R13);
    uc_reg_write(uc, UC_X86_REG_R14, &ctx.m_InitReg.R14);
    uc_reg_write(uc, UC_X86_REG_R15, &ctx.m_InitReg.R15);
    uc_reg_write(uc, UC_X86_REG_RBP, &ctx.m_InitReg.Rbp);
    uc_reg_write(uc, UC_X86_REG_RSP, &ctx.m_InitReg.Rsp);

    uc_hook_add(uc, &trace, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT | UC_HOOK_MEM_WRITE_PROT,
                InvalidRwxCallback, &ctx, 1, 0);

    uc_hook_add(uc, &trace2, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH,
                RwxCallback, &ctx, 1, 0);
    if (ctx.m_DisplayDisasm) {
        uc_hook_add(uc, &trace3, UC_HOOK_CODE,
                    CodeCallback, &ctx, 1, 0);
    }

    uc_hook_add(uc, &trace3, UC_HOOK_INTR,
                IntrCallback, &ctx, 1, 0);

    std::vector<std::tuple<std::string, uintptr_t>> fns;

    uint64_t bytes_written = 0;
    uint64_t bytes_read    = 0;

    if (ctx.m_FindChecks) {
        virtual_buffer_t imagebuf(ctx.m_ImageEnd - ctx.m_ImageBase);
        uc_mem_read(uc, ctx.m_ImageBase, imagebuf.GetBuffer(), ctx.m_ImageEnd - ctx.m_ImageBase);
        mem::region r(imagebuf.GetBuffer(), imagebuf.GetLength());
        std::array<mem::pattern, 1> patterns{mem::pattern("48 8D 05 ?? ?? ?? ?? 48 89 45 ?? 48 8B 05 ?? ?? ?? ?? 48 F7 D8")};

        auto normalise_base = [&](uintptr_t ea) {
            return r.adjust_base(0x140000000, ea).as<uintptr_t>();
            //return ea - (uintptr_t)imagebuf.GetBuffer() + 0x140000000;
        };

        auto iteratee = [&](mem::pointer ea) -> uintptr_t {
            const auto o_rel = 3;
            const auto o_abs = 14;
            // relative address requires normalisation
            const auto rel = normalise_base(ea.add(o_rel).rip(4).as<uintptr_t>());
            // virtual_buffer may be stored at strange location, but the image
            // itself is rebased at 0x140000000 so when extracting an absolute
            // reference, there is no need to normalise.
            const auto abso = ea.add(o_abs).rip(4).deref().as<uintptr_t>();

            if (rel == abso) {
                return abso;
            }
            *outs << fmt::format("find failed at: {:x}: rel: {:x}, abso: {:x}, diff: {:x}",
                                 normalise_base(ea.as<uintptr_t>()), rel, abso, (intptr_t)abso - (intptr_t)rel)
                  << "\n";
            return 0;
        };

        auto iteratee6 = [&](mem::pointer ea) -> uintptr_t {
            const auto o_rel = 14;
            const auto o_abs = 25;
            // relative address requires normalisation
            const auto rel = normalise_base(ea.add(o_rel).rip(4).as<uintptr_t>());
            // virtual_buffer may be stored at strange location, but the image
            // itself is rebased at 0x140000000 so when extracting an absolute
            // reference, there is no need to normalise.
            const auto abso = ea.add(o_abs).rip(4).deref().as<uintptr_t>();

            if (rel == abso) {
                return abso;
            }
            *outs << fmt::format("find failed at: {:x}: rel: {:x}, abso: {:x}, diff: {:x}",
                                 normalise_base(ea.as<uintptr_t>()), rel, abso, (intptr_t)abso - (intptr_t)rel)
                  << "\n";
            return 0;
        };

        auto scan_all_with_iteratee = [](mem::pattern p, mem::region r,
                                         std::function<mem::pointer(mem::pointer)> iter) -> std::vector<mem::pointer> {
            std::vector<mem::pointer> found;
            for (mem::pointer ea : mem::scan_all(p, r)) {
                auto ptr = iter(ea);
                if (ptr) found.emplace_back(ptr);
            }
            return found;
        };

        // return [e for e in FindInSegments(pattern, '.text', None, predicate_checksummers)]
        std::vector<mem::pointer> results;
        for (mem::pattern p : patterns) {
            auto found = scan_all_with_iteratee(p, r, iteratee);
            results.insert(results.end(), found.begin(), found.end());
        }
        auto found = scan_all_with_iteratee(mem::pattern("48 8b 05 ?? ?? ?? ?? 48 89 45 ?? 48 8d 05 ?? ?? ?? ?? 48 89 45"), r, iteratee6);
        results.insert(results.end(), found.begin(), found.end());

        // sort and make unique, then add to list of functions to scan
        std::sort(results.begin(), results.end(), [](const auto& lhs, const auto& rhs) { return lhs < rhs; });
        auto last = std::unique(results.begin(), results.end(), [](const auto& lhs, const auto& rhs) { return lhs == rhs; });
        results.erase(last, results.end());
        for (auto ptr : results) {
            fns.emplace_back(fmt::format("CheckFunc_{:x}", ptr.as<uintptr_t>()), ptr.as<uintptr_t>());
        }
        *outs << "Found " << fns.size() << " matching functions\n";
    }

    if (fns.empty()) {
        ctx.filename = filename;
        *outs << "Filename: " << ctx.filename << "\n";

        if (fs::exists("e:/ida/gtasc-2612/names.json")) {
            std::ifstream infile("e:/ida/gtasc-2612/names.json");
            json j;
            infile >> j;

            for (auto& [name, value] : j.items()) {
                if (value.is_number() && !value.empty() /* && value[0].is_array() && value[0].size() == 2*/) {
                    auto [it1, happy1] = megaFuncFull.emplace(value, name);
                    //if (!happy1) {
                    //    auto existing = it1->second;
                    //    if (name != existing) {
                    //        //LOG_TRACE(__FUNCTION__ ": '0x14%07x' existing key '%s' clashed with '%s', overwriting.", start, existing.c_str(), name.c_str());
                    //        megaFuncFull[start] = name;
                    //    }
                    //}
                }
            }
        }

        //uintptr_t base_address           = 0x140000000;
        //base_address                     = ctx.m_ImageEnd;
        //const uintptr_t prologue_address = base_address + 0x100;
        //uintptr_t dst                    = 0x140CBC8B1;
        //err                              = uc_mem_write(uc, prologue_address, prologue_bytes, sizeof(prologue_bytes));
        //err                              = uc_mem_write(uc, prologue_address + sizeof(prologue_bytes), &dst, 8);
        uintptr_t dst = ctx.m_ExecuteFromRip;

        mbs(0x140d8d394).nop(5);            // skip making all segments writable
        mbs(0x143bbdb2f).jmp(0x140D03816);  // skip executable tamper check
        mbs(0x141894D99).jmp(0x143A99FEE);  // skip segment size check
        // mbs(0x1417db93c).jmp(0x1417ed648); // skip initial decrypt
        // mbs(0x144874514).write_pattern("c3");

        //src = asList(ArxanGetNextRangeGen('guide_143BE1040'));
        //dst = asList(ArxanGetNextRangeGen('guide2_1432CBD71'));
        //for d, s in zip(dst, src) : ida_bytes.patch_bytes(d[0], ida_bytes.get_bytes(s[0], s[1]))
        uc_mem_write(uc, ctx.m_InitReg.Rsp, &ctx.m_ImageEnd, sizeof(ctx.m_ImageEnd));
        uc_mem_map(uc, ctx.m_ImageEnd, 0x1000, UC_PROT_EXEC | UC_PROT_READ);

        uc_reg_write(uc, UC_X86_REG_RAX, &ctx.m_InitReg.Rax);
        uc_reg_write(uc, UC_X86_REG_RBX, &ctx.m_InitReg.Rbx);
        uc_reg_write(uc, UC_X86_REG_RCX, &ctx.m_InitReg.Rcx);
        uc_reg_write(uc, UC_X86_REG_RDX, &ctx.m_InitReg.Rdx);
        uc_reg_write(uc, UC_X86_REG_RSI, &ctx.m_InitReg.Rsi);
        uc_reg_write(uc, UC_X86_REG_RDI, &ctx.m_InitReg.Rdi);
        uc_reg_write(uc, UC_X86_REG_R8, &ctx.m_InitReg.R8);
        uc_reg_write(uc, UC_X86_REG_R9, &ctx.m_InitReg.R9);
        uc_reg_write(uc, UC_X86_REG_R10, &ctx.m_InitReg.R10);
        uc_reg_write(uc, UC_X86_REG_R11, &ctx.m_InitReg.R11);
        uc_reg_write(uc, UC_X86_REG_R12, &ctx.m_InitReg.R12);
        uc_reg_write(uc, UC_X86_REG_R13, &ctx.m_InitReg.R13);
        uc_reg_write(uc, UC_X86_REG_R14, &ctx.m_InitReg.R14);
        uc_reg_write(uc, UC_X86_REG_R15, &ctx.m_InitReg.R15);
        uc_reg_write(uc, UC_X86_REG_RBP, &ctx.m_InitReg.Rbp);
        uc_reg_write(uc, UC_X86_REG_RSP, &ctx.m_InitReg.Rsp);

        *outs << "Function: " << ctx.filename << "\n";
        if (ctx.m_Bitmap) {
            ctx.m_WrittenBitmap.resize(ctx.m_ImageEnd - ctx.m_ImageBase);
        }
        while (1) {
            virtual_buffer_t imagebuf(ctx.m_ImageEnd - ctx.m_ImageBase);
            uc_mem_read(uc, ctx.m_ImageBase, imagebuf.GetBuffer(), ctx.m_ImageEnd - ctx.m_ImageBase);

            HexDump::dumpMemory(*outs, (char*)imagebuf.GetBuffer() + dst - 0x140000000, 1024);
            err = uc_emu_start(uc, ctx.m_ExecuteFromRip /*prologue_address*/, /*0x14334099C */ /*prologue_address + sizeof(prologue_bytes) - 1 */ ctx.m_ImageEnd, 0, 0);

            if (ctx.m_LastException != STATUS_SUCCESS) {
                auto except         = ctx.m_LastException;
                ctx.m_LastException = STATUS_SUCCESS;
                ctx.RtlRaiseStatus(except);
            } else {
                break;
            }
        }
        uint64_t result_rsp = 0;
        uc_reg_read(uc, UC_X86_REG_RSP, &result_rsp);
        *outs << "RSP: 0x" << std::hex << result_rsp << "\n"
              << std::dec;
        auto ptr        = result_rsp;
        uintptr_t value = 0xdeadbeef;
        for (ptr = 0x4ffb8; ptr > 0x4ff50; ptr -= 8) {
            ptrdiff_t i = ptr - result_rsp;
            uc_mem_read(uc, ptr, &value, 8);
            *outs << "uc_emu_start stack: " << std::hex << 0x140CBC8B1 << std::dec << " " << i << ": 0x" << std::hex << ptr << ": 0x" << std::hex << ctx.NormaliseBase(value) << std::dec << "\n";
            if (i == 0) break;
        }

        fs::path read_path(ctx.m_SaveRead);
        fs::path written_path(ctx.m_SaveWritten);

        read_path /= read_path / "read";
        written_path = written_path / "written";

        if (ctx.m_Bitmap) {
            WriteMemoryBitmapAccesses(uc, ctx.m_WrittenBitmap, ctx.filename, written_path.lexically_normal().string());
        } else {
            bytes_written += ctx.m_Written.size();
            bytes_read += ctx.m_Read.size();
            WriteMemoryAccesses(ctx.m_Read, ctx.filename, read_path.lexically_normal().string());
            WriteMemoryAccesses(ctx.m_Written, ctx.filename, written_path.lexically_normal().string());
            *outs << "bytes written: " << bytes_written << " bytes read: " << bytes_read << "\n";
        }

    } else
        for (const auto& tpl : fns) {
            ctx.filename = std::get<0>(tpl);

            /*
        // Copy of StackBalance to create proper stack for execution of code (prologue_address)
		
			140001000  6A 01                                         push    1
			140001002  6A 02                                         push    2
			140001004  6A 03                                         push    3
			140001006  6A 04                                         push    4
			140001008
			140001008                                TheJudge:
			140001008  E8 01 00 00 00                                call    TheWitch
			14000100D  CC                                            int     3
			14000100E
			14000100E
			14000100E                                TheWitch:
			14000100E  E8 01 00 00 00                                call    TheCorpsegrinder
			140001013  CC                                            int     3
			140001014
			140001014
			140001014                                TheCorpsegrinder:
			140001014  E8 01 00 00 00                                call    TheBalancer
			140001019  CC                                            int     3
			14000101A
			14000101A
			14000101A                                TheBalancer:
			14000101A  41 50                                         push    r8
			14000101C  41 55                                         push    r13
			14000101E  41 54                                         push    r12
			140001020  41 57                                         push    r15
			140001022  56                                            push    rsi
			140001023  52                                            push    rdx
			140001024  53                                            push    rbx
			140001025  41 51                                         push    r9
			140001027  50                                            push    rax
			140001028  41 56                                         push    r14
			14000102A  41 52                                         push    r10
			14000102C  57                                            push    rdi
			14000102D  41 53                                         push    r11
			14000102F  48 8D A4 24 00 FF FF FF                       lea     rsp, [rsp-100h]
			140001037  66 44 0F 11 3C 24                             movupd  xmmword ptr [rsp], xmm15
			14000103D  66 0F 11 7C 24 10                             movupd  xmmword ptr [rsp+10h], xmm7
			140001043  66 0F 11 5C 24 20                             movupd  xmmword ptr [rsp+20h], xmm3
			140001049  66 44 0F 11 54 24 30                          movupd  xmmword ptr [rsp+30h], xmm10
			140001050  66 0F 11 74 24 40                             movupd  xmmword ptr [rsp+40h], xmm6
			140001056  66 0F 11 6C 24 50                             movupd  xmmword ptr [rsp+50h], xmm5
			14000105C  66 0F 11 4C 24 60                             movupd  xmmword ptr [rsp+60h], xmm1
			140001062  66 44 0F 11 4C 24 70                          movupd  xmmword ptr [rsp+70h], xmm9
			140001069  66 44 0F 11 B4 24 80 00 00 00                 movupd  xmmword ptr [rsp+80h], xmm14
			140001073  66 44 0F 11 84 24 90 00 00 00                 movupd  xmmword ptr [rsp+90h], xmm8
			14000107D  66 44 0F 11 A4 24 A0 00 00 00                 movupd  xmmword ptr [rsp+0A0h], xmm12
			140001087  66 0F 11 94 24 B0 00 00 00                    movupd  xmmword ptr [rsp+0B0h], xmm2
			140001090  66 44 0F 11 9C 24 C0 00 00 00                 movupd  xmmword ptr [rsp+0C0h], xmm11
			14000109A  66 0F 11 84 24 D0 00 00 00                    movupd  xmmword ptr [rsp+0D0h], xmm0
			1400010A3  66 44 0F 11 AC 24 E0 00 00 00                 movupd  xmmword ptr [rsp+0E0h], xmm13
			1400010AD  66 0F 11 A4 24 F0 00 00 00                    movupd  xmmword ptr [rsp+0F0h], xmm4
			1400010AD
			1400010B6  6A 10                                         push    10h
			1400010B8  48 F7 C4 0F 00 00 00                          test    rsp, 0Fh
			1400010BF  75 02                                         jnz     short skip_balance
			1400010C1  6A 18                                         push    18h
			1400010C3
			1400010C3                                skip_balance:
			1400010C3  48 83 EC 08                                   sub     rsp, 8
			1400010C7  FF 15 A2 00 00 00                             call    qword ptr cs:TheChecker
			1400010CD  48 03 64 24 08                                add     rsp, [rsp+8]
			1400010D2  66 44 0F 10 3C 24                             movupd  xmm15, xmmword ptr [rsp]
			1400010D8  66 0F 10 7C 24 10                             movupd  xmm7, xmmword ptr [rsp+10h]
			1400010DE  66 0F 10 5C 24 20                             movupd  xmm3, xmmword ptr [rsp+20h]
			1400010E4  66 44 0F 10 54 24 30                          movupd  xmm10, xmmword ptr [rsp+30h]
			1400010EB  66 0F 10 74 24 40                             movupd  xmm6, xmmword ptr [rsp+40h]
			1400010F1  66 0F 10 6C 24 50                             movupd  xmm5, xmmword ptr [rsp+50h]
			1400010F7  66 0F 10 4C 24 60                             movupd  xmm1, xmmword ptr [rsp+60h]
			1400010FD  66 44 0F 10 4C 24 70                          movupd  xmm9, xmmword ptr [rsp+70h]
			140001104  66 44 0F 10 B4 24 80 00 00 00                 movupd  xmm14, xmmword ptr [rsp+80h]
			14000110E  66 44 0F 10 84 24 90 00 00 00                 movupd  xmm8, xmmword ptr [rsp+90h]
			140001118  66 44 0F 10 A4 24 A0 00 00 00                 movupd  xmm12, xmmword ptr [rsp+0A0h]
			140001122  66 0F 10 94 24 B0 00 00 00                    movupd  xmm2, xmmword ptr [rsp+0B0h]
			14000112B  66 44 0F 10 9C 24 C0 00 00 00                 movupd  xmm11, xmmword ptr [rsp+0C0h]
			140001135  66 0F 10 84 24 D0 00 00 00                    movupd  xmm0, xmmword ptr [rsp+0D0h]
			14000113E  66 44 0F 10 AC 24 E0 00 00 00                 movupd  xmm13, xmmword ptr [rsp+0E0h]
			140001148  66 0F 10 A4 24 F0 00 00 00                    movupd  xmm4, xmmword ptr [rsp+0F0h]
			140001151  48 8D A4 24 00 01 00 00                       lea     rsp, [rsp+100h]
			140001159  41 5B                                         pop     r11
			14000115B  5F                                            pop     rdi
			14000115C  41 5A                                         pop     r10
			14000115E  41 5E                                         pop     r14
			140001160  58                                            pop     rax
			140001161
			140001161  41 59                                         pop     r9
			140001163  5B                                            pop     rbx
			140001164  5A                                            pop     rdx
			140001165  5E                                            pop     rsi
			140001166  41 5F                                         pop     r15
			140001168  41 5C                                         pop     r12
			14000116A  41 5D                                         pop     r13
			14000116C  41 58                                         pop     r8
			14000116E  C3                                            retn
			14000116E
			14000116F                                TheChecker:
			14000116F  00 00 00 00 00 00 00 00                       dq    0
		*/

            unsigned char prologue_bytes[] = {
                0x6a, 0x1, 0x6a, 0x2, 0x6a, 0x3, 0x6a, 0x4, 0xe8, 0x1, 0x0, 0x0, 0x0, 0xcc,
                0xe8, 0x1, 0x0, 0x0, 0x0, 0xcc, 0xe8, 0x1, 0x0, 0x0, 0x0, 0xcc, 0x41, 0x50,
                0x41, 0x55, 0x41, 0x54, 0x41, 0x57, 0x56, 0x52, 0x53, 0x41, 0x51, 0x50, 0x41,
                0x56, 0x41, 0x52, 0x57, 0x41, 0x53, 0x48, 0x8d, 0xa4, 0x24, 0x0, 0xff, 0xff,
                0xff, 0x66, 0x44, 0xf, 0x11, 0x3c, 0x24, 0x66, 0xf, 0x11, 0x7c, 0x24, 0x10,
                0x66, 0xf, 0x11, 0x5c, 0x24, 0x20, 0x66, 0x44, 0xf, 0x11, 0x54, 0x24, 0x30,
                0x66, 0xf, 0x11, 0x74, 0x24, 0x40, 0x66, 0xf, 0x11, 0x6c, 0x24, 0x50, 0x66,
                0xf, 0x11, 0x4c, 0x24, 0x60, 0x66, 0x44, 0xf, 0x11, 0x4c, 0x24, 0x70, 0x66,
                0x44, 0xf, 0x11, 0xb4, 0x24, 0x80, 0x0, 0x0, 0x0, 0x66, 0x44, 0xf, 0x11, 0x84,
                0x24, 0x90, 0x0, 0x0, 0x0, 0x66, 0x44, 0xf, 0x11, 0xa4, 0x24, 0xa0, 0x0, 0x0,
                0x0, 0x66, 0xf, 0x11, 0x94, 0x24, 0xb0, 0x0, 0x0, 0x0, 0x66, 0x44, 0xf, 0x11,
                0x9c, 0x24, 0xc0, 0x0, 0x0, 0x0, 0x66, 0xf, 0x11, 0x84, 0x24, 0xd0, 0x0, 0x0,
                0x0, 0x66, 0x44, 0xf, 0x11, 0xac, 0x24, 0xe0, 0x0, 0x0, 0x0, 0x66, 0xf, 0x11,
                0xa4, 0x24, 0xf0, 0x0, 0x0, 0x0, 0x6a, 0x10, 0x48, 0xf7, 0xc4, 0xf, 0x0, 0x0,
                0x0, 0x75, 0x2, 0x6a, 0x18, 0x48, 0x83, 0xec, 0x8, 0xff, 0x15, 0xa2, 0x0, 0x0,
                0x0, 0x48, 0x3, 0x64, 0x24, 0x8, 0x66, 0x44, 0xf, 0x10, 0x3c, 0x24, 0x66, 0xf,
                0x10, 0x7c, 0x24, 0x10, 0x66, 0xf, 0x10, 0x5c, 0x24, 0x20, 0x66, 0x44, 0xf,
                0x10, 0x54, 0x24, 0x30, 0x66, 0xf, 0x10, 0x74, 0x24, 0x40, 0x66, 0xf, 0x10,
                0x6c, 0x24, 0x50, 0x66, 0xf, 0x10, 0x4c, 0x24, 0x60, 0x66, 0x44, 0xf, 0x10,
                0x4c, 0x24, 0x70, 0x66, 0x44, 0xf, 0x10, 0xb4, 0x24, 0x80, 0x0, 0x0, 0x0, 0x66,
                0x44, 0xf, 0x10, 0x84, 0x24, 0x90, 0x0, 0x0, 0x0, 0x66, 0x44, 0xf, 0x10, 0xa4,
                0x24, 0xa0, 0x0, 0x0, 0x0, 0x66, 0xf, 0x10, 0x94, 0x24, 0xb0, 0x0, 0x0, 0x0,
                0x66, 0x44, 0xf, 0x10, 0x9c, 0x24, 0xc0, 0x0, 0x0, 0x0, 0x66, 0xf, 0x10, 0x84,
                0x24, 0xd0, 0x0, 0x0, 0x0, 0x66, 0x44, 0xf, 0x10, 0xac, 0x24, 0xe0, 0x0, 0x0,
                0x0, 0x66, 0xf, 0x10, 0xa4, 0x24, 0xf0, 0x0, 0x0, 0x0, 0x48, 0x8d, 0xa4, 0x24,
                0x0, 0x1, 0x0, 0x0, 0x41, 0x5b, 0x5f, 0x41, 0x5a, 0x41, 0x5e, 0x58, 0x41, 0x59,
                0x5b, 0x5a, 0x5e, 0x41, 0x5f, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x58, 0xc3};

            uintptr_t base_address           = 0x140000000;
            base_address                     = ctx.m_ImageEnd;
            const uintptr_t prologue_address = base_address + 0x100;
            uintptr_t dst                    = std::get<1>(tpl);
            err                              = uc_mem_write(uc, prologue_address, prologue_bytes, sizeof(prologue_bytes));
            err                              = uc_mem_write(uc, prologue_address + sizeof(prologue_bytes), &dst, 8);

            uc_mem_write(uc, ctx.m_InitReg.Rsp, &ctx.m_ImageEnd, sizeof(ctx.m_ImageEnd));
            uc_mem_map(uc, ctx.m_ImageEnd, 0x1000, UC_PROT_EXEC | UC_PROT_READ);

            uc_reg_write(uc, UC_X86_REG_RAX, &ctx.m_InitReg.Rax);
            uc_reg_write(uc, UC_X86_REG_RBX, &ctx.m_InitReg.Rbx);
            uc_reg_write(uc, UC_X86_REG_RCX, &ctx.m_InitReg.Rcx);
            uc_reg_write(uc, UC_X86_REG_RDX, &ctx.m_InitReg.Rdx);
            uc_reg_write(uc, UC_X86_REG_RSI, &ctx.m_InitReg.Rsi);
            uc_reg_write(uc, UC_X86_REG_RDI, &ctx.m_InitReg.Rdi);
            uc_reg_write(uc, UC_X86_REG_R8, &ctx.m_InitReg.R8);
            uc_reg_write(uc, UC_X86_REG_R9, &ctx.m_InitReg.R9);
            uc_reg_write(uc, UC_X86_REG_R10, &ctx.m_InitReg.R10);
            uc_reg_write(uc, UC_X86_REG_R11, &ctx.m_InitReg.R11);
            uc_reg_write(uc, UC_X86_REG_R12, &ctx.m_InitReg.R12);
            uc_reg_write(uc, UC_X86_REG_R13, &ctx.m_InitReg.R13);
            uc_reg_write(uc, UC_X86_REG_R14, &ctx.m_InitReg.R14);
            uc_reg_write(uc, UC_X86_REG_R15, &ctx.m_InitReg.R15);
            uc_reg_write(uc, UC_X86_REG_RBP, &ctx.m_InitReg.Rbp);
            uc_reg_write(uc, UC_X86_REG_RSP, &ctx.m_InitReg.Rsp);

            /*

			Function: StackChecksumActual3_239
			RSP: 0x4ff88
			uc_emu_start stack: 140a5c90e 48: 0x4ffb8: 0x1
			uc_emu_start stack: 140a5c90e 40: 0x4ffb0: 0x2
			uc_emu_start stack: 140a5c90e 32: 0x4ffa8: 0x3
			uc_emu_start stack: 140a5c90e 24: 0x4ffa0: 0x140cc3aaf
			uc_emu_start stack: 140a5c90e 16: 0x4ff98: 0x143ea1e55
			uc_emu_start stack: 140a5c90e 8: 0x4ff90: 0x143dcbfe2
			uc_emu_start stack: 140a5c90e 0: 0x4ff88: 0x140001019
			uc_emu_start stack: 140a5c90e -8: 0x4ff80: 0x0
			uc_emu_start stack: 140a5c90e -16: 0x4ff78: 0x0
			uc_emu_start stack: 140a5c90e -24: 0x4ff70: 0x0
			uc_emu_start stack: 140a5c90e -32: 0x4ff68: 0x0
			uc_emu_start stack: 140a5c90e -40: 0x4ff60: 0x0
			uc_emu_start stack: 140a5c90e -48: 0x4ff58: 0x1
		*/

            *outs << "Function: " << ctx.filename << "\n";
            while (1) {
                err = uc_emu_start(uc, /*ctx.m_ExecuteFromRip*/ prologue_address, prologue_address + sizeof(prologue_bytes) - 1 /* ctx.m_ImageEnd */, 0, 0);

                if (ctx.m_LastException != STATUS_SUCCESS) {
                    auto except         = ctx.m_LastException;
                    ctx.m_LastException = STATUS_SUCCESS;
                    ctx.RtlRaiseStatus(except);
                } else {
                    break;
                }
            }
            uint64_t result_rsp = 0;
            uc_reg_read(uc, UC_X86_REG_RSP, &result_rsp);
            *outs << "RSP: 0x" << std::hex << result_rsp << "\n"
                  << std::dec;
            auto ptr        = result_rsp;
            uintptr_t value = 0xdeadbeef;
            for (ptr = 0x4ffb8; ptr > 0x4ff50; ptr -= 8) {
                ptrdiff_t i = ptr - result_rsp;
                uc_mem_read(uc, ptr, &value, 8);
                *outs << "uc_emu_start stack: " << std::hex << std::get<1>(tpl) << std::dec << " " << i << ": 0x" << std::hex << ptr << ": 0x" << std::hex << ctx.NormaliseBase(value) << std::dec << "\n";
                if (i == 0) break;
            }

            fs::path read_path(ctx.m_SaveRead);
            fs::path written_path(ctx.m_SaveWritten);

            read_path /= read_path / "read";
            written_path = written_path / "written";

            bytes_written += ctx.m_Written.size();
            bytes_read += ctx.m_Read.size();
            WriteMemoryAccesses(ctx.m_Read, ctx.filename, read_path.lexically_normal().string());
            WriteMemoryAccesses(ctx.m_Written, ctx.filename, written_path.lexically_normal().string());
            *outs << "bytes written: " << bytes_written << " bytes read: " << bytes_read << "\n";
        }

    uc_hook_del(uc, trace);
    uc_hook_del(uc, trace2);
    uc_hook_del(uc, trace3);

    uint64_t result_rax = 0;
    uc_reg_read(uc, UC_X86_REG_RAX, &result_rax);

    if (ctx.m_Dump) {
        virtual_buffer_t imagebuf(ctx.m_ImageEnd - ctx.m_ImageBase);
        virtual_buffer_t RebuildSectionBuffer;

        uc_mem_read(uc, ctx.m_ImageBase, imagebuf.GetBuffer(), ctx.m_ImageEnd - ctx.m_ImageBase);

        auto ntheader = RtlImageNtHeader(imagebuf.GetBuffer());

        auto SectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)ntheader + sizeof(ntheader->Signature) +
                                                     sizeof(ntheader->FileHeader) + ntheader->FileHeader.SizeOfOptionalHeader);

        auto SectionCount = ntheader->FileHeader.NumberOfSections;
        for (USHORT i = 0; i < SectionCount; ++i) {
            SectionHeader[i].PointerToRawData = SectionHeader[i].VirtualAddress;
            SectionHeader[i].SizeOfRawData    = SectionHeader[i].Misc.VirtualSize;
        }

        // ctx.RebuildSection(imagebuf.GetBuffer(), (ULONG)(ctx.m_ImageEnd - ctx.m_ImageBase), RebuildSectionBuffer);

        if (ctx.m_ImageRealEntry)
            ntheader->OptionalHeader.AddressOfEntryPoint = (ULONG)(ctx.m_ImageRealEntry - ctx.m_ImageBase);

        auto dumpfile = filename + ".upeed";

        FILE* fp = fopen(dumpfile.c_str(), "wb");

        fwrite(imagebuf.GetBuffer(), ctx.m_ImageEnd - ctx.m_ImageBase, 1, fp);

        if (RebuildSectionBuffer.GetBuffer())
            fwrite(RebuildSectionBuffer.GetBuffer(), RebuildSectionBuffer.GetLength(), 1, fp);

        fclose(fp);
    }

    uc_close(uc);

    cs_close(&ctx.m_cs);

    ctx.thisProc.mmap().UnmapAllModules();

    *outs << "bytes written: " << bytes_written << " bytes read: " << bytes_read << "\n";
    *outs << "uc_emu_start return: " << std::dec << err << "\n";
    *outs << "entrypoint return: " << std::hex << result_rax << "\n";
    *outs << "last rip: " << std::hex << ctx.m_LastRip;
    timer.ShowElapsed();

    std::stringstream rip_region, realentry_region;
    if (ctx.FindAddressInRegion(ctx.m_LastRip, rip_region))
        *outs << " (" << rip_region.str() << ")\n";

    if (ctx.m_ImageRealEntry) {
        if (ctx.FindAddressInRegion(ctx.m_ImageRealEntry, realentry_region))
            *outs << "real entrypoint: " << realentry_region.str() << "\n";
    }

    *outs << "\n";

    outs->flush();

    return 0;
}
