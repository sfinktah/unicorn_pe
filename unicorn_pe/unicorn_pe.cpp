#define NOMINMAX
#include <unicorn/unicorn.h>
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
#include <deque>
#include <map>
#include <utility>

#ifdef USE_BOOST
#include <boost/config.hpp>
#include <boost/circular_buffer.hpp>
#endif

#include <fmt/format.h>
#include <fmt/printf.h>
#include <lodash/026_slice.h>
#include <pystring/pystring.h>
#include "sniffing/nowide/convert.hpp"
using namespace nowide;

#include "buffer.h"
#include "encode.h"
#include "nativestructs.h"
#include "ucpe.h"
#include "emuapi.h"
#include "iat.h"

// #include <curl/curl.h>
//#include <restclient-cpp/restclient.h>
#include "Filesystem.hpp"
#include "FuncTailInsn.h"
#include "util.hpp"
#include "distorm_plug.h"
#include "multimatches.h"

#include "./argh.h"
#include "../vendor/mem/include/mem/mem.h"
#include "../vendor/mem/include/mem/pattern.h"
#include <nlohmann/json.hpp>
#include "sniffing/HexDump.h"
#include "membricksafe.hpp"
#include "../vendor/lodash/071_join.h"
#include "../vendor/lodash/075_first.h"
#include "../vendor/lodash/095_uniq.h"
#include "../vendor/lodash/121_times.h"
#include "s_multimatch.h"
#include "MegaFunc.h"
#include "BraceExpander.h"
#include "WhitespaceTokeniser.h"
#include "FileUtils.h"
#include "YasmExt.h"

using json = nlohmann::json;
using namespace blackbone;
using mbs = membricksafe::memBrickSafe;
std::forward_list<PATCH_ENTRY> membricksafe::g_patches;

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Wldap32.Lib")
#pragma comment(lib, "Crypt32.Lib")
#pragma comment(lib, "fmt.lib")
#pragma comment(lib, "pystring.lib")

std::ostream* outs;

#define LOG_ADDR_N(X) *outs << #X << ": " << std::hex << normalise_base(X.as<uintptr_t>()) << std::dec << std::endl
#define LOG_ADDR(X) *outs << #X << ": " << std::hex << X.as<uintptr_t>() << std::dec << std::endl
//#define LOG(X, ...) (*outs << fmt::format((X), ##__VA_ARGS__) << "\n")

extern "C" {
    NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(IN PVOID BaseAddress);
    NTSYSAPI PVOID NTAPI RtlImageDirectoryEntryToData(PVOID BaseAddress, BOOLEAN MappedAsImage, USHORT Directory, PULONG Size);
}

void* patch_nops(void* ptr, size_t count);
uint64_t EmuReadReturnAddress(uc_engine* uc);
bool EmuReadNullTermUnicodeString(uc_engine* uc, uint64_t address, std::wstring& str);
bool EmuReadNullTermString(uc_engine* uc, uint64_t address, std::string& str);
void mem_parser(PeEmulation& ctx, const std::string& _line, uintptr_t& _RESULT, argh::parser&);

static ULONG ExtractEntryPointRva(PVOID ModuleBase) { return RtlImageNtHeader(ModuleBase)->OptionalHeader.AddressOfEntryPoint; }
std::map<uint64_t, std::string> megaFuncNames;

template <typename Container>
uc_err uc_mem_write(uc_engine* uc, uint64_t address, const Container& obj) {
    using value_t = typename Container::value_type;
    using size_e  = sizeof value_t;
    return uc_mem_write(uc, uint64_t address, std::data(obj), size_e * std::size(obj));
}

uintptr_t PreManualMapCallback(int type, blackbone::pe::PEImage& peImage, const void* data) {
    if (type == 0) {
        auto ntheader = RtlImageNtHeader(peImage._pFileBase);

        DWORD SectionAlignment;

        if (ntheader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            auto ntheader64  = ntheader;
            SectionAlignment = ntheader64->OptionalHeader.SectionAlignment;
        } else {
            SectionAlignment = ntheader->OptionalHeader.SectionAlignment;
        }

        auto SectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)ntheader + sizeof(ntheader->Signature) + sizeof(ntheader->FileHeader) + ntheader->FileHeader.SizeOfOptionalHeader);

        auto correct_size = ntheader->OptionalHeader.BaseOfCode;

        for (WORD i = 0; i < ntheader->FileHeader.NumberOfSections; i++) {
            auto SectionSize = ALIGN_UP_MIN1(std::max(SectionHeader[i].Misc.VirtualSize, SectionHeader[i].SizeOfRawData), SectionAlignment);

            *outs << fmt::format("{:8} {:8x} [{:8x}] {:8x} [{:8x}] {:8x} {:8x}", SectionHeader[i].Name, SectionHeader[i].Misc.VirtualSize, SectionSize, SectionHeader[i].VirtualAddress, correct_size, SectionHeader[i].SizeOfRawData, SectionHeader[i].PointerToRawData) << "\n";

            correct_size += SectionSize;
        }

        LOG("ImageBase: {:8x}", peImage._imgBase);
        LOG("ImageSize: {:8x} [{:8x}]", peImage._imgSize, correct_size);

        peImage._imgSize = correct_size; /*PAGE_ALIGN_UP(peImage._imgSize);*/
                                         // disable DYNAMIC_BASE stop us rebase the image (even to it's original location)
        // peImage._DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

        //*outs << "SectionSize: " << std::hex << PeEmulation::RebuildSectionSizes(peImage._pFileBase, 0) << "\n";
        // auto hdr2 = peImage._pImageHdr64;
        // blackbone::pe::PEImage::PCHDR64 hdr = data;
        // peImage._imgBase            = pImageHeader->OptionalHeader.ImageBase;
        // peImage._imgSize            = pImageHeader->OptionalHeader.SizeOfImage;
        // peImage._hdrSize            = pImageHeader->OptionalHeader.SizeOfHeaders;
        // peImage._epRVA              = pImageHeader->OptionalHeader.AddressOfEntryPoint;
        // peImage._subsystem          = pImageHeader->OptionalHeader.Subsystem;
        // peImage._DllCharacteristics = pImageHeader->OptionalHeader.DllCharacteristics;
        // peImage._imgSize = 0x3ed4000;
    }
    return 0;
};

blackbone::LoadData ManualMapCallback(blackbone::CallbackType type, void* context, blackbone::Process& process, const blackbone::ModuleData& modInfo) {
    PeEmulation* ctx = (PeEmulation*)context;
    if (type == blackbone::PreCallback) {
        uint64_t desiredBase         = ctx->m_LoadModuleBase;
        uint64_t desiredNextLoadBase = PAGE_ALIGN_64k(ctx->m_LoadModuleBase + (uint64_t)modInfo.size + 0x10000ull);
        ctx->m_LoadModuleBase        = desiredNextLoadBase;

        return blackbone::LoadData(blackbone::MT_Default, blackbone::Ldr_None, ctx->m_LoadModuleBase);
    } else if (type == blackbone::PostCallback) {
        //                            name imgptr      size    base      AddressOfEntryPoint (.text)
        // ManualMapCallback: original.exe 2386e3a0000 3ed3c00 140000000 1415faff0
        //*outs << "ManualMapCallback: " << fmt::format("{} {:x} {:x} {:x}", narrow(modInfo.name), (ULONG64)modInfo.imgPtr, modInfo.size, modInfo.baseAddress)
        //      << "\n";
        if (pystring::endswith(narrow(modInfo.name), ".exe")) {
            // HexDump::dumpMemory(*outs, (char*)modInfo.imgPtr, 256);
        }
        ctx->MapImageToEngine(modInfo.name, (PVOID)modInfo.imgPtr, modInfo.size, modInfo.baseAddress, (ULONG64)modInfo.baseAddress + ExtractEntryPointRva((PVOID)modInfo.imgPtr));
    } else if (type == blackbone::ImageCallback) {  // Called after actually reading image file, but before image loading.
                                                    // ModuleData tmpData;
                                                    // tmpData.baseAddress = 0;
                                                    // tmpData.manual = ((pImage->flags & ManualImports) != 0);
                                                    // tmpData.fullPath = path;
                                                    // tmpData.name = Utils::ToLower(Utils::StripPath(path));
                                                    // tmpData.size = pImage->peImage.imageSize();
                                                    // tmpData.type = pImage->peImage.mType();
                                                    // tmpData.entryPoint = 0;
                                                    // tmpData.ldrPtr = 0;
                                                    // tmpData.imgPtr = pImage->imgMem.ptr();
                                                    // ManualMapCallback: ImageCallback xxx - original - 323.1 - cff.exe 0 3ed4000 0
                                                    // ManualMapCallback: ImageCallback xxx-original-323.1.exe           0 3ed3c00 0
        //*outs << "ManualMapCallback: ImageCallback" << fmt::format("{} {:x} {:x} {:x}", narrow(modInfo.name), (ULONG64)modInfo.imgPtr, modInfo.size, modInfo.baseAddress)
        //      << "\n";
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
    FakeAPI_t* r = nullptr;
    for (size_t i = 0; i < m_FakeModules.size(); ++i) {
        auto& m = m_FakeModules[i];
        if (!_wcsicmp(m->DllName.c_str(), DllName.c_str())) {
            for (size_t j = 0; j < m->FakeAPIs.size(); ++j) {
                if (m->FakeAPIs[j].ProcedureName == ProcedureName) {
                    AddAPIEmulation(&m->FakeAPIs[j], callback, argsCount);
                    // LOG("registered API emulation for {} in {} at {:#x}", ProcedureName, narrow(m->DllName), m->FakeAPIs[j].VirtualAddress);
                    return true;
                }
            }
            *outs << "failed to register API emulation for " << ProcedureName << "\n";
            return false;
        }
    }
    LOG("failed to find DLL {} for API emulation of {}", narrow(DllName), ProcedureName);
    return false;
}

uintptr_t PeEmulation::NormaliseBase(ULONG64 address, ULONG64 base) const {
    auto i = m_FakeModules.size() - 1;
    if (address >= m_FakeModules[i]->ImageBase && address < m_FakeModules[i]->ImageBase + m_FakeModules[i]->ImageSize) {
        address = address - m_FakeModules[i]->ImageBase + base;
    }
    return address;
}

bool PeEmulation::FindAddressInRegion(ULONG64 address, std::stringstream& RegionName) {
    auto last_module = m_FakeModules.size() - 1;
    for (size_t i = 0; i < m_FakeModules.size(); ++i) {
        if (address >= m_FakeModules[i]->ImageBase && address < m_FakeModules[i]->ImageBase + m_FakeModules[i]->ImageSize) {
            std::string dllname;
            if (i == last_module) {
                RegionName << std::hex << (address - m_FakeModules[i]->ImageBase + 0x140000000) << " ";
            }
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

bool PeEmulation::OldFindAPIByAddress(ULONG64 address, std::wstring& DllName, FakeAPI_t** api) {
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

    // well that shit didn't work, lets do it the old fashioned way

    FakeAPI_t* r = nullptr;
    for (size_t i = 0; i < m_FakeModules.size(); ++i) {
        auto& m = m_FakeModules[i];
        for (size_t j = 0; j < m->FakeAPIs.size(); ++j) {
            if (m->FakeAPIs[j].VirtualAddress == address) {
                // AddAPIEmulation(&m->FakeAPIs[j], callback, argsCount);
                // LOG("found call to {} in {} at {:#x}", m->FakeAPIs[j].ProcedureName, narrow(m->DllName), m->FakeAPIs[j].VirtualAddress);
                *api    = &m->FakeAPIs[j];
                DllName = m->DllName;
                return true;
            }
        }
        //*outs << "failed to find API emulation in " << narrow(m->DllName) << "\n";
    }
    // LOG("failed to find API emulation for {:#x}", address);
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
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &uExportSize);

    if (!pImageExportDirectory) return;

    DWORD dwNumberOfNames        = pImageExportDirectory->NumberOfNames;
    DWORD* pAddressOfFunction    = (DWORD*)((PUCHAR)ImageBase + pImageExportDirectory->AddressOfFunctions);
    DWORD* pAddressOfNames       = (DWORD*)((PUCHAR)ImageBase + pImageExportDirectory->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((PUCHAR)ImageBase + pImageExportDirectory->AddressOfNameOrdinals);

    for (size_t i = 0; i < dwNumberOfNames; i++) {
        char* strFunction = (char*)((PUCHAR)ImageBase + pAddressOfNames[i]);

        DWORD functionRva = pAddressOfFunction[pAddressOfNameOrdinals[i]];
        // forward
        if ((PUCHAR)ImageBase + functionRva >= (PUCHAR)pImageExportDirectory && (PUCHAR)ImageBase + functionRva < (PUCHAR)pImageExportDirectory + uExportSize) {
            char* strForward         = (char*)ImageBase + functionRva;
            char* strForwardFunction = strchr(strForward, '.');
            if (strForwardFunction) {
                std::string strForwardDll(strForward, strForwardFunction - strForward);
                strForwardDll += ".dll";
                // LOG("{} fowards {} to {}", narrow(module->DllName), strFunction, strForwardDll);
                ULONG64 ForwardDllBase = 0;
                std::wstring wszForwardDll;
                ANSIToUnicode(strForwardDll, wszForwardDll);
                if (NT_SUCCESS(LdrFindDllByName(wszForwardDll, &ForwardDllBase, NULL, true))) {
                    ULONG64 ForwardFunction = LdrGetProcAddress(ForwardDllBase, strForwardFunction + 1);
                    if (ForwardFunction) module->FakeAPIs.emplace_back(strFunction, ForwardFunction);
                }
            }
        } else {
            // LOG("{} exports {}", narrow(module->DllName), strFunction);
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
        if (ImageBase) *ImageBase = moduleptr->baseAddress;
        if (ImageSize) *ImageSize = moduleptr->size;

        return STATUS_SUCCESS;
    }

    if (LoadIfNotExist) return LdrLoadDllByName(newDllName, ImageBase, ImageSize);

    return STATUS_OBJECT_NAME_NOT_FOUND;
}

NTSTATUS PeEmulation::LdrLoadDllByName(const std::wstring& DllName, ULONG64* ImageBase, ULONG* ImageSize) {
    using namespace blackbone;

    auto MapResult = thisProc.mmap().MapImage(DllName, ManualImports | NoSxS | NoDelayLoad | NoExceptions | NoTLS | NoExceptions, ManualMapCallback, this);

    if (!MapResult.success()) {
        // printf("LdrLoadDllByName failed to MapImage %ws, status %08X\n", DllName.c_str(), MapResult.status);
        return MapResult.status;
    }

    return STATUS_SUCCESS;
}

static void CodeCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);

static void RwxCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);

static void EmuUnknownAPI(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);

void PeEmulation::MapImageToEngine(const std::wstring& ImageName, PVOID ImageBase, ULONG ImageSize, ULONG64 MappedBase, ULONG64 EntryPoint) {
    // MapImageToEngine(xxx-original-323.1.exe,     1e58a010000, 3ed3c00, 140000000, 1415faff0
    // MapImageToEngine(xxx-original-323.1-cff.exe, 26c21410000, 3ed4000, 140000000, 1415faff0
    // 0xd4000 - 0xd3c00 = 0x400
    // ManualMapCallback:xxx-original-323.1-cff.exe 26c21410000, 3ed4000, 140000000

#ifdef _DEBUG
    *outs << fmt::format("MapImageToEngine({}, {:x}, {:x}, {:x}, {:x}\n", narrow(ImageName), (uintptr_t)ImageBase, ImageSize, MappedBase, EntryPoint);
#endif
    FakeModule_t* mod = new FakeModule_t(MappedBase, ImageSize, EntryPoint, ImageName);
    //_DllCharacteristics = pImageHeader->OptionalHeader.DllCharacteristics;

    if (!_wcsicmp(ImageName.c_str(), L"ntoskrnl.exe"))
        mod->Priority = 100;
    else if (!_wcsicmp(ImageName.c_str(), L"hal.dll"))
        mod->Priority = 99;

    auto ExceptionTable = RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &mod->ExceptionTableSize);

    mod->ExceptionTable = MappedBase + ((PUCHAR)ExceptionTable - (PUCHAR)ImageBase);

    RtlInsertInvertedFunctionTable(&m_PsInvertedFunctionTable, MappedBase, ImageBase, ImageSize);

    m_FakeModules.push_back(mod);

    LdrResolveExportTable(mod, ImageBase, MappedBase);

    uint64_t image_base = MappedBase;
    uint64_t image_end  = PAGE_ALIGN_64(image_base + ImageSize);

    if (image_end != image_base)
        uc_mem_map(m_uc, image_base, image_end - image_base, UC_PROT_READ);
    else
        uc_mem_map(m_uc, image_base, PAGE_SIZE, UC_PROT_READ);

    bool isExe = false;
    if (pystring::endswith(narrow(ImageName), ".exe")) {
        *outs << fmt::format("MappedBase: {:x}\n", image_base);
        isExe = true;
        virtual_buffer_t buf(ImageSize);
        memcpy(buf.GetBuffer(), ImageBase, ImageSize);
        IMAGE_OPTIONAL_HEADER* ohead;  // rax
        IMAGE_FILE_HEADER* fhead;      // rax MAPDST
        IMAGE_SECTION_HEADER* shead;   // [rsp+28h] [rbp+8h]
        unsigned int i;                // [rsp+3Ch] [rbp+1Ch]

        fhead = Get_IMAGE_FILE_HEADER((IMAGE_DOS_HEADER*)buf.GetBuffer());
        if (!fhead) return;
        ohead = Get_IMAGE_OPTIONAL_HEADER(fhead);
        shead = (IMAGE_SECTION_HEADER*)&ohead->DataDirectory[ohead->NumberOfRvaAndSizes];
        i     = 0;
        while (i++ < fhead->NumberOfSections) {
            auto& size    = shead->Misc.VirtualSize;
            auto old_size = size;
            size          = PAGE_ALIGN_UP_MIN1(size);
            // if (size != old_size) {
            //    *outs << fmt::format("{:16} VirtualSize {:8x} -> {:8x}\n", shead->Name, old_size, size);
            //} else
            //    *outs << fmt::format("{:16} VirtualSize {:8x}\n", shead->Name, old_size);
            ++shead;
        }
        // uc_mem_write(m_uc, image_base, buf.GetBuffer(), ImageSize);
    } else {
        // uc_mem_write(m_uc, image_base, ImageBase, ImageSize);
    }
    uc_mem_write(m_uc, image_base, ImageBase, ImageSize);

    auto ntheader = RtlImageNtHeader(ImageBase);

    DWORD SectionAlignment;

    if (ntheader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        auto ntheader64  = ntheader;
        SectionAlignment = ntheader64->OptionalHeader.SectionAlignment;
    } else {
        SectionAlignment = ntheader->OptionalHeader.SectionAlignment;
    }

    auto SectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)ntheader + sizeof(ntheader->Signature) + sizeof(ntheader->FileHeader) + ntheader->FileHeader.SizeOfOptionalHeader);

    // xxx-original-323.1.exe          .text     1717c00     1000  1717c00      600
    // xxx-original-323.1.exe          BINK          c00  1719000      c00  1718200
    // xxx-original-323.1.exe          BINKBSS        60  171a000        0        0
    // xxx-original-323.1.exe          .rdata     369800  171b000   369800  1718e00
    // xxx-original-323.1.exe          .data      ffa4e8  1a85000   20a000  1a82600
    // xxx-original-323.1.exe          .pdata      f1000  2a80000    f1000  1c8c600
    // xxx-original-323.1.exe          .tls          a00  2b71000      a00  1d7d600
    // xxx-original-323.1.exe          BINKCONS      200  2b72000      200  1d7e000
    // xxx-original-323.1.exe          .rsrc       2de00  2b73000    2de00  1d7e200
    // xxx-original-323.1.exe          .reloc      d5600  2ba1000    d5600  1dac000
    // xxx-original-323.1.exe          .text     125cc00  2c77000  125cc00  1e81600
    //.text            VirtualSize  1717c00 ->  1718000
    // BINK             VirtualSize      c00 ->     1000
    // BINKBSS          VirtualSize       60 ->     1000
    //.rdata           VirtualSize   369800 ->   36a000
    //.data            VirtualSize   ffa4e8 ->   ffb000
    //.pdata           VirtualSize    f1000
    //.tls             VirtualSize      a00 ->     1000
    // BINKCONS         VirtualSize      200 ->     1000
    //.rsrc            VirtualSize    2de00 ->    2e000
    //.reloc           VirtualSize    d5600 ->    d6000
    //.text            VirtualSize  125cc00 ->  125d000
    // xxx-original-323.1.exe          .text     1717c00     1000  1717c00      600
    // xxx-original-323.1.exe          BINK          c00  1719000      c00  1718200
    // xxx-original-323.1.exe          BINKBSS        60  171a000        0        0
    // xxx-original-323.1.exe          .rdata     369800  171b000   369800  1718e00
    // xxx-original-323.1.exe          .data      ffa4e8  1a85000   20a000  1a82600
    // xxx-original-323.1.exe          .pdata      f1000  2a80000    f1000  1c8c600
    // xxx-original-323.1.exe          .tls          a00  2b71000      a00  1d7d600
    // xxx-original-323.1.exe          BINKCONS      200  2b72000      200  1d7e000
    // xxx-original-323.1.exe          .rsrc       2de00  2b73000    2de00  1d7e200
    // xxx-original-323.1.exe          .reloc      d5600  2ba1000    d5600  1dac000
    // xxx-original-323.1.exe          .text     125cc00  2c77000  125cc00  1e81600

    //                                 Name      VirtualSize         VirtualAddresss     RawSize  RawAddr
    // xxx-original-323.1-cff.exe      .text     1718000 [ 1718000]     1000 [    1000]  1717c00      600 + 1717c00
    // xxx-original-323.1-cff.exe      BINK         1000 [    1000]  1719000 [ 1719000]      c00  1718200 +    1e00 -.
    // xxx-original-323.1-cff.exe      BINKBSS      1000 [    1000]  171a000 [ 171a000]     1000  171a000 -   -1200  '
    // xxx-original-323.1-cff.exe      .rdata     36a000 [  36a000]  171b000 [ 171b000]   369800  1718e00 +     c00 -'
    // xxx-original-323.1-cff.exe      .data      ffb000 [  ffb000]  1a85000 [ 1a85000]   20a000  1a82600
    // xxx-original-323.1-cff.exe      .pdata      f1000 [   f1000]  2a80000 [ 2a80000]    f1000  1c8c600
    // xxx-original-323.1-cff.exe      .tls         1000 [    1000]  2b71000 [ 2b71000]      a00  1d7d600
    // xxx-original-323.1-cff.exe      BINKCONS     1000 [    1000]  2b72000 [ 2b72000]      200  1d7e000
    // xxx-original-323.1-cff.exe      .rsrc       2e000 [   2e000]  2b73000 [ 2b73000]    2de00  1d7e200
    // xxx-original-323.1-cff.exe      .reloc      d6000 [   d6000]  2ba1000 [ 2ba1000]    d5600  1dac000
    // xxx-original-323.1-cff.exe      .text     125cc00 [ 125d000]  2c77000 [ 2c77000]  125cc00  1e81600

    // xxx-original-323.1.exe          .text     1717c00 [ 1718000]     1000 [    1000]  1717c00      600
    // xxx-original-323.1.exe          BINK          c00 [    1000]  1719000 [ 1719000]      c00  1718200
    // xxx-original-323.1.exe          BINKBSS        60 [    1000]  171a000 [ 171a000]        0        0
    // xxx-original-323.1.exe          .rdata     369800 [  36a000]  171b000 [ 171b000]   369800  1718e00
    // xxx-original-323.1.exe          .data      ffa4e8 [  ffb000]  1a85000 [ 1a85000]   20a000  1a82600
    // xxx-original-323.1.exe          .pdata      f1000 [   f1000]  2a80000 [ 2a80000]    f1000  1c8c600
    // xxx-original-323.1.exe          .tls          a00 [    1000]  2b71000 [ 2b71000]      a00  1d7d600
    // xxx-original-323.1.exe          BINKCONS      200 [    1000]  2b72000 [ 2b72000]      200  1d7e000
    // xxx-original-323.1.exe          .rsrc       2de00 [   2e000]  2b73000 [ 2b73000]    2de00  1d7e200
    // xxx-original-323.1.exe          .reloc      d5600 [   d6000]  2ba1000 [ 2ba1000]    d5600  1dac000
    // xxx-original-323.1.exe          .text     125cc00 [ 125d000]  2c77000 [ 2c77000]  125cc00  1e81600

    // xxx-original-323.1-scylla-fixed .text     1718000 [ 1718000]     1000 [    1000]  1717c00      600
    // xxx-original-323.1-scylla-fixed BINK         1000 [    1000]  1719000 [ 1719000]      c00  1718200
    // xxx-original-323.1-scylla-fixed BINKBSS      1000 [    1000]  171a000 [ 171a000]        0        0
    // xxx-original-323.1-scylla-fixed .rdata     36a000 [  36a000]  171b000 [ 171b000]   369800  1718e00
    // xxx-original-323.1-scylla-fixed .data      ffb000 [  ffb000]  1a85000 [ 1a85000]   20a000  1a82600
    // xxx-original-323.1-scylla-fixed .pdata      f1000 [   f1000]  2a80000 [ 2a80000]    f1000  1c8c600
    // xxx-original-323.1-scylla-fixed .tls         1000 [    1000]  2b71000 [ 2b71000]      a00  1d7d600
    // xxx-original-323.1-scylla-fixed BINKCONS     1000 [    1000]  2b72000 [ 2b72000]      200  1d7e000
    // xxx-original-323.1-scylla-fixed .rsrc       2e000 [   2e000]  2b73000 [ 2b73000]    2de00  1d7e200
    // xxx-original-323.1-scylla-fixed .reloc      d6000 [   d6000]  2ba1000 [ 2ba1000]    d5600  1dac000
    // xxx-original-323.1-scylla-fixed .text     125d000 [ 125d000]  2c77000 [ 2c77000]  125cc00  1e81600

    // ManualMapCallback: ImageCallback xxx - original - 323.1 - cff.exe 0 3ed4000 0
    // ManualMapCallback: ImageCallback xxx-original-323.1.exe           0 3ed3c00 0
    // 0x3ed3000

    auto correct_size = ntheader->OptionalHeader.BaseOfCode;

    for (WORD i = 0; i < ntheader->FileHeader.NumberOfSections; i++) {
        //*outs << fmt::format("{:32} {:8} {:8x} [{:8x}] {:8x} [{:8x}] {:8x} {:8x}",
        //                     narrow(ImageName),
        //                     SectionHeader[i].Name,
        //                     SectionHeader[i].Misc.VirtualSize,
        //                     size,
        //                     SectionHeader[i].VirtualAddress,
        //                     correct_size,
        //                     SectionHeader[i].SizeOfRawData,
        //                     SectionHeader[i].PointerToRawData)
        //      << "\n";

        int prot = UC_PROT_READ | UC_PROT_EXEC | UC_PROT_WRITE;
        if (SectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) prot |= UC_PROT_EXEC;
        if (SectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) prot |= UC_PROT_WRITE;

        auto SectionSize = ALIGN_UP_MIN1(std::max(SectionHeader[i].Misc.VirtualSize, SectionHeader[i].SizeOfRawData), SectionAlignment);

        correct_size += SectionSize;

        uc_mem_protect(m_uc, image_base + SectionHeader[i].VirtualAddress, SectionSize, prot);

        if (SectionHeader[i].Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)) {
            bool bIsUnknownSection = !(0 == memcmp(SectionHeader[i].Name, ".text\0\0\0", 8) || 0 == memcmp(SectionHeader[i].Name, "INIT\0\0\0\0", 8) || 0 == memcmp(SectionHeader[i].Name, "PAGE\0\0\0\0", 8));

            mod->FakeSections.emplace_back(SectionHeader[i].VirtualAddress, SectionSize, (char*)SectionHeader[i].Name, bIsUnknownSection);

            uc_hook trace3;
            uc_hook_add(m_uc, &trace3, UC_HOOK_CODE, EmuUnknownAPI, this, image_base + SectionHeader[i].VirtualAddress, image_base + SectionHeader[i].VirtualAddress + SectionSize - 1);
        }
    }
}

#ifdef USE_BOOST
// CircularBuffer<FuncTailInsn, 128> history;
static boost::circular_buffer<FuncTailInsn> history(32);
#endif

void advance_rip(uc_engine* uc, int offset) {
    uintptr_t rip;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    rip += offset;
    uc_reg_write(uc, UC_X86_REG_RIP, &rip);
}

void set_rip(uc_engine* uc, uintptr_t rip) {
    uintptr_t _rip;
    uc_reg_read(uc, UC_X86_REG_RIP, &_rip);
    uc_reg_write(uc, UC_X86_REG_RIP, &rip);
    LOG("set_rip {:x} -> {:x}", _rip, rip);
}

uintptr_t adjust_rsp(uc_engine* uc, int offset) {
    uintptr_t rsp;
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    rsp += offset;
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
    return rsp;
}

uintptr_t uc_rip(uc_engine* uc) {
    uintptr_t rip;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    return rip;
}

uintptr_t uc_qword(uc_engine* uc, uintptr_t addr) {
    uintptr_t rip = 0;
    uc_mem_read(uc, addr, &rip, sizeof(rip));
    return rip;
}

template <typename T = uintptr_t>
T uc_peek(uc_engine* uc) {
    T value;
    uintptr_t rsp;
    if (!uc_reg_read(uc, UC_X86_REG_RSP, &rsp))
        if (!uc_mem_read(uc, rsp, &value, sizeof(value))) return value;
    LOG("error uc_pop");
    return {};
}

template <typename T>
uc_err uc_push(uc_engine* uc, T value) {
    uintptr_t val64 = (uintptr_t)value;
    return uc_mem_write(uc, adjust_rsp(uc, -8), &val64, sizeof(val64));
}

template <typename T>
T uc_pop(uc_engine* uc) {
    T value = uc_peek<uintptr_t>(uc);
    adjust_rsp(uc, +8);
    return value;
}

uintptr_t uc_call(uc_engine* uc, uintptr_t target, uintptr_t source) {
    if (source == 0) source = uc_rip(uc);
    uc_push(uc, source);
    set_rip(uc, target);
    return source;
}

uintptr_t uc_ret(uc_engine* uc, int stack_adjust) {
    adjust_rsp(uc, stack_adjust);
    auto retto = uc_pop<uintptr_t>(uc);
    set_rip(uc, retto);
    return retto;
}

static std::set<uintptr_t> visited;
static std::map<std::string, size_t> insn_count;
static std::set<uintptr_t> call_targets;

size_t Disassemble(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    PeEmulation* ctx = (PeEmulation*)user_data;

    /*uc_reg_read(uc, UC_X86_REG_EFLAGS, &ctx->m_InitReg.EFlags);
    ctx->m_InitReg.EFlags |= (1 << 8);
    uc_reg_write(uc, UC_X86_REG_EFLAGS, &ctx->m_InitReg.EFlags);*/

    const uint64_t virtualBase    = ctx->NormaliseBase(address);
    mem::region rr(ctx->m_ImageBase, ctx->m_ImageEnd - ctx->m_ImageBase);
    auto ripadd = [&](const std::string& str, uintptr_t rip, uintptr_t& abso) {
        if (~pystring::find(str, "[rip ")) {
            auto splut = preg_split(" ([-+]) ", pystring::rstrip(str, "]"), MAXINT, PREG_SPLIT_DELIM_CAPTURE);
            if (splut.size() == 3) {
                abso = (rip + parseInt(pystring::strip(splut[1]) + splut[2], 16));
                // LOG("abso: {:x}", abso);
                return fmt::format("[rel {:#x}]", abso);
            }
        }
        return str;
    };

    auto [it, suc] = visited.emplace(address);
    if (suc) {

        unsigned char codeBuffer[15];
        uc_mem_read(uc, address, codeBuffer, size);

        cs_insn* insn;
        // memset(&insn, 0, sizeof(insn));

        int64_t rsp;
        uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
        uint8_t* code = codeBuffer;
        size_t codeSize = size;
        auto count = cs_disasm(ctx->m_cs, code, codeSize, virtualBase, 0, &insn);
        if (count) {
            int ii = 0;

            std::string op_string = insn[ii].op_str;
            // regex = r"\b(rip[+-]0x[0-9a-f]+)"
            // operand = re.sub(regex, lambda m: ripadd(m.group(), ea + size), operand, 0, re.IGNORECASE)
            uintptr_t rip_rel_addr = 0;
            if (~pystring::find(op_string, "[rip ")) {
                std::vector<std::string> splut;
                pystring::split(op_string, splut, ", ");
                op_string = _::join_array(_::map2(splut, [&](const std::string& s) { return ripadd(s, ctx->NormaliseBase(address + insn->size), rip_rel_addr); }), ", ");
            }

            op_string = preg_replace(" ([-+]) ", R"($1)", op_string.c_str());
            auto mnem = insn[ii].mnemonic;
            std::string mnem_str(mnem);
            auto disasm = pystring::rstrip(fmt::format("{} {}", mnem, op_string));

            {
                auto op_string2 = regex_replace(op_string, std::regex(R"(\b0x14[0-9a-fA-F]{7})"), [=](const std::smatch& m) {
                    auto match = m.str();
                    auto index = m.position();
                    std::string prefix(m.str());
                    prefix += ":";

                    // TODO: these won't work if base is not 0x140000000
                    if (auto _addr = asQword(match.c_str(), 16)) {
                        uintptr_t addr = *_addr;
                        uintptr_t next_addr = 0;

                        while (UC_ERR_OK == uc_mem_read(ctx->m_uc, addr, &next_addr, 8)) {
                            if (auto it = megaFuncNames.find(ctx->NormaliseBase(addr, 0)); it != megaFuncNames.end()) {
                                return fmt::format("{}{}", prefix, it->second);
                            }
                            if (megafunc && megafunc->Contains(ctx->NormaliseBase(addr, 0))) {
                                return pystring::rstrip(megafunc->Lookup(ctx->NormaliseBase(addr, 0)));
                            }

                            std::wstring DllName;
                            FakeAPI_t* api = nullptr;
                            if (ctx->FindAPIByAddress(addr, DllName, &api)) {
                                return fmt::format("{}{}!{}", prefix, narrow(DllName), api->ProcedureName);
                            }

                            prefix += "&";
                            addr = next_addr;
                        }
                    }
                    return match;
                    });

                std::stringstream region2;
                if (ctx->FindAddressInRegion(address, region2)) {
                    if (megafunc)
                        *outs << megafunc->Lookup(virtualBase - 0x140000000) << "\t\t" << std::hex << 0x50000 - rsp << "\t" << std::dec << mnem << "\t\t" << op_string2 << "\n";
                    else
                        *outs << std::hex << region2.str() << "\t\t" << std::hex << 0x50000 - rsp << "\t" << std::dec << mnem << "\t\t" << op_string2 << "\n";
                }
                else {
                    *outs << std::hex << virtualBase << "\t\t" << 0x50000 - rsp << "\t" << std::dec << mnem << "\t\t" << op_string2 << "\n";
                }
                cs_free(insn, count);
            }
        }
        else {
            *outs << "No count: " << std::hex << address << std::dec << " " << size << " " << HexDump::dumpMemory((uint8_t*)address, size);
        }
        return count;
    }
    return -1;
}


static void CodeCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    PeEmulation* ctx = (PeEmulation*)user_data;

    /*uc_reg_read(uc, UC_X86_REG_EFLAGS, &ctx->m_InitReg.EFlags);
    ctx->m_InitReg.EFlags |= (1 << 8);
    uc_reg_write(uc, UC_X86_REG_EFLAGS, &ctx->m_InitReg.EFlags);*/

    ctx->FlushMemMapping();

    ctx->CurrentInstruction = address;
    ctx->CurrentInstructionLength = size;

    if (ctx->m_Disassemble || ctx->m_RewriteRsp) {
        static bool was_disassembling = true;
        const uint64_t virtualBase    = ctx->NormaliseBase(address);
        mem::region rr(ctx->m_ImageBase, ctx->m_ImageEnd - ctx->m_ImageBase);
        auto ripadd = [&](const std::string& str, uintptr_t rip, uintptr_t& abso) {
            if (~pystring::find(str, "[rip ")) {
                auto splut = preg_split(" ([-+]) ", pystring::rstrip(str, "]"), MAXINT, PREG_SPLIT_DELIM_CAPTURE);
                if (splut.size() == 3) {
                    abso = (rip + parseInt(pystring::strip(splut[1]) + splut[2], 16));
                    // LOG("abso: {:x}", abso);
                    return fmt::format("[rel {:#x}]", abso);
                }
            }
            return str;
        };

        auto [it, suc] = visited.emplace(address);
#ifdef USE_BOOST
        if (suc && (ctx->m_Disassemble)) {
            unsigned char codeBuffer[15];
            uc_mem_read(uc, address, codeBuffer, size);

            virtual_buffer_based_t vbuf(size, address);
            memcpy(vbuf.GetBuffer(), codeBuffer, size);
            emu_disassemble(vbuf, 0, 0, [&](const FuncTailInsn& fti) {
                m_Instructions.emplace_back(fti);
                size_t index = m_Instructions.size() - 1;
                *outs << color_disasm(pystring::lower(fti.asString())) << std::endl;
                if (pystring::startswith(fti.asString(), "jmp 0x") ||
                    pystring::startswith(fti.asString(), "nop")
                ) {
                    __nop();
                }
                else {
                    for (auto& mm : multimatches) {
                        mm.test(m_Instructions, index, fti);
                    }
                }


                return false;
                });
        }
#endif

        if (suc && (ctx->m_DisassembleForce || ctx->m_RewriteRsp)) {
            was_disassembling = true;
            unsigned char codeBuffer[15];
            uc_mem_read(uc, address, codeBuffer, size);

#ifdef USE_BOOST
            virtual_buffer_based_t vbuf(size, address);
            memcpy(vbuf.GetBuffer(), codeBuffer, size);
            emu_disassemble(vbuf, 0, 0, [&](const FuncTailInsn& fti) {
                m_Instructions.emplace_back(fti);
                size_t index = m_Instructions.size() - 1;
                *outs << pystring::lower(fti.asString()) << std::endl;
                for (auto& mm : multimatches) {
                    mm.test(m_Instructions, index, fti);
                }


                return false;
            });
#endif

            cs_insn* insn;
            // memset(&insn, 0, sizeof(insn));

            int64_t rsp;
            uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
            uint8_t* code   = codeBuffer;
            size_t codeSize = size;
            auto count      = cs_disasm(ctx->m_cs, code, codeSize, virtualBase, 0, &insn);
            if (count) {
                int ii = 0;

                std::string op_string = insn[ii].op_str;
                // regex = r"\b(rip[+-]0x[0-9a-f]+)"
                // operand = re.sub(regex, lambda m: ripadd(m.group(), ea + size), operand, 0, re.IGNORECASE)
                uintptr_t rip_rel_addr = 0;
                if (~pystring::find(op_string, "[rip ")) {
                    std::vector<std::string> splut;
                    pystring::split(op_string, splut, ", ");
                    op_string = _::join_array(_::map2(splut, [&](const std::string& s) { return ripadd(s, ctx->NormaliseBase(address + insn->size), rip_rel_addr); }), ", ");
                }

                op_string = preg_replace(" ([-+]) ", R"($1)", op_string.c_str());
                auto mnem = insn[ii].mnemonic;
                std::string mnem_str(mnem);
                auto disasm = pystring::rstrip(fmt::format("{} {}", mnem, op_string));

                // if (mnem == "xchg") {
                //    auto& xchg_count = insn_count[mnem];
                //    xchg_count       = xchg_count + 1;
                //    if (xchg_count == 1) {

                //    }
                //}
                if (ctx->m_RewriteRsp) {
                    static uintptr_t last_self_ptr = 0;
                    auto e_rsp                     = 0x50000 - rsp;
                    // e = 50 - r
                    // e + r = 50
                    // r = 50 - e
                    if (e_rsp == 0x1f0 && mnem_str == "call") {
                        // This really shouldn't be needed, but... hmmmm
                        last_self_ptr = parseUint(op_string, 16);
                        ctx->m_BalanceEntry = last_self_ptr;
                        LOG("call {:x}", last_self_ptr);
                    } else if (e_rsp == 0x200 && !ctx->m_RewriteRspDone) {
                        ctx->m_RewriteRspDone   = true;
                        uintptr_t resume_target = ctx->m_ImageEnd + 0x100 + 0x144b741c6 - 0x144b74100 + 6;
                        uc_mem_write(uc, 0x50000 - 0x1f8, &resume_target, sizeof(resume_target));
                        if (!ctx->m_BalanceEntry)
                            ctx->m_BalanceEntry = virtualBase;
                        LOG("rewrote RSP to {:x}", resume_target);
                    } else if (e_rsp > 0x200) {
                        if (rip_rel_addr && (mnem_str == "lea" || mnem_str == "mov") && op_string[0] == 'r') {
                            uintptr_t this_ptr;
                            if (mnem_str == "lea") {
                                this_ptr = rip_rel_addr;
                                // LOG("lea: {:x}", this_ptr);
                            } else {
                                this_ptr = uc_qword(uc, rip_rel_addr);
                                // LOG("mov: {:x}", this_ptr);
                            }
                            LOG("lea/mov target address is {:x}", this_ptr);
                            if (this_ptr != 0x140000000) {
                                if (ctx->m_BalanceEntry) {
                                    LOG("already set starting address to {:x}", ctx->m_BalanceEntry);
                                }
                                if (this_ptr == last_self_ptr) {
                                    if (!ctx->m_BalanceEntry) {
                                        ctx->m_BalanceEntry = this_ptr;
                                    }
                                    ctx->m_RewriteRsp   = false;
                                    if (this_ptr == ctx->m_BalanceEntry) {
                                        LOG("starting address confirmed as {:x}", this_ptr);
                                        
                                    }
                                    else {
                                        LOG("starting address is {:x}", this_ptr);
                                    }
                                } else {
                                    LOG("tentative starting address is {:x}", this_ptr);
                                    last_self_ptr = this_ptr;
                                }
                            }
                        }
                    }
                }

                if (ctx->m_SkipSecondCall || ctx->m_SkipFourthCall) {
                    if (!strcmp(mnem, "call")) {
                        char* errch      = nullptr;
                        uintptr_t target = strtoull(op_string.c_str(), &errch, 16);
                        if (*errch != '\0') {
                            *outs << "call operand couldn't be converted to ll: " << op_string << "\n";
                            return;
                        }

                        auto [iter, inserted] = call_targets.emplace(target);
                        if (inserted) {
                            ctx->m_Calls.emplace_back(ctx->NormaliseBase(address, 0), ctx->NormaliseBase(address + insn[ii].size + mem::pointer(code - 4).as<int32_t&>(), 0));
                            if (megafunc) op_string = megafunc->Lookup(target);
                            auto& call_count = insn_count[mnem];
                            call_count       = call_count + 1;
                            *outs << fmt::format("{} {} used {} times with unique target\n", mnem, op_string, call_count);
                            if ((ctx->m_SkipSecondCall && call_count == 2)) {
                                *outs << "skipping call " << call_count << " to " << op_string << "\n";
                                advance_rip(uc, 5);
                                ctx->m_SkipSecondCall = false;
                                return;
                            }
                            if ((ctx->m_SkipFourthCall && call_count == 4)) {
                                *outs << "skipping call " << call_count << " to " << op_string << "\n";
                                advance_rip(uc, 5);
                                ctx->m_SkipFourthCall = false;
                                return;
                            }
                        }
                    }
                }
                {
                    auto op_string2 = regex_replace(op_string, std::regex(R"(\b0x14[0-9a-fA-F]{7})"), [=](const std::smatch& m) {
                        auto match = m.str();
                        auto index = m.position();
                        std::string prefix(m.str());
                        prefix += ":";

                        // TODO: these won't work if base is not 0x140000000
                        if (auto _addr = asQword(match.c_str(), 16)) {
                            uintptr_t addr      = *_addr;
                            uintptr_t next_addr = 0;

                            while (UC_ERR_OK == uc_mem_read(ctx->m_uc, addr, &next_addr, 8)) {
                                if (auto it = megaFuncNames.find(ctx->NormaliseBase(addr, 0)); it != megaFuncNames.end()) {
                                    return fmt::format("{}{}", prefix, it->second);
                                }
                                if (megafunc && megafunc->Contains(ctx->NormaliseBase(addr, 0))) {
                                    return pystring::rstrip(megafunc->Lookup(ctx->NormaliseBase(addr, 0)));
                                }

                                std::wstring DllName;
                                FakeAPI_t* api = nullptr;
                                if (ctx->FindAPIByAddress(addr, DllName, &api)) {
                                    return fmt::format("{}{}!{}", prefix, narrow(DllName), api->ProcedureName);
                                }

                                prefix += "&";
                                addr = next_addr;
                            }
                        }
                        return match;
                    });

                    std::stringstream region2;
                    if (ctx->FindAddressInRegion(address, region2)) {
                        if (megafunc)
                            *outs << megafunc->Lookup(virtualBase - 0x140000000) << "\t\t" << std::hex << 0x50000 - rsp << "\t" << std::dec << mnem << "\t\t" << op_string2 << "\n";
                        else
                            *outs << std::hex << region2.str() << "\t\t" << std::hex << 0x50000 - rsp << "\t" << std::dec << mnem << "\t\t" << op_string2 << "\n";
                    } else {
                        *outs << std::hex << virtualBase << "\t\t" << 0x50000 - rsp << "\t" << std::dec << mnem << "\t\t" << op_string2 << "\n";
                    }
                    cs_free(insn, count);
                }
#ifdef USE_BOOST
                if (ctx->m_Obfu) {
#ifdef REVISIT_OBFU
                    static uintptr_t scratch = ctx->m_ImageEnd + 0x100;
#endif
                    if (!pystring::startswith(mnem, "nop")) {
                        FuncTailInsn fti;
                        fti.ea(virtualBase).size(size).code(std::string((char*)codeBuffer, size)).mnemonic(mnem).operands(op_string);

                        // history.push_back(fmt::format("{} {}", mnem, op_string));
                        history.push_back(fti);
                    }

                    group_t capture_groups;
                    map_fti insn_groups;
                    vector_fti insn_list;
                    if (1 && multimatch(history,
                                        {
                                            R"(push rbp)",
                                            R"(lea rbp, \[rel ({jtarget}[::address::])\])",
                                            R"(xchg qword ptr \[rsp\], rbp)",
                                            R"(jmp ({ctarget}[::address::]))",
                                        },
                                        capture_groups, insn_groups, insn_list, '$')) {

                        LOG("multimatch: call-jmp");
                        auto chunks = _::chunk_if(insn_list, [&](auto lhs, auto rhs) {
                            visited.erase(lhs.ea());
                            visited.erase(rhs.ea());
                            return lhs.ea() + lhs.size() == rhs.ea();
                        });
                        for (auto chunk : chunks) {
                            if (auto chunk_len = chunk.back().ea() + chunk.back().size() - chunk.front().ea(); chunk_len < 11)
                                mbs(chunk.front().ea()).nop(chunk_len);
                            else {
                                mbs(chunk.front().ea()).call(parseUint(capture_groups["ctarget"][0], 16)).jmp(parseUint(capture_groups["jtarget"][0], 16));
                                break;
                            }
                        }

#ifdef REVISIT_OBFU
                        // this is really:  `call ctarget` `jmp jtarget`, and
                        // we need a way to trigger our "call counter"... lets
                        // use some temporary memory as a trampoline-ish device:
                        set_rip(ctx->m_uc, scratch);
                        scratch = mbs(scratch).nop(1).call(parseUint(capture_groups["ctarget"][0], 16)).jmp(parseUint(capture_groups["jtarget"][0], 16)).as<uintptr_t>();
                        adjust_rsp(ctx->m_uc, +8);
                        return;
#endif
                    }

                    // LOG("chunk: {}", pystring::join("; ", _::map2(chunk, [](const auto& ft) { return ft.text(); })));
                    if (1 && multimatch(history,
                                        {R"(push rbp)",
                                         R"(movabs rbp, ({raxtarget}[::address::]))",
                                         R"(xchg qword ptr \[rsp\], rbp)",
                                         R"(push ({rax}[::r64-8::]))",
                                         R"(push ({rcx}[::r64-8::]))",
                                         R"(mov ${rax}, qword ptr \[rsp\+0x10\])",
                                         R"(movabs ${rcx}, ({rcxtarget}[::address::]))",
                                         R"(({cmov}cmov\w+) ${rax}, ${rcx})",
                                         R"(mov qword ptr \[rsp\+0x10\], ${rax})",
                                         R"(pop ${rcx})",
                                         R"(pop ${rax})",
                                         R"(ret)"},
                                        capture_groups, insn_groups, insn_list, '$')) {
                        LOG("multimatch: mini-cmov");
                        auto chunks = _::chunk_if(insn_list, [&](auto lhs, auto rhs) {
                            visited.erase(lhs.ea());
                            visited.erase(rhs.ea());
                            return lhs.ea() + lhs.size() == rhs.ea();
                        });
                        for (auto chunk : chunks) {
                            if (auto chunk_len = chunk.back().ea() + chunk.back().size() - chunk.front().ea(); chunk_len < 11)
                                mbs(chunk.front().ea()).nop(chunk_len);
                            else {
                                auto rax_target = asQwordO(_::firstOpt(capture_groups["raxtarget"]), 16);
                                auto rcx_target = asQwordO(_::firstOpt(capture_groups["rcxtarget"]), 16);
                                if (auto cmov_insn = _::firstOpt(insn_groups["cmov"]); cmov_insn && rax_target && rcx_target) {
                                    auto cmov_addr = cmov_insn->ea();
                                    auto condition = (cmov_insn->code()[2] & 0x0f) ^ 0x01;

                                    // auto condition = mbs(cmov_addr).cmovcc();
                                    LOG("cmov: {} {:x} condition: {:x}", cmov_insn->text(), cmov_insn->ea(), condition);
                                    HexDump::dumpBytesAsHex(*outs, cmov_insn->code());
                                    mbs(chunk.front().ea())
                                        .jcc(*rax_target, condition)  // flip condition to negative proposition to match un-obfu code
                                        .jmp(*rcx_target)
                                        .db(0xCC);

#if REVISIT_OBFU
                                    // revisit the modified code to ensure everything is ok
                                    // LOG("setting rip to {:x}", scratch);
                                    visited.erase(chunk.front().ea());
                                    set_rip(ctx->m_uc, scratch);
                                    scratch = mbs(scratch).nop(1).jmp(chunk.front().ea()).as<uintptr_t>();
                                    // LOG("setting scratch to {:x}", scratch);
                                    adjust_rsp(ctx->m_uc, +0x10);
                                    return;
#endif
                                    break;
                                }
                            }
                        }
                    }

                    if (1 && multimatch(history,
                                        {
                                            // push rbp
                                            // lea  rbp, [rel 0x144698cef]
                                            // xchg qword ptr [rsp], rbp
                                            // ret
                                            R"(push rbp)",
                                            R"(lea rbp, \[rel ({jtarget}[::address::])\])",
                                            R"(xchg qword ptr \[rsp\], rbp)",
                                            R"(ret)",
                                        },
                                        capture_groups, insn_groups, insn_list, '$')) {

                        LOG("multimatch: jmp");
                        auto chunks = _::chunk_if(insn_list, [&](auto lhs, auto rhs) {
                            visited.erase(lhs.ea());
                            visited.erase(rhs.ea());
                            return lhs.ea() + lhs.size() == rhs.ea();
                        });
                        for (auto chunk : chunks) {
                            if (auto chunk_len = chunk.back().ea() + chunk.back().size() - chunk.front().ea(); chunk_len < 5)
                                mbs(chunk.front().ea()).nop(chunk_len);
                            else {
                                mbs(chunk.front().ea()).jmp(parseUint(capture_groups["jtarget"][0], 16)).db(0xCC);
                                break;
                            }
                        }

#ifdef REVISIT_OBFU
                        // this is really:  `call ctarget` `jmp jtarget`, and
                        // we need a way to trigger our "call counter"... lets
                        // use some temporary memory as a trampoline-ish device:
                        set_rip(ctx->m_uc, scratch);
                        scratch = mbs(scratch).nop(1).call(parseUint(capture_groups["ctarget"][0], 16)).jmp(parseUint(capture_groups["jtarget"][0], 16)).as<uintptr_t>();
                        adjust_rsp(ctx->m_uc, +8);
                        return;
#endif
                    }
                    if (1 && multimatch(history,
                                        {
                                            R"(mov qword ptr \[rsp-8\], [::r64-8::])",
                                            R"(lea rsp, \[rsp-8\])",
                                        },
                                        capture_groups, insn_groups, insn_list, '$')) {

                        LOG("multimatch: push rbp");
                        auto chunks = _::chunk_if(insn_list, [&](auto lhs, auto rhs) {
                            visited.erase(lhs.ea());
                            visited.erase(rhs.ea());
                            return lhs.ea() + lhs.size() == rhs.ea();
                        });
                        for (auto chunk : chunks)
                            if (auto chunk_len = chunk.back().ea() + chunk.back().size() - chunk.front().ea()) mbs(chunk.front().ea()).nop(chunk_len);
                        for (auto chunk : chunks) {
                            mbs(chunk.front().ea()).push(0xf & (chunk.front().code()[2] & ~0x44) >> 3).nop(chunk.back().ea() + chunk.back().size() - chunk.front().ea() - 1);
                            break;
                        }
                    }
                    if (1 && multimatch(history,
                                        {
                                            R"(lea rsp, \[rsp-8\])",
                                            R"(mov qword ptr \[rsp\], [::r64-8::])",
                                        },
                                        capture_groups, insn_groups, insn_list, '$')) {

                        LOG("multimatch: push rbp");
                        auto chunks = _::chunk_if(insn_list, [&](auto lhs, auto rhs) {
                            visited.erase(lhs.ea());
                            visited.erase(rhs.ea());
                            return lhs.ea() + lhs.size() == rhs.ea();
                        });
                        for (auto chunk : chunks)
                            if (auto chunk_len = chunk.back().ea() + chunk.back().size() - chunk.front().ea()) mbs(chunk.front().ea()).nop(chunk_len);
                        for (auto chunk : chunks) {
                            mbs(chunk.front().ea()).push(0xf & (insn_list[1].code()[2]) >> 3).nop(chunk.back().ea() + chunk.back().size() - chunk.front().ea() - 1);
                            break;
                        }
                    }
                    if (1 && multimatch(history,
                                        {
                                            R"(lea rsp, \[rsp\+8\])",
                                            R"(mov ({rline}[::r64-8::]), qword ptr \[rsp-8\])",
                                        },
                                        capture_groups, insn_groups, insn_list, '$')) {

                        LOG("multimatch: pop rbp1");
                        auto chunks = _::chunk_if(insn_list, [&](auto lhs, auto rhs) {
                            visited.erase(lhs.ea());
                            visited.erase(rhs.ea());
                            return lhs.ea() + lhs.size() == rhs.ea();
                        });
                        for (auto chunk : chunks)
                            if (auto chunk_len = chunk.back().ea() + chunk.back().size() - chunk.front().ea()) mbs(chunk.front().ea()).nop(chunk_len);
                        for (auto chunk : chunks) {
                            mbs(chunk.front().ea())
                                //.push(0xf & (insn_list[1].code()[2]) >> 3)
                                // [ ((nassemble('mov {}, qword [rsp-8]'.format(r))[0]) & ~0x48) << 1 | ((nassemble('mov {}, qword [rsp-8]'.format(r))[2]) & ~0x44) >> 3  for r in regs]
                                .pop(0xf & ((_::first(insn_groups["rline"]).code()[2] & ~0x44) >> 3))
                                .nop(chunk.back().ea() + chunk.back().size() - chunk.front().ea() - 1);
                            break;
                        }
                    }
                    if (1 && multimatch(history,
                                        {
                                            R"(mov ({rline}[::r64-8::]), qword ptr \[rsp\])",
                                            R"(lea rsp, \[rsp\+8\])",
                                        },
                                        capture_groups, insn_groups, insn_list, '$')) {

                        LOG("multimatch: pop rbp2");
                        auto chunks = _::chunk_if(insn_list, [&](auto lhs, auto rhs) {
                            visited.erase(lhs.ea());
                            visited.erase(rhs.ea());
                            return lhs.ea() + lhs.size() == rhs.ea();
                        });
                        for (auto chunk : chunks)
                            if (auto chunk_len = chunk.back().ea() + chunk.back().size() - chunk.front().ea()) mbs(chunk.front().ea()).nop(chunk_len);
                        for (auto chunk : chunks) {
                            mbs(chunk.front().ea()).pop(0xf & ((_::first(insn_groups["rline"]).code()[2] & ~0x44) >> 3)).nop(chunk.back().ea() + chunk.back().size() - chunk.front().ea() - 1);
                            break;
                        }
                    }
                    if (1 && multimatch(history,
                                        {

                                            R"(lea rsp, \[rsp\+8\])",
                                            R"(jmp qword ptr \[rsp-8\])",
                                        },
                                        capture_groups, insn_groups, insn_list, '$')) {

                        LOG("multimatch: ret");
                        auto chunks = _::chunk_if(insn_list, [&](auto lhs, auto rhs) {
                            visited.erase(lhs.ea());
                            visited.erase(rhs.ea());
                            return lhs.ea() + lhs.size() == rhs.ea();
                        });
                        for (auto chunk : chunks)
                            if (auto chunk_len = chunk.back().ea() + chunk.back().size() - chunk.front().ea()) mbs(chunk.front().ea()).nop(chunk_len);
                        for (auto chunk : chunks) {
                            mbs(chunk.front().ea()).db(0xc3).nop(chunk.back().ea() + chunk.back().size() - chunk.front().ea() - 1);
                            break;
                        }
                    }

                    if (0 && multimatch(history,
                                        {
                                            R"(jmp .*)",
                                            R"(mov eax, dword ptr \[rip\+.*])",
                                            R"(mov edx, dword ptr \[rip-.*])",
                                            R"(cmp eax, edx)",
                                            R"(jne ({jne}.*)",
                                            R"(mov eax, dword ptr \[rbp\+0x64])",
                                            R"(test eax, eax)",
                                            R"(jne .*)",

                                            // R"(push.*0x10)",
                                            // R"(test rsp, 0xf)",
                                            // R"(jn[ze] .*)",
                                            ////R"(push.*0x18)",
                                            // R"(call ({target}0x\x+))",

                                            // R"((add|sub) rsp, .*)",
                                            // R"((mov|lea).*r[sb]p.*r[sb]p)",
                                            // R"((mov|lea).*r[sb]p.*r[sb]p)",
                                            // R"(lea rbp, \[rel ({jmp}\w+)])",
                                            // R"(xchg \[rsp], rbp)",
                                            // R"(push rbp)",
                                            // R"(lea rbp, \[rel ({call}\w+)])",
                                            // R"(xchg \[rsp], rbp)",
                                            // R"(retn?)",
                                        },
                                        capture_groups, insn_groups, insn_list, '^')) {
                        for (auto& [key, values] : capture_groups) {
                            *outs << "capture group: " << key << ": " << _::join(values, ", ") << std::endl;
                        }
                    }
                }
#endif
            }
        } else {
            if (was_disassembling) {
                was_disassembling = false;
                LOG_DEBUG("............repeated instructions skipped");
#if USE_BOOST
                history.clear();
#endif
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

static bool InvalidRwxCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
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

            // return true;
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

            // RestClient::Response r = RestClient::get("http://127.0.0.1:2020/ida/api/v1.0/name?ea=0x140000000");
            // if (r.code == 200) {
            //    auto name = string_between("'", "'", r.body);
            //    if (name.size()) {
            //        *outs << "UC_MEM_WRITE_PROT: name: " << name << "\n";
            //    }
            //}

            *outs << "UC_MEM_WRITE_PROT: address 0x" << std::hex << ctx->NormaliseBase(address) << std::dec << "\n";
            *outs << "UC_MEM_WRITE_PROT: size 0x" << std::hex << size << std::dec << "\n";
            *outs << "UC_MEM_WRITE_PROT: value 0x" << std::hex << value << std::dec << "\n";

            if (std::stringstream region2; ctx->FindAddressInRegion(rip, region2))
                *outs << "UC_MEM_WRITE_PROT rip at " << region2.str() << "\n";
            else
                *outs << "UC_MEM_WRITE_PROT rip at " << ctx->NormaliseBase(rip) << "\n";

            // return true;
            uc_emu_stop(uc);
            break;
        }
        case UC_MEM_FETCH_UNMAPPED: {
            uint64_t rip;
            uc_reg_read(uc, UC_X86_REG_RIP, &rip);

            if (std::stringstream region; ctx->FindAddressInRegion(address, region))
                *outs << "UC_MEM_FETCH_UNMAPPED from " << region.str() << "\n";
            else
                *outs << "UC_MEM_FETCH_UNMAPPED from " << std::hex << ctx->NormaliseBase(address) << std::dec << "\n";

            std::stringstream region2;
            if (ctx->FindAddressInRegion(rip, region2))
                *outs << "UC_MEM_FETCH_UNMAPPED rip at " << region2.str() << "\n";
            else
                *outs << "UC_MEM_FETCH_UNMAPPED rip at " << std::hex << ctx->NormaliseBase(rip) << std::dec << "\n";

            // return true;
            uc_emu_stop(uc);
            break;
        }
        case UC_MEM_READ_UNMAPPED: {
            uint64_t rip;
            uc_reg_read(uc, UC_X86_REG_RIP, &rip);

            if (std::stringstream region; ctx->FindAddressInRegion(address, region))
                *outs << "UC_MEM_READ_UNMAPPED from " << region.str() << "\n";
            else
                *outs << "UC_MEM_READ_UNMAPPED from " << std::hex << address << std::dec << "\n";

            std::stringstream region2;
            if (ctx->FindAddressInRegion(rip, region2))
                *outs << "UC_MEM_READ_UNMAPPED rip at " << region2.str() << "\n";
            else
                *outs << "UC_MEM_READ_UNMAPPED rip at " << std::hex << rip << std::dec << "\n";

            // return true;
            uc_emu_stop(uc);
            break;
        }
        case UC_MEM_WRITE_UNMAPPED: {
            uint64_t rip;
            uc_reg_read(uc, UC_X86_REG_RIP, &rip);

            if (std::stringstream region; ctx->FindAddressInRegion(address, region))
                *outs << "UC_MEM_WRITE_UNMAPPED from " << region.str() << "\n";
            else
                *outs << "UC_MEM_WRITE_UNMAPPED from " << address << "\n";
            // uint64_t address, int size, int64_t value
            *outs << "UC_MEM_WRITE_UNMAPPED: address 0x" << std::hex << address << std::dec << "\n";
            *outs << "UC_MEM_WRITE_UNMAPPED: size 0x" << std::hex << size << std::dec << "\n";
            *outs << "UC_MEM_WRITE_UNMAPPED: value 0x" << std::hex << value << std::dec << "\n";
            std::stringstream region2;
            if (ctx->FindAddressInRegion(rip, region2))
                *outs << "UC_MEM_WRITE_UNMAPPED rip at " << region2.str() << "\n";
            else
                *outs << "UC_MEM_WRITE_UNMAPPED rip at " << rip << "\n";

            // return true;
            uc_emu_stop(uc);
            break;
        }
    }
    return false;
}

static void RwxCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
    PeEmulation* ctx = (PeEmulation*)user_data;

    switch (type) {
        case UC_MEM_READ: {
            if (address > 0x50000) {
                Disassemble(uc, ctx->CurrentInstruction, ctx->CurrentInstructionLength, user_data);
            }
            if (!ctx->m_SaveReadRanges.empty()) {
                auto _size = size;
                auto _address = address;
                if (_address >= ctx->m_ImageBase && _address < ctx->m_ImageEnd) {
                    _address -= ctx->m_ImageBase;
                    while (_size-- && _address < ctx->m_ReadBitmap.size()) {
                        ctx->m_ReadBitmap[_address++] = true;
                    }
                }
            }
            if (!ctx->m_SaveRead.empty() || ctx->m_Dwords) {
                if (address > 0x50000) {
                    switch (size) {
                        case 1: ctx->m_Read.emplace_back(ctx->NormaliseBase(address), (uint8_t)value); break;
                        case 2: ctx->m_Read.emplace_back(ctx->NormaliseBase(address), (uint8_t)(value >> 0)); ctx->m_Read.emplace_back(ctx->NormaliseBase(address + 1), (uint8_t)(value >> 8));
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
                            if (ctx->FindAddressInRegion(rip, region)) *outs << "UC_MEM_READ rip at " << region.str() << "\n";
                    }
                    //*outs << "UC_MEM_WRITE: " << std::hex << ctx->NormaliseBase(address) << "\n";

                    // uc_emu_stop(uc);
                }

                break;
            }
        }
        case UC_MEM_WRITE: {
            if (address > 0x50000) {
                Disassemble(uc, ctx->CurrentInstruction, ctx->CurrentInstructionLength, user_data);
            }
            if (!ctx->m_SaveWrittenRanges.empty()) {
                auto _size = size;
                auto _address = address;
                if (_address >= ctx->m_ImageBase && _address < ctx->m_ImageEnd) {
                    _address -= ctx->m_ImageBase;
                    while (_size-- && _address < ctx->m_WrittenBitmap.size()) {
                        ctx->m_WrittenBitmap[_address++] = true;
                    }
                }
            }
            if (!ctx->m_SaveWritten.empty() || ctx->m_Sandbox) {
                if (ctx->m_Unpack && address >= ctx->m_ImageBase && address < ctx->m_ImageEnd) {
                    address -= ctx->m_ImageBase;
                    while (size-- > 0) {
                        ctx->m_WrittenBitmap[address++] = true;
                    }
                } else if (address > 0x50000) {
                    if (ctx->m_Sandbox) {
                        uint64_t old_value;
                        uc_mem_read(uc, address, &old_value, sizeof(old_value));
                        switch (size) {
                            case 1: ctx->m_Undo.emplace_back(ctx->NormaliseBase(address), (uint8_t)old_value); break;
                            case 2:
                                ctx->m_Undo.emplace_back(ctx->NormaliseBase(address), (uint8_t)(old_value >> 0));
                                ctx->m_Undo.emplace_back(ctx->NormaliseBase(address + 1), (uint8_t)(old_value >> 8));
                                break;
                            case 4:
                                ctx->m_Undo.emplace_back(ctx->NormaliseBase(address), (uint8_t)(old_value >> 0));
                                ctx->m_Undo.emplace_back(ctx->NormaliseBase(address + 1), (uint8_t)(old_value >> 8));
                                ctx->m_Undo.emplace_back(ctx->NormaliseBase(address + 2), (uint8_t)(old_value >> 16));
                                ctx->m_Undo.emplace_back(ctx->NormaliseBase(address + 3), (uint8_t)(old_value >> 24));
                                break;
                            case 8:
                                ctx->m_Undo.emplace_back(ctx->NormaliseBase(address), (uint8_t)(old_value >> 0));
                                ctx->m_Undo.emplace_back(ctx->NormaliseBase(address + 1), (uint8_t)(old_value >> 8));
                                ctx->m_Undo.emplace_back(ctx->NormaliseBase(address + 2), (uint8_t)(old_value >> 16));
                                ctx->m_Undo.emplace_back(ctx->NormaliseBase(address + 3), (uint8_t)(old_value >> 24));
                                ctx->m_Undo.emplace_back(ctx->NormaliseBase(address + 4), (uint8_t)(old_value >> 32));
                                ctx->m_Undo.emplace_back(ctx->NormaliseBase(address + 5), (uint8_t)(old_value >> 40));
                                ctx->m_Undo.emplace_back(ctx->NormaliseBase(address + 6), (uint8_t)(old_value >> 48));
                                ctx->m_Undo.emplace_back(ctx->NormaliseBase(address + 7), (uint8_t)(old_value >> 56));
                                break;
                            default:
                                std::stringstream region;
                                *outs << "UC_MEM_WRITE cannot handle size " << size << " to "
                                      << "0x" << std::hex << ctx->NormaliseBase(address) << std::dec << "\n";
                                uint64_t rip;
                                uc_reg_read(uc, UC_X86_REG_RIP, &rip);
                                if (ctx->FindAddressInRegion(rip, region)) *outs << "UC_MEM_WRITE rip at " << region.str() << "\n";
                        }
                    }
                    if (!ctx->m_SaveWritten.empty() || ctx->m_Dwords) {
                        switch (size) {
                            case 1: ctx->m_Written.emplace_back(ctx->NormaliseBase(address), (uint8_t)value); break;
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
                                if (ctx->FindAddressInRegion(rip, region)) *outs << "UC_MEM_WRITE rip at " << region.str() << "\n";
                        }
                    }
                    //*outs << "UC_MEM_WRITE: " << std::hex << ctx->NormaliseBase(address) << "\n";
                    // uc_emu_stop(uc);
                }
                // else if (address > 0x40000 && address < 0x50000 && value > 0x140000000) {
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
    FakeAPI_t* api = nullptr;

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
                    if (retaddr >= ctx->m_ImageBase && retaddr < ctx->m_ImageEnd) *outs << "called from imagebase+0x" << std::hex << (ULONG)(retaddr - ctx->m_ImageBase) << "\n";
                    uc_emu_stop(uc);
                } else {
                    void (*callback)(uc_engine * uc, uint64_t address, uint32_t size, void* user_data) = (decltype(callback))api->EmuCallback;

                    callback(uc, address, size, user_data);
                }
            } else {
                LOG("unknown API {:#x} called", ctx->NormaliseBase(address));
                //*outs << "unknown API called\n";
                auto retaddr = EmuReadReturnAddress(uc);
                if (retaddr >= ctx->m_ImageBase && retaddr < ctx->m_ImageEnd) *outs << "called from imagebase+0x" << std::hex << (ULONG)(retaddr - ctx->m_ImageBase) << "\n";
                uc_emu_stop(uc);
            }
        }
        ctx->m_LastRipModule = currentModule;
    } else if (currentModule != ctx->m_ImageBase) {
        if (ctx->OldFindAPIByAddress(address, DllName, &api)) {
            _CrtDbgBreak();
        }
    }

    if (currentModule == ctx->m_ImageBase && ctx->m_IsPacked && !ctx->m_ImageRealEntry) {
        FakeSection_t* section = nullptr;
        if (ctx->FindSectionByAddress(address, &section) && !section->IsUnknownSection) {
            ctx->m_ImageRealEntry = address;
        }
    }
}

static void init_descriptor64(SegmentDesctiptorX64* desc, uint64_t base, uint64_t limit, bool is_code, bool is_long_mode) {
    desc->descriptor.all              = 0;  // clear the descriptor
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
    desc->descriptor.fields.db      = 1;  // 64 bit
    desc->descriptor.fields.type    = is_code ? 0xb : 3;
    desc->descriptor.fields.system  = 1;  // code or data
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

    TEB teb = {nullptr};

    teb.ProcessEnvironmentBlock = (PPEB)m_PebBase;

    uc_mem_map(m_uc, m_TebBase, m_TebEnd - m_TebBase, UC_PROT_READ);
    uc_mem_write(m_uc, m_TebBase, &teb, sizeof(TEB));

    uc_x86_msr msr;
    msr.rid   = (uint32_t)Msr::kIa32GsBase;
    msr.value = m_TebBase;

    uc_reg_write(m_uc, UC_X86_REG_MSR, &msr);
}

void PeEmulation::InitKTHREAD() {
    // todo
    m_KThreadBase = HeapAlloc(1234);

    uc_x86_msr msr;
    msr.rid   = (uint32_t)Msr::kIa32GsBase;
    msr.value = m_KThreadBase;

    uc_reg_write(m_uc, UC_X86_REG_MSR, &msr);
}

void PeEmulation::SortModuleList() {
    std::sort(m_FakeModules.begin(), m_FakeModules.end(), [](const FakeModule_t* value1, const FakeModule_t* value2) { return value1->Priority > value2->Priority; });
}

void PeEmulation::InsertTailList(IN ULONG64 ListHeadAddress, IN ULONG64 EntryAddress) {
    PLIST_ENTRY Blink;

    // Blink = ListHead->Blink;
    uc_mem_read(m_uc, ListHeadAddress + offsetof(LIST_ENTRY, Blink), &Blink, sizeof(Blink));

    // Entry->Flink = (PLIST_ENTRY)ListHeadAddress;

    uc_mem_write(m_uc, EntryAddress + offsetof(LIST_ENTRY, Flink), &ListHeadAddress, sizeof(ListHeadAddress));

    // Entry->Blink = Blink;

    uc_mem_write(m_uc, EntryAddress + offsetof(LIST_ENTRY, Blink), &Blink, sizeof(Blink));

    // Blink->Flink = (PLIST_ENTRY)EntryAddress;

    uc_mem_write(m_uc, (uint64_t)Blink + offsetof(LIST_ENTRY, Flink), &EntryAddress, sizeof(EntryAddress));

    // ListHead->Blink = (PLIST_ENTRY)EntryAddress;

    uc_mem_write(m_uc, ListHeadAddress + offsetof(LIST_ENTRY, Blink), &EntryAddress, sizeof(EntryAddress));
}

void PeEmulation::InitPsLoadedModuleList() {
    m_PsLoadedModuleListBase = HeapAlloc(sizeof(LIST_ENTRY));

    LIST_ENTRY PsLoadedModuleList = {nullptr};
    PsLoadedModuleList.Blink = PsLoadedModuleList.Flink = (PLIST_ENTRY)m_PsLoadedModuleListBase;

    uc_mem_write(m_uc, m_PsLoadedModuleListBase, &PsLoadedModuleList, sizeof(PsLoadedModuleList));

    for (size_t i = 0; i < m_FakeModules.size(); ++i) {
        auto LdrEntryBase = HeapAlloc(sizeof(KLDR_DATA_TABLE_ENTRY));

        KLDR_DATA_TABLE_ENTRY LdrEntry = {nullptr};
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
            if (alloc < m_HeapAllocs[i].base + m_HeapAllocs[i].size) alloc = m_HeapAllocs[i].base + m_HeapAllocs[i].size;
        }

        if (!alloc) alloc = m_HeapBase;

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
        if (maxaddr < m_HeapAllocs[i].base) maxaddr = m_HeapAllocs[i].base;
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
void WriteMemoryBitmapAccesses(uc_engine* uc, json* j, const std::vector<bool>& vec, const std::string& filename, const std::string& prefix) {
    auto short_prefix = basename(prefix);
    auto last_folder  = dirname(prefix);

    std::vector<uint8_t> buf;
    uintptr_t base = 0x140000000;
    std::string ranges;
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
            if (j) (*j)[last_folder][std::to_string(start_ea)][std::to_string(len)].push_back(json::array({short_prefix, filename}));
            //*outs << "Writing to '" << fn << "'\n";
            file_put_contents_if_changed(spread_filename(smart_path(fn)).string(), (char*)buf.data(), buf.size(), 1);
        }
        it = std::find(end_it, end, true);
    }
}

void WriteMemoryBitmapAccessesSummary(uc_engine* uc, json* j, const std::vector<bool>& vec, const std::string& filename) {
    std::vector<uint8_t> buf;
    uintptr_t base = 0x140000000;
    std::string ranges;
    auto begin     = vec.begin();
    auto end       = vec.end();
    auto it        = std::find(begin, end, true);
    while (it != end) {
        uintptr_t start_ea = base + std::distance(begin, it);
        auto end_it        = std::find(it, end, false);
        if (end_it != end) {
            size_t len     = std::distance(it, end_it);
            ranges += fmt::format("    (0x{:x},0x{:x}),\n", start_ea, start_ea + len);
            // if (j) (*j)["summary"][std::to_string(start_ea)][std::to_string(len)].push_back(json::array({short_prefix, filename}));
        }
        it = std::find(end_it, end, true);
    }
    if (!vec.empty()) {
        file_put_contents_if_changed(filename, ranges.data(), ranges.length(), 1);
    }
}
bool tryAndReadJson(const std::string& filename, json& j, json defaultValue) {
    // Various read-text-from-file implementations from:
    // http://stackoverflow.com/questions/2602013/read-whole-ascii-file-into-c-stdstring

    LOG_DEBUG("tryAndReadJson: \"{}\"", (filename));

    // fspath path = filepath(filename);
    // path.replace_extension();
    // std::string filename_noext = filepath(path);

    // std::string found;
    std::string contents;
    bool bExists = file_exists(filename);
    if (bExists) {
        contents = file_get_contents(filename);
        if (contents.empty()) {
            LOG_FUNC("unable to decode or empty: {}", (filename));
            goto FAIL;
        }
        try {
            j = json::parse(contents.c_str());
            LOG_FUNC("parsed {}", (filename));
            return true;
        } catch (json::parse_error pex) {
            // (101, m_lexer.get_position(), error_msg));
            LOG_ERROR(__FUNCTION__ ": json::parse_error reading '{}': {}", (filename), pex.what());
            goto FAIL;
        } catch (const json::exception& e) {
            LOG_ERROR(__FUNCTION__ ": json::exception reading '{}': {}", (filename), e.what());
            goto FAIL;
        }
    } else {
        LOG_FUNC("file not found: {}", (filename));
        goto FAIL;
    }
FAIL:
    j = defaultValue;
    return false;
}

bool tryAndWriteJson(const std::string& filename, const json& _json) {
    if (!filename.length()) {
        LOG_ERROR("tryAndWriteJson called with empty filename");
        return false;
    }
    // LOG_DEBUG("%s: %s", __FUNCTION__, C(fn));
    // write prettified JSON to another file
    try {
        std::ofstream o(filename);
        o << std::setw(4) << _json << std::endl;
        return true;
    } catch (...) {
        LOG_DEBUG("Couldn't write JSON file: {}", filename);
        return false;
    }
}

void WriteMemoryAccesses(json* j, std::vector<std::tuple<uintptr_t, uint8_t>>& vec, const std::string& filename, const std::string& prefix) {
    if (vec.size()) {
        auto short_prefix = basename(prefix);
        auto last_folder  = dirname(prefix);

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
                    file_put_contents_if_changed(spread_filename(fn).string(), (char*)to_write.data(), to_write.size(), 1);
                    if (j) (*j)[last_folder][std::to_string(range_start_address)][std::to_string(to_write.size())].push_back(json::array({short_prefix, filename}));
                }
                to_write.clear();
                range_start_address = address;
                range_start_index   = i;
                to_write.emplace_back(data);
            }

            last_address = address;
        }
        // if (j) {
        //    std::string json_fn = (dirname(fs::path(prefix)) / "files.json").string();
        //    if (tryAndWriteJson(json_fn, *j))
        //        LOG("wrote json: {}", json_fn);
        //    else
        //        LOG("didn't write json: {}", json_fn);
        //}
    }
}

template <typename KeyType, typename LeftValue, typename RightValue>
std::map<KeyType, std::pair<LeftValue, RightValue>> IntersectMapKeys(const std::map<KeyType, LeftValue>& left, const std::map<KeyType, RightValue>& right) {
    std::map<KeyType, std::pair<LeftValue, RightValue>> result;
    typename std::map<KeyType, LeftValue>::const_iterator il  = left.begin();
    typename std::map<KeyType, RightValue>::const_iterator ir = right.begin();
    while (il != left.end() && ir != right.end()) {
        if (il->first < ir->first)
            ++il;
        else if (ir->first < il->first)
            ++ir;
        else {
            result.insert(std::make_pair(il->first, std::make_pair(il->second, ir->second)));
            ++il;
            ++ir;
        }
    }
    return result;
}

void RestoreWrittenMemory(uc_engine* uc, std::vector<std::tuple<uintptr_t, uint8_t>>& vec) {
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
                    uc_mem_write(uc, range_start_address, to_write.data(), to_write.size());
                }
                to_write.clear();
                range_start_address = address;
                range_start_index   = i;
                to_write.emplace_back(data);
            }

            last_address = address;
        }
    }
}

std::map<uintptr_t, std::vector<uint8_t>> WrittenMemoryAsMap(std::vector<std::tuple<uintptr_t, uint8_t>>& vec) {
    std::map<uintptr_t, std::vector<uint8_t>> result;
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
                    result.insert({range_start_address, to_write});
                }
                to_write.clear();
                range_start_address = address;
                range_start_index   = i;
                to_write.emplace_back(data);
            }

            last_address = address;
        }
    }
    return result;
}

uc_err patch_nops(uc_engine* uc, uint64_t address, size_t count) {
    // stored as an array of [9][8] (not ragged)
    const unsigned char nop_bytes[][8] = {
        {}, {0x90}, {0x66, 0x90}, {0x0f, 0x1f, 0x00}, {0x0f, 0x1f, 0x40, 0x00}, {0x0f, 0x1f, 0x44, 0x00, 0x00}, {0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00}, {0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00}, {0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
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

void* patch_nops(void* ptr, size_t count) {
    // stored as an array of [9][8] (not ragged)
    const unsigned char nop_bytes[][8] = {
        {}, {0x90}, {0x66, 0x90}, {0x0f, 0x1f, 0x00}, {0x0f, 0x1f, 0x40, 0x00}, {0x0f, 0x1f, 0x44, 0x00, 0x00}, {0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00}, {0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00}, {0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
    };

    while (count) {
        size_t size = count > 8 ? 8 : count;
        memcpy(ptr, nop_bytes[size], size);
        count = count - size;
        ptr   = (char*)ptr + size;
    }
    return ptr;
}

void* uc_memcpy(uc_engine* uc, uintptr_t _Dst, void const* _Src, size_t _Size) { return (void*)((UC_ERR_OK == uc_mem_write(uc, _Dst, _Src, _Size)) ? _Dst : 0); }

int uc_memcmp(uc_engine* uc, uintptr_t _Dst, void const* _Src, size_t _Size) {
    std::vector<uint8_t> buf;
    buf.resize(_Size);
    uc_mem_read(uc, _Dst, buf.data(), buf.size());
    return std::memcmp(buf.data(), _Src, _Size);
}

void* uc_memset(uc_engine* uc, uintptr_t _Dst, int _Val, size_t _Size) {
    for (size_t i = 0; i < _Size; ++i) {
        if (UC_ERR_OK != uc_mem_write(uc, _Dst + i, &_Val, 1)) {
            return nullptr;
        }
    }
    return (void*)(_Dst);
}

PeEmulation g_ctx;

void ResetRegisters(uc_engine* uc, PeEmulation& ctx) {
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
}

void GetRegisters(uc_engine* uc, CONTEXT& c) {
    uc_reg_read(uc, UC_X86_REG_RAX, &c.Rax);
    uc_reg_read(uc, UC_X86_REG_RBX, &c.Rbx);
    uc_reg_read(uc, UC_X86_REG_RCX, &c.Rcx);
    uc_reg_read(uc, UC_X86_REG_RDX, &c.Rdx);
    uc_reg_read(uc, UC_X86_REG_RSI, &c.Rsi);
    uc_reg_read(uc, UC_X86_REG_RDI, &c.Rdi);
    uc_reg_read(uc, UC_X86_REG_R8, &c.R8);
    uc_reg_read(uc, UC_X86_REG_R9, &c.R9);
    uc_reg_read(uc, UC_X86_REG_R10, &c.R10);
    uc_reg_read(uc, UC_X86_REG_R11, &c.R11);
    uc_reg_read(uc, UC_X86_REG_R12, &c.R12);
    uc_reg_read(uc, UC_X86_REG_R13, &c.R13);
    uc_reg_read(uc, UC_X86_REG_R14, &c.R14);
    uc_reg_read(uc, UC_X86_REG_R15, &c.R15);
    uc_reg_read(uc, UC_X86_REG_RBP, &c.Rbp);
    uc_reg_read(uc, UC_X86_REG_RSP, &c.Rsp);
    uc_reg_read(uc, UC_X86_REG_RIP, &c.Rip);
}

void ShowRegisters(uc_engine* uc) {
    CONTEXT c;
    GetRegisters(uc, c);
    constexpr const char* registers      = "RAX\0RCX\0RDX\0RBX\0RSP\0RBP\0RSI\0RDI\0R8\0\0R9\0\0R10\0R11\0R12\0R13\0R14\0R15\0RIP\0";
    const uint64_t* p                    = &c.Rax;
    constexpr auto STACKWALK_MAX_NAMELEN = 1024;
    CHAR buffer[STACKWALK_MAX_NAMELEN];
    size_t maxLen = STACKWALK_MAX_NAMELEN;
#if _MSC_VER >= 1400
    maxLen = _TRUNCATE;
#endif
    // clang-format off
    _snprintf_s(buffer, maxLen, "RAX: %16llx   RCX: %16llx   RDX: %16llx   RBX: %16llx  ", p[0], p[1], p[2], p[3]); p += 4; buffer[STACKWALK_MAX_NAMELEN - 1] = 0; LOG("{}", buffer);
    _snprintf_s(buffer, maxLen, "RSP: %16llx   RBP: %16llx   RSI: %16llx   RDI: %16llx  ", p[0], p[1], p[2], p[3]); p += 4; buffer[STACKWALK_MAX_NAMELEN - 1] = 0; LOG("{}", buffer);
    _snprintf_s(buffer, maxLen, "R8:  %16llx   R9:  %16llx   R10: %16llx   R11: %16llx  ", p[0], p[1], p[2], p[3]); p += 4; buffer[STACKWALK_MAX_NAMELEN - 1] = 0; LOG("{}", buffer);
    _snprintf_s(buffer, maxLen, "R12: %16llx   R13: %16llx   R14: %16llx   R15: %16llx  ", p[0], p[1], p[2], p[3]); p += 4; buffer[STACKWALK_MAX_NAMELEN - 1] = 0; LOG("{}", buffer);
    _snprintf_s(buffer, maxLen, "RIP: %16llx", *p); 
	buffer[STACKWALK_MAX_NAMELEN - 1] = 0; 
	LOG("{}", buffer);
    // clang-format on
}

void SaveResult(uc_engine* uc, uintptr_t fn_address, PeEmulation& ctx, json* j) {
    uint64_t result_rsp = 0;
    uc_reg_read(uc, UC_X86_REG_RSP, &result_rsp);
    *outs << "RSP: 0x" << std::hex << result_rsp << "\n" << std::dec;
    auto ptr        = result_rsp;
    uintptr_t value = 0xdeadbeef;
    for (ptr = 0x4ffb8; ptr > 0x4ff50; ptr -= 8) {
        ptrdiff_t i = ptr - result_rsp;
        uc_mem_read(uc, ptr, &value, 8);
        *outs << "uc_emu_start stack: " << std::hex << fn_address << std::dec << " " << i << ": 0x" << std::hex << ptr << ": 0x" << std::hex << ctx.NormaliseBase(value) << std::dec << "\n";
        if (i == -0x20) break;
    }

    fs::path read_path(ctx.m_SaveRead);
    fs::path written_path(ctx.m_SaveWritten);

    read_path    = read_path / "read";
    written_path = written_path / "written";
    LOG("read_path: {}", read_path.string());

    if (fn_address) ctx.filename = string_between("", "_", ctx.filename, STRING_BETWEEN_INCLUSIVE) + fmt::format("{:x}", fn_address);

    if (ctx.m_Unpack) {
        WriteMemoryBitmapAccesses(uc, j, ctx.m_WrittenBitmap, ctx.filename, written_path.lexically_normal().string());
    } else {
        uint64_t bytes_written = 0;
        uint64_t bytes_read    = 0;

        bytes_written += ctx.m_Written.size();
        bytes_read += ctx.m_Read.size();
        if (!ctx.m_SaveRead.empty()) WriteMemoryAccesses(nullptr, ctx.m_Read, ctx.filename, read_path.lexically_normal().string());
        if (!ctx.m_SaveWritten.empty()) WriteMemoryAccesses(j, ctx.m_Written, ctx.filename, written_path.lexically_normal().string());
        *outs << "bytes written: " << bytes_written << " bytes read: " << bytes_read << "\n";
    }

    if (!ctx.m_SaveReadRanges.empty()) {
        std::string fnBitmapSummary = path_combine(ctx.m_SaveReadRanges, replace_extension(ctx.filename, ".ranges.py")).string();
        WriteMemoryBitmapAccessesSummary(uc, j, ctx.m_ReadBitmap, fnBitmapSummary);
    }
    if (!ctx.m_SaveWrittenRanges.empty()) {
        std::string fnBitmapSummary = path_combine(ctx.m_SaveWrittenRanges, replace_extension(ctx.filename, ".ranges.py")).string();
        WriteMemoryBitmapAccessesSummary(uc, j, ctx.m_WrittenBitmap, fnBitmapSummary);
    }
    if (ctx.m_Dwords) {
        auto intersection = IntersectMapKeys(WrittenMemoryAsMap(ctx.m_Read), WrittenMemoryAsMap(ctx.m_Written));
        for (const auto& [address, bytepair] : intersection) {
            LOG("Intersection: {:x} {} = {}", address, HexDump::asString(bytepair.first), HexDump::asString(bytepair.second));
        }
    }
    if (ctx.m_Sandbox) {
        RestoreWrittenMemory(ctx.m_uc, ctx.m_Undo);
    }

    ctx.m_Read.clear();
    ctx.m_Written.clear();
    ctx.m_Undo.clear();
}

std::vector<mem::pointer> scan_all_with_iteratee(mem::region r, mem::pattern p, std::function<uintptr_t(uintptr_t)> iter) {
    std::vector<mem::pointer> found;
    for (mem::pointer ea : mem::scan_all(p, r)) {
        auto ptr = iter(ea.as<uintptr_t>());
        if (ptr) found.emplace_back(ptr);
    }
    return found;
}

size_t scan_all_do(mem::region r, mem::pattern p, std::function<void(uintptr_t)> iter) {
    size_t counter = 0;
    for (mem::pointer ea : mem::scan_all(p, r)) {
        iter(ea.as<uintptr_t>());
        ++counter;
    }
    LOG("scan_all_do found {} matches for {}", counter, p.to_string());
    return counter;
}

std::string megalookup(uintptr_t addr) {
    if (auto it = megaFuncNames.find(addr - 0x140000000); it != megaFuncNames.end()) {
        return fmt::format("{}", it->second);
    }
    if (megafunc && megafunc->Contains(addr - 0x140000000)) {
        return pystring::rstrip(megafunc->Lookup(addr - 0x140000000));
    }

    return fmt::format("{:#x}", addr);
}

int ImageDump(PeEmulation& ctx, uc_engine* uc, const std::string& filename) {
    virtual_buffer_t imagebuf(ctx.m_ImageEnd - ctx.m_ImageBase);
    virtual_buffer_t RebuildSectionBuffer;
    mem::region r(imagebuf.GetBuffer(), imagebuf.GetLength());
    auto m_normalise_base = [&](mem::pointer& ea) { return r.adjust_base_to(0x140000000, ea.as<uintptr_t>()).as<uintptr_t>(); };

    uc_mem_read(uc, ctx.m_ImageBase, imagebuf.GetBuffer(), ctx.m_ImageEnd - ctx.m_ImageBase);

    auto ntheader = RtlImageNtHeader(imagebuf.GetBuffer());

    auto SectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)ntheader + sizeof(ntheader->Signature) + sizeof(ntheader->FileHeader) + ntheader->FileHeader.SizeOfOptionalHeader);

    auto SectionCount = ntheader->FileHeader.NumberOfSections;
    for (USHORT i = 0; i < SectionCount; ++i) {
        SectionHeader[i].PointerToRawData = SectionHeader[i].VirtualAddress;
        SectionHeader[i].SizeOfRawData    = SectionHeader[i].Misc.VirtualSize;
    }

    {
        DWORD SectionAlignment;

        if (ntheader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            auto ntheader64  = ntheader;
            SectionAlignment = ntheader64->OptionalHeader.SectionAlignment;
        } else {
            SectionAlignment = ntheader->OptionalHeader.SectionAlignment;
        }

        auto correct_size = ntheader->OptionalHeader.BaseOfCode;

        for (WORD i = 0; i < ntheader->FileHeader.NumberOfSections; i++) {
            DWORD SectionSize = SectionHeader[i].Misc.VirtualSize;
            SectionSize       = ALIGN_UP_MIN1(std::max(SectionHeader[i].Misc.VirtualSize, SectionHeader[i].SizeOfRawData), SectionAlignment);
            *outs << fmt::format("{:8} {:8x} [{:8x}] {:8x} [{:8x}] {:8x} {:8x}", SectionHeader[i].Name, SectionHeader[i].Misc.VirtualSize, SectionSize, SectionHeader[i].VirtualAddress, correct_size, SectionHeader[i].SizeOfRawData, SectionHeader[i].PointerToRawData) << "\n";

            correct_size += SectionSize;
            if (ctx.m_RebuildSectionSizes) {
                SectionHeader[i].Misc.VirtualSize = SectionSize;
            }
        }

        LOG("ImageBase: {:8x}", ntheader->OptionalHeader.ImageBase);
        LOG("ImageSize: {:8x}", ntheader->OptionalHeader.SizeOfImage);
        if (ntheader->OptionalHeader.SizeOfImage != correct_size && ctx.m_RebuildImageSize) {
            ntheader->OptionalHeader.SizeOfImage = correct_size;
            LOG("ImageSize changed to: {:8x}", correct_size);
        }

        if (ctx.m_DisableRebase) {
            ntheader->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
        }
    }

    if (ctx.m_PatchRuntime) {
        mem::scan(mem::pattern("01 b9 2f a9"), r).or_else([] { LOG("Couldn't patch launcher detection"); }).and_then([&](auto m) {
            LOG("Patching launcher detection at {:#x}", m_normalise_base(m));
            m.sub(9).rip(4).put_bytes(mem::pattern("b8 01 00 00 00 c3"));
        });

        if (ctx.m_Calls.size() < 3)
            LOG("Couldn't find second call to patch for runtime execution");
        else {
            auto& [call, target] = ctx.m_Calls[2];
            LOG("Patching runtime tamper detection at offset {:#x}", call);
            patch_nops(imagebuf.at(call), 5);
        }
    }

    // ctx.RebuildSection(imagebuf.GetBuffer(), (ULONG)(ctx.m_ImageEnd - ctx.m_ImageBase), RebuildSectionBuffer);

    // ctx.m_ImageRealEntry = 0x140000000;
    if (ctx.m_ImageRealEntry) ntheader->OptionalHeader.AddressOfEntryPoint = (ULONG)(ctx.m_ImageRealEntry - ctx.m_ImageBase);

    auto dumpfile = filename + ".upeed";

    FILE* fp = fopen(dumpfile.c_str(), "wb");

    fwrite(imagebuf.GetBuffer(), ctx.m_ImageEnd - ctx.m_ImageBase, 1, fp);

    // if (RebuildSectionBuffer.GetBuffer())
    //    fwrite(RebuildSectionBuffer.GetBuffer(), RebuildSectionBuffer.GetLength(), 1, fp);

    fclose(fp);
    return 0;
}

int WritePrologue(uc_engine* uc, uintptr_t prologue_address, uintptr_t start_address, int type = 0) {
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
            140001037  66 44 0F 11 3C 24                             movupd  xmmword [rsp], xmm15
            14000103D  66 0F 11 7C 24 10                             movupd  xmmword [rsp+10h], xmm7
            140001043  66 0F 11 5C 24 20                             movupd  xmmword [rsp+20h], xmm3
            140001049  66 44 0F 11 54 24 30                          movupd  xmmword [rsp+30h], xmm10
            140001050  66 0F 11 74 24 40                             movupd  xmmword [rsp+40h], xmm6
            140001056  66 0F 11 6C 24 50                             movupd  xmmword [rsp+50h], xmm5
            14000105C  66 0F 11 4C 24 60                             movupd  xmmword [rsp+60h], xmm1
            140001062  66 44 0F 11 4C 24 70                          movupd  xmmword [rsp+70h], xmm9
            140001069  66 44 0F 11 B4 24 80 00 00 00                 movupd  xmmword [rsp+80h], xmm14
            140001073  66 44 0F 11 84 24 90 00 00 00                 movupd  xmmword [rsp+90h], xmm8
            14000107D  66 44 0F 11 A4 24 A0 00 00 00                 movupd  xmmword [rsp+0A0h], xmm12
            140001087  66 0F 11 94 24 B0 00 00 00                    movupd  xmmword [rsp+0B0h], xmm2
            140001090  66 44 0F 11 9C 24 C0 00 00 00                 movupd  xmmword [rsp+0C0h], xmm11
            14000109A  66 0F 11 84 24 D0 00 00 00                    movupd  xmmword [rsp+0D0h], xmm0
            1400010A3  66 44 0F 11 AC 24 E0 00 00 00                 movupd  xmmword [rsp+0E0h], xmm13
            1400010AD  66 0F 11 A4 24 F0 00 00 00                    movupd  xmmword [rsp+0F0h], xmm4
            1400010AD
            1400010B6  6A 10                                         push    10h
            1400010B8  48 F7 C4 0F 00 00 00                          test    rsp, 0Fh
            1400010BF  75 02                                         jnz     short skip_balance
            1400010C1  6A 18                                         push    18h
            1400010C3
            1400010C3                                skip_balance:
            1400010C3  48 83 EC 08                                   sub     rsp, 8
            (inserted) 48 89 e5                                      mov     rbp, rsp
            1400010C7  FF 15 A2 00 00 00                             call    cs:TheChecker
            1400010CD  48 03 64 24 08                                add     rsp, [rsp+8]
            1400010D2  66 44 0F 10 3C 24                             movupd  xmm15, xmmword [rsp]
            1400010D8  66 0F 10 7C 24 10                             movupd  xmm7, xmmword [rsp+10h]
            1400010DE  66 0F 10 5C 24 20                             movupd  xmm3, xmmword [rsp+20h]
            1400010E4  66 44 0F 10 54 24 30                          movupd  xmm10, xmmword [rsp+30h]
            1400010EB  66 0F 10 74 24 40                             movupd  xmm6, xmmword [rsp+40h]
            1400010F1  66 0F 10 6C 24 50                             movupd  xmm5, xmmword [rsp+50h]
            1400010F7  66 0F 10 4C 24 60                             movupd  xmm1, xmmword [rsp+60h]
            1400010FD  66 44 0F 10 4C 24 70                          movupd  xmm9, xmmword [rsp+70h]
            140001104  66 44 0F 10 B4 24 80 00 00 00                 movupd  xmm14, xmmword [rsp+80h]
            14000110E  66 44 0F 10 84 24 90 00 00 00                 movupd  xmm8, xmmword [rsp+90h]
            140001118  66 44 0F 10 A4 24 A0 00 00 00                 movupd  xmm12, xmmword [rsp+0A0h]
            140001122  66 0F 10 94 24 B0 00 00 00                    movupd  xmm2, xmmword [rsp+0B0h]
            14000112B  66 44 0F 10 9C 24 C0 00 00 00                 movupd  xmm11, xmmword [rsp+0C0h]
            140001135  66 0F 10 84 24 D0 00 00 00                    movupd  xmm0, xmmword [rsp+0D0h]
            14000113E  66 44 0F 10 AC 24 E0 00 00 00                 movupd  xmm13, xmmword [rsp+0E0h]
            140001148  66 0F 10 A4 24 F0 00 00 00                    movupd  xmm4, xmmword [rsp+0F0h]
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

    /*
                push    1
                push    2
                push    3
                push    4
TheJudge:
                call    TheWitch
                int     3
TheWitch:
                call    TheCorpsegrinder
                int     3
TheCorpsegrinder:
                call    TheBalancer
                int     3
TheBalancer:
                push    r8
                push    r13
                push    r12
                push    r15
                push    rsi
                push    rdx
                push    rbx
                push    r9
                push    rax
                push    r14
                push    r10
                push    rdi
                push    r11
                lea     rsp, [rsp-100h]
                movupd  oword [rsp], xmm15
                movupd  oword [rsp+10h], xmm7
                movupd  oword [rsp+20h], xmm3
                movupd  oword [rsp+30h], xmm10
                movupd  oword [rsp+40h], xmm6
                movupd  oword [rsp+50h], xmm5
                movupd  oword [rsp+60h], xmm1
                movupd  oword [rsp+70h], xmm9
                movupd  oword [rsp+80h], xmm14
                movupd  oword [rsp+90h], xmm8
                movupd  oword [rsp+0A0h], xmm12
                movupd  oword [rsp+0B0h], xmm2
                movupd  oword [rsp+0C0h], xmm11
                movupd  oword [rsp+0D0h], xmm0
                movupd  oword [rsp+0E0h], xmm13
                movupd  oword [rsp+0F0h], xmm4
                push    10h
                test    rsp, 0Fh
                jnz     short skip_balance
                push    18h
skip_balance:
        jmp qword [rel TheChecker]
force_resume:
                add     rsp, [rsp+8]
                movupd  xmm15, xmmword [rsp]
                movupd  xmm7, xmmword [rsp+10h]
                movupd  xmm3, xmmword [rsp+20h]
                movupd  xmm10, xmmword [rsp+30h]
                movupd  xmm6, xmmword [rsp+40h]
                movupd  xmm5, xmmword [rsp+50h]
                movupd  xmm1, xmmword [rsp+60h]
                movupd  xmm9, xmmword [rsp+70h]
                movupd  xmm14, xmmword [rsp+80h]
                movupd  xmm8, xmmword [rsp+90h]
                movupd  xmm12, xmmword [rsp+0A0h]
                movupd  xmm2, xmmword [rsp+0B0h]
                movupd  xmm11, xmmword [rsp+0C0h]
                movupd  xmm0, xmmword [rsp+0D0h]
                movupd  xmm13, xmmword [rsp+0E0h]
                movupd  xmm4, xmmword [rsp+0F0h]
                lea     rsp, [rsp+100h]
                pop     r11
                pop     rdi
                pop     r10
                pop     r14
                pop     rax

                pop     r9
                pop     rbx
                pop     rdx
                pop     rsi
                pop     r15
                pop     r12
                pop     r13
                pop     r8
                retn
TheChecker:
                dq    0

*/

    unsigned char prologue_bytes_short[] =
        //{
        //       0x6a, 0x1, 0x6a, 0x2, 0x6a, 0x3, 0x6a, 0x4, 0xe8, 0x2, 0x0, 0x0, 0x0, 0xcd,
        //       0x3, 0xe8, 0x2, 0x0, 0x0, 0x0, 0xcd, 0x3, 0xe8, 0x2, 0x0, 0x0, 0x0, 0xcd, 0x3,
        //       0x41, 0x50, 0x41, 0x55, 0x41, 0x54, 0x41, 0x57, 0x56, 0x52, 0x53, 0x41, 0x51,
        //       0x50, 0x41, 0x56, 0x41, 0x52, 0x57, 0x41, 0x53, 0x48, 0x8d, 0xa4, 0x24, 0x0,
        //       0xff, 0xff, 0xff, 0x66, 0x44, 0xf, 0x11, 0x3c, 0x24, 0x66, 0xf, 0x11, 0x7c,
        //       0x24, 0x10, 0x66, 0xf, 0x11, 0x5c, 0x24, 0x20, 0x66, 0x44, 0xf, 0x11, 0x54,
        //       0x24, 0x30, 0x66, 0xf, 0x11, 0x74, 0x24, 0x40, 0x66, 0xf, 0x11, 0x6c, 0x24,
        //       0x50, 0x66, 0xf, 0x11, 0x4c, 0x24, 0x60, 0x66, 0x44, 0xf, 0x11, 0x4c, 0x24,
        //       0x70, 0x66, 0x44, 0xf, 0x11, 0xb4, 0x24, 0x80, 0x0, 0x0, 0x0, 0x66, 0x44, 0xf,
        //       0x11, 0x84, 0x24, 0x90, 0x0, 0x0, 0x0, 0x66, 0x44, 0xf, 0x11, 0xa4, 0x24, 0xa0,
        //       0x0, 0x0, 0x0, 0x66, 0xf, 0x11, 0x94, 0x24, 0xb0, 0x0, 0x0, 0x0, 0x66, 0x44,
        //       0xf, 0x11, 0x9c, 0x24, 0xc0, 0x0, 0x0, 0x0, 0x66, 0xf, 0x11, 0x84, 0x24, 0xd0,
        //       0x0, 0x0, 0x0, 0x66, 0x44, 0xf, 0x11, 0xac, 0x24, 0xe0, 0x0, 0x0, 0x0, 0x66,
        //       0xf, 0x11, 0xa4, 0x24, 0xf0, 0x0, 0x0, 0x0, 0x6a, 0x10, 0x48, 0xf7, 0xc4, 0xf,
        //       0x0, 0x0, 0x0, 0x75, 0x2, 0x6a, 0x18, 0xff, 0x25, 0x0, 0x0, 0x0, 0x0};

        {0x6a, 0x1,  0x6a, 0x2,  0x6a, 0x3,  0x6a, 0x4,  0xe8, 0x2,  0x0,  0x0,  0x0,  0xcd, 0x3,  0xe8, 0x2,  0x0,  0x0,  0x0,  0xcd, 0x3,  0xe8, 0x2,  0x0,  0x0,  0x0,  0xcd, 0x3,  0x41, 0x50, 0x41, 0x55, 0x41, 0x54, 0x41, 0x57, 0x56, 0x52, 0x53, 0x41, 0x51, 0x50, 0x41, 0x56, 0x41, 0x52, 0x57, 0x41, 0x53, 0x48, 0x8d, 0xa4, 0x24, 0x0,  0xff, 0xff, 0xff, 0x66, 0x44, 0xf,  0x11, 0x3c, 0x24, 0x66, 0xf,  0x11, 0x7c, 0x24, 0x10, 0x66, 0xf,  0x11, 0x5c,
         0x24, 0x20, 0x66, 0x44, 0xf,  0x11, 0x54, 0x24, 0x30, 0x66, 0xf,  0x11, 0x74, 0x24, 0x40, 0x66, 0xf,  0x11, 0x6c, 0x24, 0x50, 0x66, 0xf,  0x11, 0x4c, 0x24, 0x60, 0x66, 0x44, 0xf,  0x11, 0x4c, 0x24, 0x70, 0x66, 0x44, 0xf,  0x11, 0xb4, 0x24, 0x80, 0x0,  0x0,  0x0,  0x66, 0x44, 0xf,  0x11, 0x84, 0x24, 0x90, 0x0,  0x0,  0x0,  0x66, 0x44, 0xf,  0x11, 0xa4, 0x24, 0xa0, 0x0,  0x0,  0x0,  0x66, 0xf,  0x11, 0x94, 0x24, 0xb0, 0x0,  0x0,  0x0,  0x66,
         0x44, 0xf,  0x11, 0x9c, 0x24, 0xc0, 0x0,  0x0,  0x0,  0x66, 0xf,  0x11, 0x84, 0x24, 0xd0, 0x0,  0x0,  0x0,  0x66, 0x44, 0xf,  0x11, 0xac, 0x24, 0xe0, 0x0,  0x0,  0x0,  0x66, 0xf,  0x11, 0xa4, 0x24, 0xf0, 0x0,  0x0,  0x0,  0x6a, 0x10, 0x48, 0xf7, 0xc4, 0xf,  0x0,  0x0,  0x0,  0x75, 0x2,  0x6a, 0x18, 0xff, 0x25, 0xa2, 0x0,  0x0,  0x0,  0x48, 0x3,  0x64, 0x24, 0x8,  0x66, 0x44, 0xf,  0x10, 0x3c, 0x24, 0x66, 0xf,  0x10, 0x7c, 0x24, 0x10, 0x66,
         0xf,  0x10, 0x5c, 0x24, 0x20, 0x66, 0x44, 0xf,  0x10, 0x54, 0x24, 0x30, 0x66, 0xf,  0x10, 0x74, 0x24, 0x40, 0x66, 0xf,  0x10, 0x6c, 0x24, 0x50, 0x66, 0xf,  0x10, 0x4c, 0x24, 0x60, 0x66, 0x44, 0xf,  0x10, 0x4c, 0x24, 0x70, 0x66, 0x44, 0xf,  0x10, 0xb4, 0x24, 0x80, 0x0,  0x0,  0x0,  0x66, 0x44, 0xf,  0x10, 0x84, 0x24, 0x90, 0x0,  0x0,  0x0,  0x66, 0x44, 0xf,  0x10, 0xa4, 0x24, 0xa0, 0x0,  0x0,  0x0,  0x66, 0xf,  0x10, 0x94, 0x24, 0xb0, 0x0,
         0x0,  0x0,  0x66, 0x44, 0xf,  0x10, 0x9c, 0x24, 0xc0, 0x0,  0x0,  0x0,  0x66, 0xf,  0x10, 0x84, 0x24, 0xd0, 0x0,  0x0,  0x0,  0x66, 0x44, 0xf,  0x10, 0xac, 0x24, 0xe0, 0x0,  0x0,  0x0,  0x66, 0xf,  0x10, 0xa4, 0x24, 0xf0, 0x0,  0x0,  0x0,  0x48, 0x8d, 0xa4, 0x24, 0x0,  0x1,  0x0,  0x0,  0x41, 0x5b, 0x5f, 0x41, 0x5a, 0x41, 0x5e, 0x58, 0x41, 0x59, 0x5b, 0x5a, 0x5e, 0x41, 0x5f, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x58, 0xc3};

    unsigned char prologue_bytes[] = {0x6a, 0x1,  0x6a, 0x2,  0x6a, 0x3,  0x6a, 0x4,  0xe8, 0x1,  0x0,  0x0,  0x0,  0xcc, 0xe8, 0x1,  0x0,  0x0,  0x0,  0xcc, 0xe8, 0x1,  0x0,  0x0,  0x0,  0xcc, 0x41, 0x50, 0x41, 0x55, 0x41, 0x54, 0x41, 0x57, 0x56, 0x52, 0x53, 0x41, 0x51, 0x50, 0x41, 0x56, 0x41, 0x52, 0x57, 0x41, 0x53, 0x48, 0x8d, 0xa4, 0x24, 0x0,  0xff, 0xff, 0xff, 0x66, 0x44, 0xf,  0x11, 0x3c, 0x24, 0x66, 0xf,  0x11, 0x7c, 0x24, 0x10,
                                      0x66, 0xf,  0x11, 0x5c, 0x24, 0x20, 0x66, 0x44, 0xf,  0x11, 0x54, 0x24, 0x30, 0x66, 0xf,  0x11, 0x74, 0x24, 0x40, 0x66, 0xf,  0x11, 0x6c, 0x24, 0x50, 0x66, 0xf,  0x11, 0x4c, 0x24, 0x60, 0x66, 0x44, 0xf,  0x11, 0x4c, 0x24, 0x70, 0x66, 0x44, 0xf,  0x11, 0xb4, 0x24, 0x80, 0x0,  0x0,  0x0,  0x66, 0x44, 0xf,  0x11, 0x84, 0x24, 0x90, 0x0,  0x0,  0x0,  0x66, 0x44, 0xf,  0x11, 0xa4, 0x24, 0xa0, 0x0,  0x0,
                                      0x0,  0x66, 0xf,  0x11, 0x94, 0x24, 0xb0, 0x0,  0x0,  0x0,  0x66, 0x44, 0xf,  0x11, 0x9c, 0x24, 0xc0, 0x0,  0x0,  0x0,  0x66, 0xf,  0x11, 0x84, 0x24, 0xd0, 0x0,  0x0,  0x0,  0x66, 0x44, 0xf,  0x11, 0xac, 0x24, 0xe0, 0x0,  0x0,  0x0,  0x66, 0xf,  0x11, 0xa4, 0x24, 0xf0, 0x0,  0x0,  0x0,  0x6a, 0x10, 0x48, 0xf7, 0xc4, 0xf,  0x0,  0x0,  0x0,  0x75, 0x2,  0x6a, 0x18, 0x48, 0x83, 0xec, 0x8,

                                      0x48, 0x89, 0xe5,

                                      0xff, 0x15, 0xa2, 0x0,  0x0,  0x0,  0x48, 0x3,  0x64, 0x24, 0x8,  0x66, 0x44, 0xf,  0x10, 0x3c, 0x24, 0x66, 0xf,  0x10, 0x7c, 0x24, 0x10, 0x66, 0xf,  0x10, 0x5c, 0x24, 0x20, 0x66, 0x44, 0xf,  0x10, 0x54, 0x24, 0x30, 0x66, 0xf,  0x10, 0x74, 0x24, 0x40, 0x66, 0xf,  0x10, 0x6c, 0x24, 0x50, 0x66, 0xf,  0x10, 0x4c, 0x24, 0x60, 0x66, 0x44, 0xf,  0x10, 0x4c, 0x24, 0x70, 0x66, 0x44, 0xf,  0x10, 0xb4, 0x24,
                                      0x80, 0x0,  0x0,  0x0,  0x66, 0x44, 0xf,  0x10, 0x84, 0x24, 0x90, 0x0,  0x0,  0x0,  0x66, 0x44, 0xf,  0x10, 0xa4, 0x24, 0xa0, 0x0,  0x0,  0x0,  0x66, 0xf,  0x10, 0x94, 0x24, 0xb0, 0x0,  0x0,  0x0,  0x66, 0x44, 0xf,  0x10, 0x9c, 0x24, 0xc0, 0x0,  0x0,  0x0,  0x66, 0xf,  0x10, 0x84, 0x24, 0xd0, 0x0,  0x0,  0x0,  0x66, 0x44, 0xf,  0x10, 0xac, 0x24, 0xe0, 0x0,  0x0,  0x0,  0x66, 0xf,  0x10, 0xa4, 0x24,
                                      0xf0, 0x0,  0x0,  0x0,  0x48, 0x8d, 0xa4, 0x24, 0x0,  0x1,  0x0,  0x0,  0x41, 0x5b, 0x5f, 0x41, 0x5a, 0x41, 0x5e, 0x58, 0x41, 0x59, 0x5b, 0x5a, 0x5e, 0x41, 0x5f, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x58, 0xc3};

    uc_err err;
    if (type == 0) {
        err = uc_mem_write(uc, prologue_address, prologue_bytes, sizeof(prologue_bytes));
        err = uc_mem_write(uc, prologue_address + sizeof(prologue_bytes), &start_address, 8);
        return sizeof(prologue_bytes);
    } else if (type == 1) {
        err = uc_mem_write(uc, prologue_address, prologue_bytes_short, sizeof(prologue_bytes_short));
        err = uc_mem_write(uc, prologue_address + sizeof(prologue_bytes_short), &start_address, 8);
        return sizeof(prologue_bytes_short);
    }
    LOG(__FUNCTION__ ": unknown prologue type: {}", type);
    return 0;
}

void RegisterAPIs(PeEmulation& ctx) {
    if (!ctx.m_IsKernel) {
        ctx.RegisterAPIEmulation(L"kernel32.dll", "GetSystemTimeAsFileTime", EmuGetSystemTimeAsFileTime, 1);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "GetCurrentThreadId", EmuGetCurrentThreadId, 0);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "GetCurrentProcessId", EmuGetCurrentProcessId, 0);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "GetCurrentProcess", EmuGetCurrentProcess, 0);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "QueryPerformanceCounter", EmuQueryPerformanceCounter, 1);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "LoadLibraryExW", EmuLoadLibraryExW, 3);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "LoadLibraryA", EmuLoadLibraryA, 1);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "GetProcAddress", EmuGetProcAddress, 2);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "GetModuleHandleA", EmuGetModuleHandleA, 1);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "GetLastError", EmuGetLastError, 0);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "InitializeCriticalSectionAndSpinCount", EmuInitializeCriticalSectionAndSpinCount, 2);

        if (!ctx.RegisterAPIEmulation(L"kernelbase.dll", "InitializeCriticalSectionEx", EmuInitializeCriticalSectionEx, 3)) ctx.RegisterAPIEmulation(L"kernel32.dll", "InitializeCriticalSectionEx", EmuInitializeCriticalSectionEx, 3);

        ctx.RegisterAPIEmulation(L"ntdll.dll", "RtlDeleteCriticalSection", EmuDeleteCriticalSection, 1);
        ctx.RegisterAPIEmulation(L"ntdll.dll", "RtlIsProcessorFeaturePresent", EmuRtlIsProcessorFeaturePresent, 1);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "GetProcessAffinityMask", EmuGetProcessAffinityMask, 1);

        ctx.RegisterAPIEmulation(L"kernel32.dll", "TlsAlloc", EmuTlsAlloc, 0);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "TlsSetValue", EmuTlsSetValue, 2);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "TlsFree", EmuTlsFree, 1);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "LocalAlloc", EmuLocalAlloc, 2);
        ctx.RegisterAPIEmulation(L"ntdll.dll", "NtProtectVirtualMemory", EmuNtProtectVirtualMemory, 5);
        // ctx.RegisterAPIEmulation(L"kernel32.dll", "VirtualProtectEx", EmuVirtualProtectEx, 6);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "VirtualProtect", EmuVirtualProtect, 4);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "VirtualQueryEx", EmuVirtualQueryEx, 4);
        ctx.RegisterAPIEmulation(L"kernel32.dll", "VirtualQuery", EmuVirtualQuery, 3);

        ctx.RegisterAPIEmulation(L"kernel32.dll", "GetSystemInfo", EmuGetSystemInfo, 1);

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
}

int main(int argc, char** argv) {
    using namespace blackbone;

    Timer timer;

    PeEmulation& ctx = g_ctx;


    auto cmdl = argh::parser(argc, argv);
    outs      = &std::cout;

#ifdef USE_BOOST
    init_multimatches();
#endif

    if (!cmdl(1)) {
        printf("usage: unicorn_pe (filename) [--decrypt | --unpack] [--disasm] [--save-dump] [--bitmap] [--obfu] [--save-written=PATH] [--save-read[-ranges]=PATH]\n");
        return 0;
    }

    *outs << "Positional args:\n";
    for (auto& pos_arg : cmdl.pos_args()) *outs << '\t' << pos_arg << '\n';

    *outs << "\nFlags:\n";
    for (auto& flag : cmdl.flags()) *outs << '\t' << flag << '\n';

    *outs << "\nParameters:\n";
    for (auto& param : cmdl.params()) *outs << '\t' << param.first << " : " << param.second << '\n';

    if (cmdl["tmp"]) {
        // tmpname: C:\Users\sfink\AppData\Local\Temp\ss44.0
        // fulltmpname: C:\Users\sfink\AppData\Local\Temp\ss44.1
        // tmpdir: C:\Users\sfink\AppData\Local\Temp

        LOG("tmpname: {}", tmpname());
        LOG("fulltmpname: {}", fulltmpname());
        LOG("tmpdir: {}", tmpdir());
    }

    //*outs << "\nValues for all multiple-use parameters:\n";
    // for (const auto& param : _::uniq _VECTOR(std::string)(_::keys2(cmdl.params())))
    //    if (cmdl.params(param).size() > 1) {
    //        for (auto& param2 : cmdl.params(param))  // iterate on all params called "input"
    //            *outs << '\t' << param2.first << " : " << param2.second << '\n';
    //        *outs << '\n';
    //    }

    std::string filename;
    cmdl(1) >> filename;
    std::wstring wfilename;
    ANSIToUnicode(smart_path(filename), wfilename);

    if (!fs::exists(wfilename)) {
        LOG("File does not exist: {}", narrow(wfilename));
    }

    bool bKernel              = true;
    ctx.m_IsKernel            = cmdl["k"];
    ctx.m_Disassemble         = cmdl["disasm"];
    ctx.m_Unpack              = cmdl["unpack"];
    ctx.m_IsPacked            = cmdl["packed"];  // some vmprotect stuff that was already here
    ctx.m_BoundCheck          = cmdl["boundcheck"];
    ctx.m_Dump                = cmdl[{"save-dump", "dump"}];
    ctx.m_FindChecks          = cmdl["find"];
    ctx.m_FindBalance         = cmdl[{"decrypt", "find-balance"}];
    ctx.m_SkipSecondCall      = cmdl["skip-second-call"];
    ctx.m_SkipFourthCall      = cmdl["skip-4th-call"];
    ctx.m_Obfu                = cmdl["obfu"];
    ctx.m_PatchRuntime        = cmdl["patch-runtime"];
    ctx.m_RebuildImageSize    = cmdl["rebuild-size"];
    ctx.m_RebuildSectionSizes = cmdl["rebuild-sections"];
    ctx.m_DisableRebase       = cmdl["no-aslr"];
    ctx.m_Dwords              = cmdl["dwords"];
    ctx.m_Sandbox             = !cmdl["no-sandbox"];
    if (cmdl("rax")) cmdl("rax") >> ctx.m_InitReg.Rax;
    if (cmdl("rcx")) cmdl("rcx") >> ctx.m_InitReg.Rcx;
    if (cmdl("rdx")) cmdl("rdx") >> ctx.m_InitReg.Rdx;
    if (cmdl("rbx")) cmdl("rbx") >> ctx.m_InitReg.Rbx;
    if (cmdl("rsp")) cmdl("rsp") >> ctx.m_InitReg.Rsp;
    if (cmdl("rbp")) cmdl("rbp") >> ctx.m_InitReg.Rbp;
    if (cmdl("rsi")) cmdl("rsi") >> ctx.m_InitReg.Rsi;
    if (cmdl("rdi")) cmdl("rdi") >> ctx.m_InitReg.Rdi;
    if (cmdl("r8")) cmdl("r8") >> ctx.m_InitReg.R8;
    if (cmdl("r9")) cmdl("r9") >> ctx.m_InitReg.R9;
    if (cmdl("r10")) cmdl("r10") >> ctx.m_InitReg.R10;
    if (cmdl("r11")) cmdl("r11") >> ctx.m_InitReg.R11;
    if (cmdl("r12")) cmdl("r12") >> ctx.m_InitReg.R12;
    if (cmdl("r13")) cmdl("r13") >> ctx.m_InitReg.R13;
    if (cmdl("r14")) cmdl("r14") >> ctx.m_InitReg.R14;
    if (cmdl("r15")) cmdl("r15") >> ctx.m_InitReg.R15;

    if (cmdl("save-written") >> ctx.m_SaveWritten) {
        if (!fs::is_directory(ctx.m_SaveWritten) && !fs::create_directory(ctx.m_SaveWritten)) {
            *outs << "Not a directory: " << ctx.m_SaveWritten << "\n";
            return 0;
        }
        *outs << "Saving memory writes to " << ctx.m_SaveWritten << "\n";
        make_spread_folders(ctx.m_SaveWritten);
    }
    if (cmdl("save-read") >> ctx.m_SaveRead) {
        if (!fs::is_directory(ctx.m_SaveRead) && !fs::create_directory(ctx.m_SaveRead)) {
            *outs << "Not a directory: " << ctx.m_SaveRead << "\n";
            return 0;
        }
        *outs << "Saving memory reads to " << ctx.m_SaveRead << "\n";
        make_spread_folders(ctx.m_SaveRead);
    }
    if (cmdl("save-read-ranges") >> ctx.m_SaveReadRanges) {
        if (!fs::is_directory(ctx.m_SaveReadRanges) && !fs::create_directory(ctx.m_SaveReadRanges)) {
            *outs << "Not a directory: " << ctx.m_SaveReadRanges << "\n";
            return 0;
        }
        *outs << "Saving memory read ranges to " << ctx.m_SaveReadRanges << "\n";
    }
    if (cmdl("save-written-ranges") >> ctx.m_SaveWrittenRanges) {
        if (!fs::is_directory(ctx.m_SaveWrittenRanges) && !fs::create_directory(ctx.m_SaveWrittenRanges)) {
            *outs << "Not a directory: " << ctx.m_SaveWrittenRanges << "\n";
            return 0;
        }
        *outs << "Saving memory written ranges to " << ctx.m_SaveWrittenRanges << "\n";
    }
    uc_engine* uc = nullptr;
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
    /// (1) CS_OP_DETAIL = CS_OPT_ON
    /// (2) Engine is not in Skipdata mode (CS_OP_SKIPDATA option set to CS_OPT_ON)
    auto err3 = cs_option(ctx.m_cs, CS_OPT_DETAIL, CS_OPT_ON);
    if (err3) {
        printf("failed to cs_option CS_OPT_DETAIL %d\n", err2);
        return 0;
    }
    auto err4 = cs_option(ctx.m_cs, CS_OPT_SKIPDATA, CS_OPT_OFF);
    if (err4) {
        printf("failed to cs_option CS_OPT_SKIPDATA %d\n", err2);
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

    // allocate virtual stack for execution
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

    auto MapResult = ctx.thisProc.mmap().MapImage(wfilename, RebaseProcess | ManualImports | NoSxS | NoExceptions | NoDelayLoad | NoTLS | NoExceptions | NoExec, ManualMapCallback, &ctx, nullptr, 0x140000000, PreManualMapCallback);

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

    if (cmdl("entry")) {
        if (auto addr = asQword(cmdl("entry").str())) {
            ctx.m_ExecuteFromRip = *addr;
        }
    }
    // 143E5F107
    printf("ctx.m_ImageBase: 0x%llx\n", ctx.m_ImageBase);
    printf("ctx.m_ImageEnd: 0x%llx\n", ctx.m_ImageEnd);
    printf("ctx.m_ImageEntry: 0x%llx\n", ctx.m_ImageEntry);
    printf("ctx.m_LastRipModule: 0x%llx\n", ctx.m_LastRipModule);
    printf("ctx.m_ExecuteFromRip: 0x%llx\n", ctx.m_ExecuteFromRip);

    RegisterAPIs(ctx);

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

    // return to image end when entrypoint is executed
    ResetRegisters(uc, ctx);

    uc_hook_add(uc, &trace, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT | UC_HOOK_MEM_WRITE_PROT, InvalidRwxCallback, &ctx, 1, 0);

    uc_hook_add(uc, &trace2, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH, RwxCallback, &ctx, 1, 0);
    if (ctx.m_Disassemble || ctx.m_FindBalance) {
        uc_hook_add(uc, &trace3, UC_HOOK_CODE, CodeCallback, &ctx, 1, 0);
    }

    uc_hook_add(uc, &trace3, UC_HOOK_INTR, IntrCallback, &ctx, 1, 0);

    std::vector<std::tuple<std::string, uintptr_t>> fns;
    std::vector<std::tuple<std::string, uintptr_t>> balance_fns;
    {
        std::string nasm;
        for (auto& param : cmdl.params("nasm")) {
            auto st_addr  = string_between("", ":", param.second);
            auto st_patch = string_between(":", "", param.second);
            if (st_addr == "image_end") st_addr = fmt::format("{:#x}", ctx.m_ImageEnd);
            if (auto addr = asQword(st_addr, 16)) {
                LOG("patching {:#x} with {}", *addr, st_patch);
                if (pystring::startswith(st_patch, "<")) {
                    auto fn = pystring::slice(st_patch, 1);
                    if (!file_exists(fn)) {
                        LOG("file does not exist: {}", fn);
                        break;
                    }
                    nasm = file_get_contents(fn);
                } else {
                    nasm = cmdl("nasm").str();
                }
                LOG("assembling: {}", nasm);
                YasmExt yasm(nasm, *addr);
                if (yasm.prep()) {
                    LOG("patching {:#x} with {}", *addr, HexDump::asString(yasm.get_assembled()));
                    mbs(*addr).memcpy(yasm.get_assembled().data(), yasm.get_assembled().size());
                }
            } else
                LOG("patching: couldn't process {} as an address", st_addr);
        }
    }

    // --patch="14000100:66 90 E9 00 00 00 00" --patch= ...
    for (auto& param : cmdl.params("mem")) {
        auto st_address  = string_between("", ":", param.second);
        auto st_commands = string_between(":", "", param.second);
        uintptr_t result = 0;
        LOG("mem: {}", st_commands);
        if (auto addr = asQword(st_address)) {
            result = *addr;
        }
        mem_parser(ctx, st_commands, result, cmdl);
        outs->flush();
    }

    for (auto& param : cmdl.params("patch")) {
        auto st_addr  = string_between("", ":", param.second);
        auto st_patch = string_between(":", "", param.second);
        if (st_addr == "image_end") st_addr = fmt::format("{:#x}", ctx.m_ImageEnd);
        if (auto addr = asQword(st_addr, 16)) {
            LOG("patching {:#x} with {}", *addr, st_patch);
            mbs(*addr).write_pattern(st_patch.c_str());
        } else
            LOG("patching: couldn't process {} as an address", st_addr);
    }

    {
        ctx.filename = filename;
        *outs << "Filename: " << ctx.filename << "\n";

        std::vector<std::string> filenames{ctx.filename, "default.exe"};
        for (const auto& basename : filenames) {
            auto fnJson = replace_extension(basename, ".funcs.json");
            if (fs::exists(fnJson)) {
                megafunc = new MegaFunc(fnJson);
                LOG_INFO(__FUNCTION__ ": reversed location 0x140001000 to: %s", megafunc->Lookup(0x100).c_str());
                break;
            }
        }

        for (const auto& basename : filenames) {
            auto fnJson = replace_extension(ctx.filename, ".names.json");
            if (fs::exists(fnJson)) {
                LOG("reading names from {}", fnJson);
                std::ifstream infile(fnJson);
                json j;
                infile >> j;

                for (auto& [name, value] : j.items()) {
                    if (value.is_number() && !value.empty()) {
                        auto [it1, happy1] = megaFuncNames.emplace(value, name);
                    }
                }
                break;
            }
        }
    }

    //*outs << "\nValues for all `--ea` parameters:\n";
    for (auto& param : cmdl.params("start"))  // iterate on all params called "start"
    {
        if (param.second == "image_end") {
            ctx.m_StartAddresses.emplace_back(ctx.m_ImageEnd);
            continue;
        }

        auto st_start = param.second;

        if (pystring::startswith(st_start, "<")) {
            auto fn = pystring::slice(st_start, 1);
            if (!file_exists(fn)) {
                LOG("file does not exist: {}", fn);
                break;
            }
            std::ifstream infile(fn);
            uintptr_t a;
            std::string h;
            while (infile >> h) {
                a = parseInt(h, 16, 0LLU);

                *outs << "adding " << std::hex << a << std::dec << std::endl;
                ctx.m_StartAddresses.emplace_back(a);
            }
        } else {
            char* errch      = nullptr;
            uintptr_t target = strtoull(param.second.c_str(), &errch, 16);
            if (*errch != '\0') {
                *outs << "string couldn't be converted to ll: " << param.second.c_str() << "\n";
                continue;
            }
            *outs << '\t' << param.first << " : " << std::hex << param.second << std::dec << '\n';
            ctx.m_StartAddresses.emplace_back(target);
        }
    }

    if (ctx.m_StartAddresses.size()) {
        for (uintptr_t ptr : ctx.m_StartAddresses) {
            fns.emplace_back(fmt::format("BalanceFunc_{:x}", ptr), ptr);
        }
    }

    if (ctx.m_FindBalance) {
        virtual_buffer_t imagebuf(ctx.m_ImageEnd - ctx.m_ImageBase);
        uc_mem_read(uc, ctx.m_ImageBase, imagebuf.GetBuffer(), ctx.m_ImageEnd - ctx.m_ImageBase);
        mem::region r(imagebuf.GetBuffer(), imagebuf.GetLength());
        mem::region rr(ctx.m_ImageBase, ctx.m_ImageEnd - ctx.m_ImageBase);

        auto normalise_base   = [&](uintptr_t ea) { return r.adjust_base_to(0x140000000, ea).as<uintptr_t>(); };
        auto m_normalise_base = [&](mem::pointer& ea) { return r.adjust_base_to(0x140000000, ea.as<uintptr_t>()).as<uintptr_t>(); };

        // mb("6A 10 48 F7 C4 0F 00 00 00 0F 85 ?? ?? ?? ?? E9").add(11).rip()
        auto found = scan_all_with_iteratee(r, mem::pattern("6A 10 48 F7 C4 0F 00 00 00 0F 85 ?? ?? ?? ?? E9"), [&](mem::pointer ea) -> uintptr_t {
            mem::pointer ptr(ea);
            ptr = ptr.add(11).rip(4);
            if (r.contains(ptr)) {
                return m_normalise_base(ptr);
            }
            return {};
        });

        // sort and make unique, then add to list of functions to scan
        std::sort(found.begin(), found.end(), [](const auto& lhs, const auto& rhs) { return lhs < rhs; });
        auto last = std::unique(found.begin(), found.end(), [](const auto& lhs, const auto& rhs) { return lhs == rhs; });
        found.erase(last, found.end());
        for (auto ptr : found) {
            balance_fns.emplace_back(fmt::format("BalanceFunc_{:x}", ptr.as<uintptr_t>()), ptr.as<uintptr_t>());
        }
        *outs << "Found " << balance_fns.size() << " matching balance functions\n";
    }
    if (ctx.m_FindChecks || cmdl("find-ref")) {
        virtual_buffer_t imagebuf(ctx.m_ImageEnd - ctx.m_ImageBase);
        uc_mem_read(uc, ctx.m_ImageBase, imagebuf.GetBuffer(), ctx.m_ImageEnd - ctx.m_ImageBase);
        mem::region r(imagebuf.GetBuffer(), imagebuf.GetLength());
        mem::region rr(ctx.m_ImageBase, ctx.m_ImageEnd - ctx.m_ImageBase);

        auto normalise_base = [&](uintptr_t ea) {
            return r.adjust_base_to(0x140000000, ea).as<uintptr_t>();
            // return ea - (uintptr_t)imagebuf.GetBuffer() + 0x140000000;
        };
        auto m_normalise_base = [&](mem::pointer& ea) { return r.adjust_base_to(0x140000000, ea.as<uintptr_t>()).as<uintptr_t>(); };

        std::set<uintptr_t> find_ref_dupes;
        std::deque<uintptr_t> find_refs;
        for (auto& param : cmdl.params("find-ref")) {
            for (auto expanded : sfinktah::string::brace_expander::expand(param.second)) {
                if (auto addr = asQword(expanded, 16)) {
                    find_refs.emplace_back(*addr);
                } else
                    LOG("couldn't process '{}' as an address", param.second);
            }
        }

        bool recursive = cmdl["r"];
        while (!find_refs.empty()) {
            auto target = find_refs.front();
            find_refs.pop_front();
            LOG("searching  for reference to {:#x}", target);
            auto ImageSize = ctx.m_ImageEnd - ctx.m_ImageBase - 8;
            auto ptr       = mem::pointer(imagebuf.GetBuffer());
            for (size_t a = 0; a < ImageSize; ++a) {
                if (ptr.at<int32_t>(a) + 0x140000000 + a + 4 == target) {
                    auto at = 0x140000000 + a;
                    LOG("found relative reference to {:#x} at {}", target, megalookup(at));
                    if (recursive) {
                        if (find_ref_dupes.emplace(0x140000000 + a).second) {
                            find_refs.emplace_back(0x140000000 + a);
                        }
                    }
                }
                if (ptr.at<uintptr_t>(a) == target) {
                    auto at = 0x140000000 + a;
                    LOG("found absolute reference to {:#x} at {}", target, megalookup(at));
                    if (recursive) {
                        if (find_ref_dupes.emplace(0x140000000 + a).second) {
                            find_refs.emplace_back(0x140000000 + a);
                        }
                    }
                }
            }
        }
        if (cmdl("find-ref")) {
            LOG("that's it");
            outs->flush();
            TerminateProcess(GetCurrentProcess(), 2);
        }

        auto iteratee = [&](uintptr_t ptr) -> uintptr_t {
            mem::pointer ea(ptr);
            const auto o_rel = 3;
            const auto o_abs = 14;
            // relative address requires normalisation
            const auto rel = normalise_base(ea.add(o_rel).rip(4).as<uintptr_t>());
            // virtual_buffer may be stored at strange location, but the image
            // itself is rebased at 0x140000000 so when extracting an absolute
            // reference, there is no need to normalise.
            // const auto abso = ea.add(o_abs).rip(4).deref().as<uintptr_t>();
            auto abso_offset = ea.add(o_abs).rip(4);
            if (r.contains(abso_offset)) {
                auto abso_ptr = abso_offset.as<uintptr_t&>();
                // auto abso_ptr = abso_offset.deref();
                if (rr.contains(abso_ptr)) {
                    auto abso = abso_offset.as<uintptr_t&>();
                    if (rel == abso) {
                        return abso;
                    }
                }
            }
            *outs << fmt::format("find failed at: {:x}: rel: {:x}", normalise_base(ea.as<uintptr_t>()), rel) << "\n";
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
            // const auto abso = ea.add(o_abs).rip(4).deref().as<uintptr_t>();
            auto abso_offset = ea.add(o_abs).rip(4);
            if (r.contains(abso_offset)) {
                auto abso_ptr = abso_offset.as<uintptr_t&>();
                // auto abso_ptr = abso_offset.deref();
                if (rr.contains(abso_ptr)) {
                    auto abso = abso_offset.as<uintptr_t&>();
                    if (rel == abso) {
                        return abso;
                    }
                } else
                    LOG("abso_ptr: {}", abso_offset.as<uintptr_t>());
            }
            *outs << fmt::format("find failed at: {:x}: rel: {:x}", normalise_base(ea.as<uintptr_t>()), rel) << "\n";
            return 0;
        };

        auto m_skip_jmps = [&](mem::pointer& ea) -> bool {
            auto byte = ea.as<uint8_t&>();
            auto addr = m_normalise_base(ea);
            // compiler will optimise using sneaky trick
            while (byte == 0xe9 || byte == 0xeb) {
                if (byte == 0xe9)
                    ea = ea.add(1).rip(4);
                else
                    // jmp short
                    ea += ea.at<int8_t>(1) + 2;
                if (!r.contains(ea)) return LOG("SKIPJMPFAILREGION1: {:x}", addr), false;
            }
            return true;
        };

        auto iteratee11 = [&](mem::pointer ea) -> uintptr_t {
            const auto o_abs = 3;
            const auto o_rel = 14;

            // 48 8B 05 08 88 B8 00                              mov     rax, cs:_off_image_base
            // 48 89 45 38                                       mov     [rbp+38h], rax
            // 48 8D 05 8B BA 85 00                              lea     rax, check_func
            // 48 89 45 18                                       mov     [rbp+18h], rax
            // 48 8B 05 90 D6 D6 00                              mov     rax, cs:_off_check_func
            // 48 F7 D8                                          neg     rax
            auto abso_ptr = ea.add(o_abs).rip(4);
            if (r.contains(abso_ptr)) {
                abso_ptr = abso_ptr.deref();
                if (abso_ptr.as<uintptr_t>() == 0x140000000) {
                    const auto rel = normalise_base(ea.add(o_rel).rip(4).as<uintptr_t>());
                    if (rr.contains(rel)) {
                        ea += 0x12;
                        if (!m_skip_jmps(ea)) return LOG_NOOP("FASTFAIL1: {:x}", m_normalise_base(ea)), 0;
                        if ((ea.as<uint32_t&>() & 0x00ffffff) != 0x00458948)  // 'mov [rbp+0x18], rax'
                            return LOG_NOOP("FASTFAIL2: {:x}", m_normalise_base(ea)), 0;
                        ea += 4;
                        if (!m_skip_jmps(ea)) return LOG_NOOP("FASTFAIL3: {:x}", m_normalise_base(ea)), 0;
                        if ((ea.as<uint32_t&>() & 0x00ffffff) != 0x00058b48)  // 'mov rax, [rel off_146C028B2]'
                            return LOG_NOOP("FASTFAIL4: {:x}", m_normalise_base(ea)), 0;
                        abso_ptr = ea.add(3).rip(4);
                        if (r.contains(abso_ptr)) {
                            const auto abso = abso_ptr.as<uintptr_t&>();
                            if (rel == abso) {
                                return LOG_NOOP("ITER11: {:x}", m_normalise_base(ea)), abso;
                            }
                            return LOG_NOOP("SLOWFAIL2: {:x}", m_normalise_base(ea)), 0;
                        }
                        return LOG_NOOP("SLOWFAIL3: {:x}", m_normalise_base(ea)), 0;
                    }
                    return LOG_NOOP("SLOWFAIL4: {:x}", m_normalise_base(ea)), 0;
                }
                return LOG_NOOP("SLOWFAIL5: {:x}", m_normalise_base(ea)), 0;
            }
            return LOG_NOOP("SLOWFAIL1: {:x}", m_normalise_base(ea)), 0;
        };

        // return [e for e in FindInSegments(pattern, '.text', None, predicate_checksummers)]

        std::vector<mem::pointer> results;

        // XXX HERE

        auto found = scan_all_with_iteratee(r, mem::pattern("48 8D 05 ?? ?? ?? ?? 48 89 45 ?? 48 8B 05 ?? ?? ?? ??"), iteratee);
        results.insert(results.end(), found.begin(), found.end());
        found = scan_all_with_iteratee(r, mem::pattern("48 8b 05 ?? ?? ?? ?? 48 89 45 ?? 48 8d 05 ?? ?? ?? ??"), iteratee6);
        results.insert(results.end(), found.begin(), found.end());
        found = scan_all_with_iteratee(r, mem::pattern("48 8b 05 ?? ?? ?? ?? 48 89 45 ?? 48 8d 05 ?? ?? ?? ??"), iteratee11);
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
    if (ctx.m_Unpack) {
        json json_written;
        uintptr_t dst = ctx.m_ExecuteFromRip;

#ifdef USE_BOOST

        // 335.2 mbs(0x140813A76).nop(5);            // skip making all segments writable
        // mbs(0x143B486E3).jmp(0x1439C66BF);  // skip tamper and size check
        // 350.2

        if (cmdl["fti"]) {
            // ("55 48 81 ec b0").add(0x58 - 9).rip(4).add(3).dword()

            if (1) {
                uintptr_t address = 0x143EE7BD6;
                unsigned char codeBuffer[15];
                uint32_t size = 15;
                std::deque<uintptr_t> pending{address};
                std::set<uintptr_t> visited;
                std::vector<FuncTailInsn> insns;

                while (!pending.empty()) {
                    address               = pending.front();
                    uintptr_t nextAddress = address;
                    pending.pop_front();
                    while (address >= ctx.m_ImageBase && address < ctx.m_ImageEnd && visited.insert(address).second) {
                        nextAddress = address;
                        uc_mem_read(uc, address, codeBuffer, size);
                        uint8_t* code   = codeBuffer;
                        size_t codeSize = size;
                        cs_insn insn;
                        memset(&insn, 0, sizeof(insn));

                        if (!cs_disasm_iter(ctx.m_cs, (const uint8_t**)&code, &codeSize, &nextAddress, &insn)) {
                            *outs << "failed to disassemble at " << std::hex << address << "\n";
                            break;
                        }

                        std::string op_string = insn.op_str;
                        *outs << std::hex << address << "\t\t" << std::dec << insn.mnemonic << "\t\t" << op_string << "\n";

                        FuncTailInsn fti;
                        fti.ea(address).size(size).code(std::string((char*)codeBuffer, size)).mnemonic(insn.mnemonic).operands(op_string);

                        insns.emplace_back(std::move(fti));

                        if (!strcmp(insn.mnemonic, "jmp")) {
                            address += insn.size + mem::pointer(code - 4).as<int32_t&>();
                            // if (insn.detail->x86.op_count) {
                            //    *outs << "jmp has no opcount\n";
                            //    break;
                            //}
                            // address += 5 + insn.detail->x86.operands[0].imm;
                        } else if (!strncmp(insn.mnemonic, "j", 1)) {
                            auto insn_size = insn.size;
                            if (insn_size > 4) {
                                pending.emplace_back(address + insn.size + mem::pointer(code - 4).as<int32_t&>());
                            } else {
                                pending.emplace_back(address + insn.size + mem::pointer(code - 1).as<int8_t&>());
                            }
                            *outs << "adding to pending list\n";
                            address += insn.size;
                        } else if (!strcmp(insn.mnemonic, "ret")) {
                            address = 0;
                        } else {
                            address += insn.size;
                        }
                    }
                }
            }
        }

#endif
        auto patch_anti_tamper = [&] {
            if (cmdl["patch-anti-tamper"]) {
                virtual_buffer_t imagebuf(ctx.m_ImageEnd - ctx.m_ImageBase);
                uc_mem_read(uc, ctx.m_ImageBase, imagebuf.GetBuffer(), ctx.m_ImageEnd - ctx.m_ImageBase);
                mem::region r(imagebuf.GetBuffer(), imagebuf.GetLength());

                auto normalise_base   = [&](uintptr_t ea) { return r.adjust_base_to(0x140000000, ea).as<uintptr_t>(); };
                auto m_normalise_base = [&](mbs& ea) { return r.adjust_base_to(0x140000000, ea.as<uintptr_t>()).as<uintptr_t>(); };
                // mem("55 48 81 ec b0").find("3b c2 0f 85", 128).add(4).rip(4).matches("c7 45", 2).dword()
                // m = mem(FindInSegments("48 89 6c 24 f8 48 8d 64 24 f8")).find("3b c2 0f 85", 128).add(4).rip(4).is_match("c7 45 64 01 00 00 00", 7)
                // m = [x for x in [mem(ea).add(4).rip(4).is_match("c7 45 .. 01 00 00 00", 7) for ea in FindInSegments("3b c2 0f 85")] if not x.in_error()]
                // clang-format off
                mbs ptr1;
                LOG("at1");
                scan_all_do(r, mem::pattern("3b c2 0f 85"), [&](auto ea) {
                    LOG("at1 match at {:#x}", normalise_base(ea));
                    mbs(ea)
                        .add(4)
                        .rip(4)
                        // C7 45 5C 01 00 00 00
                        .matches("c7 45 ?? 01 00 00 00")
						.and_then([&](auto m) { 
                             LOG("  found ptr1 at {:#x}", m_normalise_base(m));
                             ptr1 = m.add(7); 
                             if (m.add(3).as<uint32_t&>() == 1) {
                                 m.add(3).as<uint32_t&>() = 0; 
                                 LOG("  rewrote dword 1 to 0");
                             }
                             else
                                 LOG("  dword was not 1 as we expected, but was {}", m.add(3).as<uint32_t&>());
                         }).or_else([&]{
                             LOG("  wasn't ptr1 at {:x}", normalise_base(ea));
                         });
                });
                #if 1
                if (!ptr1) {
                    LOG("at2");
                    scan_all_do(r, mem::pattern("55 48 81 ec ?? 00 00 00"), [&](auto ea) {
                        LOG("at2 match at {:#x}", normalise_base(ea));
                        mbs(ea)
                            .find("3b c2 0f 85", 256)
                            .and_then([&](auto m) {
                                LOG("  found 3b c2 05 85");
                                m.add(4)
                                 .rip(4)
                                 .if_find("c7 45", 0, [&](auto m) { 
                                     LOG("  found ptr1 at {:#x}", m_normalise_base(m));
                                     ptr1 = m.add(7); 
                                     if (m.add(3).as<uint32_t&>() == 1) {
                                         m.add(3).as<uint32_t&>() = 0; 
                                         LOG("  rewrite dword 1 to 0");
                                     }
                                     else
                                         LOG("  dword was not 1 as we expected, but was {}", m.add(3).as<uint32_t&>());
                                 }).or_else([]{
                                     *outs << "couldn't find ptr1\n";
                                 });
                            })
                            .or_else([] {
                                *outs << "couldn't find start of unpack\n";
                            });
                    });
                }
                #endif

                // for x in FindInSegments("8b 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 3b c2 0f 85 ?? ?? ?? ?? e9"):
                //     mem(x).add(21).rip(4).matches('c7 45 .. 00 00 00 00').jmp(y)
                bool done = false;
                if (ptr1) {
                    LOG("at3");
                    scan_all_do(r,
                            mem::pattern("8b 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 3b c2 0f 85 ?? ?? ?? ?? e9"),
                            [&](uintptr_t ea) {
                                LOG("at3 match at {:#x}", normalise_base(ea));
                                *outs << "found5 " << std::hex << normalise_base(ea) << "\n";
                                mbs(ea).add(21).rip(4).matches("c7 45 ?? 00 00 00 00").and_then([&](auto m) {
                                    *outs << "found6 " << std::hex << m_normalise_base(m) << "\n";
                                    if (ptr1) {
                                        *outs << "replacing ptr1 with jmp\n";
                                        ptr1.as<uint8_t&>()           = 0xe9;
                                        ptr1.offset(1).as<int32_t&>() = (int)(m.as<uintptr_t>() - ptr1.as<uintptr_t>() - 5);
                                        //ptr1.write<uint8_t>(0xe9);
                                        //ptr1.offset(1).write<int32_t>((int)(m.as<uintptr_t>() - ptr1.as<uintptr_t>() - 5));
                                        done = true;
                                        // return ptr1.jmp(m_normalise_base(m)).as<uintptr_t>();
                                    }
                                });
                            });

                }
                if (!done) {
                    LOG("couldn't complete patches, exiting.");
                    uc_close(uc);
                    cs_close(&ctx.m_cs);
                    ctx.thisProc.mmap().UnmapAllModules();
                    timer.ShowElapsed();
                    return 1;
                }
                LOG("patches complete");

                // clang-format on
                auto iteratee = [&](mem::pointer ea) -> uintptr_t {
                    LOG_ADDR_N(ea);
                    auto ptr = ea.add(0x58 - 9).rip(4);
                    LOG_ADDR_N(ptr);
                    auto pdw = ptr.add(3);
                    LOG_ADDR_N(pdw);

                    if (r.contains(pdw.as<uintptr_t>())) {
                        auto& dw = pdw.as<int32_t&>();
                        *outs << "dw: " << dw << std::endl;
                        if (dw == 1) {
                            dw = 0;
                            *outs << "changed to " << dw << std::endl;
                        }
                    } else
                        *outs << "r didn't contain pdw";

                    auto pjz = ptr.add(0x26);
                    auto& w  = pjz.as<uint16_t&>();
                    *outs << "jnz opcode: " << std::hex << w << std::endl;
                    if (w == 0x840f) {
                        w = 0xe990;
                        *outs << "changed to " << w << std::endl;
                    }

                    auto ptr2 = ptr.add(0x26).add(2).rip(4);
                    LOG_ADDR_N(ptr2);
                    if (r.contains((ptr2.as<uintptr_t>()))) {
                        if (ptr2.add(0).as<uint8_t&>() == 0x8b) {
                            auto& a = ptr2.add(2).as<uint32_t&>();
                            auto& b = ptr2.add(8).as<uint32_t&>();
                            *outs << "hash: " << std::hex << a << " "
                                  << "correct_hash: " << b << std::endl;
                            a = b + 6;
                            *outs << "changed a to " << a << std::dec << std::endl;
                        } else
                            *outs << "twin peaks didn't match" << std::endl;
                    }
                    return 0;
                };
                // mem::pattern p("55 48 81 ec b0");
                //         if (auto found = mem::scan(p, r)) {
                //             iteratee(found);
                //         }
                uc_mem_write(uc, ctx.m_ImageBase, imagebuf.GetBuffer(), ctx.m_ImageEnd - ctx.m_ImageBase);
                return 0;
            }
            return 0;
        };
        // patch_anti_tamper();

        // 335.2
        // mbs(0x14384BE32).jmp(0x143612F8C);  // skip tamper and segment check

        // mbs(0x140d8d394).nop(5);            // skip making all segments writable
        // mbs(0x143bbdb2f).jmp(0x140D03816);  // skip executable tamper check
        // mbs(0x141894D99).jmp(0x143A99FEE);  // skip segment size check
        // mbs(0x1417db93c).jmp(0x1417ed648); // skip initial decrypt
        // mbs(0x144874514).write_pattern("c3");

        // for d, s in zip(dst, src) : ida_bytes.patch_bytes(d[0], ida_bytes.get_bytes(s[0], s[1]))
        ResetRegisters(uc, ctx);

        *outs << "Function: " << ctx.filename << "\n";
        if (!ctx.m_SaveReadRanges.empty()) {
            ctx.m_ReadBitmap.resize(ctx.m_ImageEnd - ctx.m_ImageBase);
        }
        if (!ctx.m_SaveWrittenRanges.empty()) {
            ctx.m_WrittenBitmap.resize(ctx.m_ImageEnd - ctx.m_ImageBase);
        }
        if (ctx.m_Unpack) {
            ctx.m_WrittenBitmap.resize(ctx.m_ImageEnd - ctx.m_ImageBase);
        }
        while (1) {
            {
                virtual_buffer_t imagebuf(128);
                uc_mem_read(uc, ctx.m_ImageBase, imagebuf.GetBuffer(), 128);
                HexDump::dumpMemory(*outs, (char*)imagebuf.GetBuffer() + 0x0, 128);
                if (*(DWORD*)imagebuf.GetBuffer() == 0) {
                    break;
                }
            }

            if (ctx.m_Obfu) {
                ctx.m_DisassembleForce = true;
                err                    = uc_emu_start(uc, ctx.m_ExecuteFromRip, ctx.m_ImageEnd, 0, 1000);
                LOG("-------------------- restart ----------------------");
                if (1 == patch_anti_tamper()) {
                    TerminateProcess(GetCurrentProcess(), 2);
                }
                ResetRegisters(uc, ctx);
                visited.clear();
                insn_count.clear();
                call_targets.clear();
                ctx.m_Calls.clear();
                ctx.m_SkipSecondCall = cmdl["skip-second-call"];
                ctx.m_SkipFourthCall = cmdl["skip-4th-call"];
            }

            ctx.m_DisassembleForce = false;
            err                    = uc_emu_start(uc, ctx.m_ExecuteFromRip, ctx.m_ImageEnd, 0, 0);

            if (ctx.m_LastException != STATUS_SUCCESS) {
                auto except         = ctx.m_LastException;
                ctx.m_LastException = STATUS_SUCCESS;
                ctx.RtlRaiseStatus(except);
            } else {
                break;
            }

            *outs << "Looping...\n";
            break;
        }
        uintptr_t fn_address = 0x140CBC8B1;
        SaveResult(uc, fn_address, ctx, &json_written);
    } else {
        json json_written;
        if (!ctx.m_SaveReadRanges.empty()) {
            ctx.m_ReadBitmap.resize(ctx.m_ImageEnd - ctx.m_ImageBase);
        }
        if (!ctx.m_SaveWrittenRanges.empty()) {
            ctx.m_WrittenBitmap.resize(ctx.m_ImageEnd - ctx.m_ImageBase);
        }
        if (!ctx.m_SaveWritten.empty()) {
            tryAndReadJson((fs::path(ctx.m_SaveWritten) / "files.json").string(), json_written, {});
        }
        for (const auto& tpl : fns) {
            auto ori_sandbox                 = ctx.m_Sandbox;
            ctx.m_Sandbox                    = false;
            ctx.filename                     = std::get<0>(tpl);
            uintptr_t start_address          = std::get<1>(tpl);
            uintptr_t base_address           = ctx.m_ImageEnd;
            const uintptr_t prologue_address = base_address + 0x100;

            auto prologue_size = WritePrologue(uc, prologue_address, start_address, 0);

            ResetRegisters(uc, ctx);

            *outs << "Function: " << ctx.filename << "\n";
            while (1) {
                err = uc_emu_start(uc, /*ctx.m_ExecuteFromRip*/ prologue_address, prologue_address + prologue_size - 1 /* ctx.m_ImageEnd */, 0, 0);

                if (ctx.m_LastException != STATUS_SUCCESS) {
                    auto except         = ctx.m_LastException;
                    ctx.m_LastException = STATUS_SUCCESS;
                    ctx.RtlRaiseStatus(except);
                } else {
                    break;
                }
            }
            uintptr_t fn_address = std::get<1>(tpl);
            SaveResult(uc, fn_address, ctx, &json_written);
            ctx.m_Sandbox = ori_sandbox;
        }
        for (const auto& tpl : balance_fns) {
            ctx.filename                     = std::get<0>(tpl);
            uintptr_t start_address          = std::get<1>(tpl);
            uintptr_t base_address           = ctx.m_ImageEnd;
            const uintptr_t prologue_address = base_address + 0x100;

            auto prologue_size = WritePrologue(uc, prologue_address, start_address, 1);

            ResetRegisters(uc, ctx);
            ctx.m_RewriteRsp     = true;
            ctx.m_RewriteRspDone = false;
            ctx.m_BalanceEntry   = 0;

            *outs << "Function: " << ctx.filename << "\n";
            while (1) {
                err = uc_emu_start(uc, /*ctx.m_ExecuteFromRip*/ prologue_address, prologue_address + prologue_size - 1 /* ctx.m_ImageEnd */, 0, 0);

                if (ctx.m_LastException != STATUS_SUCCESS) {
                    auto except         = ctx.m_LastException;
                    ctx.m_LastException = STATUS_SUCCESS;
                    ctx.RtlRaiseStatus(except);
                } else {
                    break;
                }
                break;
            }
            uintptr_t fn_address = std::get<1>(tpl);
            if (ctx.m_BalanceEntry) fn_address = ctx.m_BalanceEntry;
            SaveResult(uc, fn_address, ctx, &json_written);
        }
        if (!ctx.m_SaveWritten.empty()) {
            tryAndWriteJson((fs::path(ctx.m_SaveWritten) / "files.json").string(), json_written);
        }
    }

    uc_hook_del(uc, trace);
    uc_hook_del(uc, trace2);
    uc_hook_del(uc, trace3);

    uint64_t result_rax = 0;
    uc_reg_read(uc, UC_X86_REG_RAX, &result_rax);

    if (ctx.m_Dump) {
        ImageDump(ctx, uc, filename);
    }

    ShowRegisters(uc);

    *outs << "uc_emu_start return: " << std::dec << err << std::endl;
    *outs << "entrypoint return: " << std::hex << result_rax << std::endl;
    *outs << "last rip: " << std::hex << ctx.m_LastRip << std::endl;

    outs->flush();
    timer.ShowElapsed();

    // _exit() abort() std::terminate()
    TerminateProcess(GetCurrentProcess(), 2);

    uc_close(uc);
    cs_close(&ctx.m_cs);
    ctx.thisProc.mmap().UnmapAllModules();

    std::stringstream rip_region, realentry_region;
    if (ctx.FindAddressInRegion(ctx.m_LastRip, rip_region)) *outs << " (" << rip_region.str() << ")\n";

    if (ctx.m_ImageRealEntry) {
        if (ctx.FindAddressInRegion(ctx.m_ImageRealEntry, realentry_region)) *outs << "real entrypoint: " << realentry_region.str() << "\n";
    }

    *outs << "flushing...\n";
    // std::string k;
    // std::cin >> k;
    *outs << "forcing exit now" << std::endl;
    outs->flush();
    // _exit() abort() std::terminate()
    TerminateProcess(GetCurrentProcess(), 2);

    return 0;
}

template <typename... Args>
std::string lnva(const char* format, const Args&... args) {
    std::string text;
    try {
        0 && printf(format, args...);
        *outs << fmt::sprintf(format, args...) << std::endl;
    } catch (fmt::format_error& e) {
        LOG_DEBUG(__FUNCTION__ "::format(\"%s\"): %s", format, e.what());
    }
    return text;
};

void mem_parser(PeEmulation& ctx, const std::string& _line, uintptr_t& _RESULT, argh::parser& cmdl) {
    // to be written-ish
    std::deque<mem::pointer> stack;
    // auto normalise_base   = [&](uintptr_t n) -> uintptr_t { return n; };
    auto safe_dereference = [&](uintptr_t) -> bool { return true; };
    auto push             = [&](mem::pointer p) -> void { stack.emplace_back(p); };
    auto pop              = [&]() -> mem::pointer {
        auto r = stack.back();
        stack.pop_back();
        return r;
    };
    // end to be written

    auto parser = pogo::WhitespaceTokeniser("dummy line");
    try {
        parser = pogo::WhitespaceTokeniser(_line);
    } catch (std::runtime_error& ex) {
        LOG("Exception parsing string: {}", ex.what());
        return;
    }

    if (parser.empty()) return;
    if (parser.size() == 0) {
        lnva(R"(
[ alloc <size> | push | pop | from_file <filename> | write <size_type> <value> | push_param <param> |
  pop_write <size_type> | loop <times> [\\\"<commands>\\\"|!param-name|<filename] | deref | [rip|add|sub|offset] <offset> | 
  <filename | [call|jmp] <0x14xxxxxxx> | as <size_type> ]

size_type ::= [u|]int[[8|16|32|64|ptr]_t]
)");
        return;
    }

    virtual_buffer_t imagebuf(ctx.m_ImageEnd - ctx.m_ImageBase);
    uc_mem_read(ctx.m_uc, ctx.m_ImageBase, imagebuf.GetBuffer(), ctx.m_ImageEnd - ctx.m_ImageBase);
    mem::region r(imagebuf.GetBuffer(), imagebuf.GetLength());

    auto normalise_base     = [&](uintptr_t ea) { return r.adjust_base_to(0x140000000, ea).as<uintptr_t>(); };
    auto unnormalise_base   = [&](uintptr_t ea) { return r.adjust_base_from(0x140000000, ea).as<uintptr_t>(); };
    auto m_normalise_base   = [&](mem::pointer& ea) { return r.adjust_base_to(0x140000000, ea.as<uintptr_t>()).as<uintptr_t>(); };
    auto m_unnormalise_base = [&](mem::pointer& ea) { return r.adjust_base_from(0x140000000, ea.as<uintptr_t>()).as<uintptr_t>(); };

    bool isPattern = false;

    mem::pointer ptr(unnormalise_base(_RESULT));

    for (auto cmd = parser.current; !parser.eof(); cmd = parser.next) {
        // LOG("mem::ptr {:#x}", m_normalise_base(ptr));
        if (cmd.empty()) break;
        // LOG("cmd: {}", cmd);
        if (cmd == "alloc") {
            if (!parser.empty()) {
                if (auto _size = asQword(parser.next, 10)) {
                    uintptr_t alloc = ctx.HeapAlloc((ULONG)*_size);
                    ptr             = mem::pointer(alloc);
                }
            }
        } else if (cmd == "from_file") {
            if (!parser.empty()) {
                auto _filename = parser.next;
                if (!file_exists(_filename)) {
                    LOG("File does not exist: '{}'", _filename);
                    return;
                }
                auto _contents = file_get_contents_bin(_filename);
                ptr.put_bytes(_contents);
                ptr += _contents.size();
            }
        } else if (cmd == "push") {
            push(ptr);
        } else if (cmd == "pop") {
            ptr = pop();
        } else if (cmd == "goto") {
            auto target = parser.next;
            if (auto _target = asQword(target)) {
                ptr = mem::pointer(unnormalise_base(*_target));
            } else {
                lnva("Couldn't parse address \"%s\"", target.c_str());
            }
        } else if (cmd == "jmp") {
            if (auto func = asQword(parser.next)) {
                ptr.as<uint8_t&>()           = 0xe9;
                ptr.offset(1).as<int32_t&>() = ((int)(unnormalise_base(*func) - m_normalise_base(ptr) - 5));
                ptr += 5;
            }
        } else if (cmd == "call") {
            if (auto func = asQword(parser.next)) {
                ptr.as<uint8_t&>()           = 0xe8;
                ptr.offset(1).as<int32_t&>() = ((int)(unnormalise_base(*func) - m_normalise_base(ptr) - 5));
                ptr += 5;
            }
        } else if (cmd == "as") {
            if (!parser.empty()) {
                auto _type = parser.next;

                // allow for [u]int
                if (pystring::endswith(_type, "int")) _type += "32_t";

                vector_string matches;
                // [u] int (64|ptr) _t
                if (!preg_match(R"((u?)int((?:\d+|ptr)+)_t)", _type, &matches)) {
                    lnva("Invalid type for \"as\" - \"%s\"", _type.c_str());
                    return;
                }
                auto _unsigned    = matches[1] == "u";
                int_fast8_t _bits = matches[2] == "ptr" ? 64 : (int_fast8_t)strtoul(matches[2].c_str(), nullptr, 10);

                if (_unsigned)
                    _RESULT = ptr.as<uint64_t&>() & ((1 << (64 - _bits)) - 1);
                else
                    _RESULT = ptr.as<int64_t&>() << (64 - _bits) >> (64 - _bits);
                lnva("%-8s %-8s 0x%llx", cmd.c_str(), _type.c_str(), _RESULT);
                // return;
            }
        } else if (cmd == "pop_write") {
            if (!parser.empty()) {
                auto _type  = parser.next;
                auto _value = pop().as<uintptr_t>();

                if (!_value) {
                    LOG("invalid value");
                    return;
                }

                // allow for [u]int
                if (pystring::endswith(_type, "int")) _type += "32_t";

                vector_string matches;
                // [u] int (64|ptr) _t
                if (!preg_match(R"((u?)int((?:\d+|ptr)+)_t)", _type, &matches)) {
                    lnva("Invalid type for \"as\" - \"%s\"", _type.c_str());
                    return;
                }
                auto _unsigned = matches[1] == "u";
                int_fast8_t _bits =

                    matches[2] == "ptr" ? 64 : (int_fast8_t)strtoul(matches[2].c_str(), nullptr, 10);

                if (_unsigned) {
                    // clang-format off
					ptr.as<uint64_t&>() = (ptr.as<uint64_t&>() & ~((1 << (64 - _bits)) - 1)) | 
													   (_value &  ((1 << (64 - _bits)) - 1));
                    // clang-format on
                    ptr += _bits / 8;
                } else
                    LOG("never really figured out how to do an signed write");
                lnva("%-8s %-8s 0x%llx", cmd.c_str(), _type.c_str(), _RESULT);
            }
        } else if (cmd == "write") {
            if (!parser.empty()) {
                auto _type  = parser.next;
                auto _value = asQword(parser.next);

                if (!_value) {
                    LOG("invalid value");
                    return;
                }

                // allow for [u]int
                if (pystring::endswith(_type, "int")) _type += "32_t";

                vector_string matches;
                // [u] int (64|ptr) _t
                if (!preg_match(R"((u?)int((?:\d+|ptr)+)_t)", _type, &matches)) {
                    lnva("Invalid type for \"as\" - \"%s\"", _type.c_str());
                    return;
                }
                auto _unsigned    = matches[1] == "u";
                int_fast8_t _bits = matches[2] == "ptr" ? 64 : (int_fast8_t)strtoul(matches[2].c_str(), nullptr, 10);

                if (_unsigned) {
                    // LOG("reading current value from {:#x} ({:#x})", ptr.as<uint64_t>(), m_normalise_base(ptr));
                    auto current_value_64 = ptr.as<uint64_t&>();
                    // LOG("current_value_64: {:#x}", current_value_64);
                    auto write    = *_value;
                    auto bit_mask = _bits == 64 ? -1 : (1 << (64 - _bits)) - 1;
                    // LOG("writing         : {:#x} & {:#x}", write, bit_mask);
                    auto new_value_64 = (current_value_64 & ~bit_mask) | (write & bit_mask);
                    // LOG("new_value_64    : {:#x}", new_value_64);
                    ptr.as<uint64_t&>() = new_value_64;

                    // ptr.as<uint64_t&>() = (ptr.as<uint64_t&>() & ~((1 << (64 - _bits)) - 1)) |
                    //	  							    (*_value &  ((1 << (64 - _bits)) - 1));
                    ptr += _bits / 8;
                    lnva("%-8s %-8s 0x%llx", cmd.c_str(), _type.c_str(), m_normalise_base(ptr));
                } else
                    LOG("never really figured out how to do an signed write");
            }
        } else if (cmd == "offset" || cmd == "sub" || cmd == "add" || cmd == "rip") {
            if (!parser.empty()) {
                if (auto optionalOffset = parseIntOpt(parser.next, 0)) {
                    auto offset = *optionalOffset;
                    if (cmd == "add" || cmd == "offset") {
                        ptr = ptr.add(offset);
                    } else if (cmd == "sub") {
                        ptr = ptr.sub(offset);
                    } else if (cmd == "rip") {
                        ptr = ptr.rip(offset);
                    }
                    lnva("%-8s %-8lli 0x%llx", cmd.c_str(), offset, m_normalise_base(ptr));
                }
            }
        } else if (cmd[0] == '<') {
            std::string subject = pystring::rstrip(file_get_contents(cmd.substr(1)));
            LOG("adding file {} to queue: {}", cmd.substr(1), subject);
            auto tmp_parser = pogo::WhitespaceTokeniser(subject);
            parser.insert(tmp_parser.slice(0));
        } else if (cmd == "loop") {
            if (auto _times = asQword(parser.next)) {
                std::string subject = parser.next;
                if (subject[0] == '!') {
                    subject = cmdl(subject.substr(1)).str();
                }
                if (subject[0] == '<') {
                    subject = pystring::rstrip(file_get_contents(subject.substr(1)));
                }
                // trim off surrounding 's
                // auto tmp_parser = pogo::WhitespaceTokeniser(subject.substr(1, subject.size() - 2));
                LOG("adding to queue {} times: {}", *_times, subject);
                auto tmp_parser = pogo::WhitespaceTokeniser(subject);
                _::timesSimple(*_times, [&] { parser.insert(tmp_parser.slice(0)); });
            }
        } else if (cmd == "push_param") {
            std::string subject = parser.next;
            uintptr_t target;
            cmdl(subject) >> target;
            push(target);
        } else if (cmd == "deref") {
            if (!safe_dereference(ptr.as<uintptr_t>())) {
                lnva("Exception dereferencing 0x%llu", ptr.as<uintptr_t>());
                return;
            }
            ptr = ptr.deref();
            lnva("%-8s          0x%llx", cmd.c_str(), ptr.as<uintptr_t>());
        } else if (cmd == "store") {
            _RESULT = ptr.as<uintptr_t>();
            lnva("%-8s          0x%llx", cmd.c_str(), ptr.as<uintptr_t>());
        }
    }
    // address = normalise_base(r.as<uintptr_t>());
}

/*
https://github.com/sfinktah/unicorn_pe  -- there's a built copy in x64/releases, and to build it yourself you will need `vcpkg install boost:x64-windows-static fmt:x64-windows-static nlohmann-json:x64-windows-static` or something to that effect.  The other things are included (capstone, blackbone, unicorn).

To extract blobs from a dumped binary:
`/path/to/unicorn_pe.exe dumped.exe --decrypt --save-written=test1` where test1 is a folder that exists (or it will be made for you) underneath where-ever you keep you .i64 file

To extract a non-dumped binary
```
/path/to/unicorn_pe.exe retail.exe --unpack
```

`--unpack` mode can also take a `save-written=<unpack_folder>` argument to create individual blobs.

There are also some optional arguments that I haven't tested for a while, e.g.

`--start 0x14000100 [--start 0x14000234...]` to manually set the addresses to scan (you'd normally be using those with `--disasm`
`--patch "0x14000100:66 90"` to apply patches before running


Requirements (no longer needed):

git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
bootstrap-vcpkg.bat
vcpkg install boost:x64-windows-static fmt:x64-windows-static nlohmann-json:x64-windows-static pystring:x64-windows-static ms-gsl:x64-windows-static



*/
