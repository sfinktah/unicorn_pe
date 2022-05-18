// #include "stdafx.h"
// #include "Utility/Memory.h"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#undef PSAPI_VERSION
#define PSAPI_VERSION 1
#include <psapi.h>
#include "membricksafe.hpp"

using namespace membricksafe;

std::forward_list<PATCH_ENTRY> membricksafe::g_patches;
MODULEINFO GetMainModuleInfo()
{
    MODULEINFO mi;
    GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &mi, sizeof(mi));
    return mi;
}

MODULEINFO g_MainModuleInfo = GetMainModuleInfo();

memBrickSafe membricksafe::SafeScan(const char* pattern, const char* identifier)
{
	memBrickSafe mb = memBrickSafe::scan(g_MainModuleInfo, pattern, identifier);
	if (!mb) {
		//LOG_WARN("Mein Pudel hat ein schlechtes Muster (%s)", identifier);
        MessageBoxA(nullptr, identifier, /* MOD_NAME " " */ "MBFAIL", MB_OK);
		return memBrickSafe();
	}
	return mb;
}

/* End of yelling */
std::unordered_map<std::string, PATCH_ENTRY&> PATCH_ENTRY::patchlist;
