#include <windows.h>
#include <chrono>
#include <functional>
#include <iostream>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <pystring/pystring.h>
#include <nlohmann/json.hpp>
#include <fmt/format.h>
#include "Filesystem.hpp"
#include "FileUtils.h"
#include "Logger.hpp"
#include "MegaFunc.h"
#include "joaat.h"
#include "maclog.h"
#include "sniffing/nowide/convert.hpp"
#include "util.hpp"
#include "lodash/001_each.h"

namespace fs = std::filesystem;
using namespace nlohmann;

CUSTOM_EXCEPTION(megafunc_error);

MegaFunc* megafunc = nullptr;

void MegaFunc::CheckIndex(const std::string& filename) {
    m_filename = filename;
    //std::lock_guard<std::mutex> guard(_loading);
    std::string fn;
    if (tryAndFindFile(replace_extension(filename, ".json"), fn)) {
        filename_source = replace_extension(fn, "json");
        filename_full   = replace_extension(fn, "dat");

        if (IsNewer(filename_source, filename_full)) {
            LOG_FUNC("Building func data...");
            {
                std::ifstream infile((filename_source));
                json j;
                infile >> j;
                lineHandlerFull(j);
            }
        }
        ReadIndex(filename_full);
    } else if (tryAndFindFile(replace_extension(filename, ".dat"), fn)) {
        LOG_FUNC("Depending on .dat file as .json is missing...");
        filename_source.clear();
        filename_full = replace_extension(fn, "dat");
        ReadIndex(filename_full);
    } else {
        throw megafunc_error("file not found");
    }
}

bool MegaFunc::IsRefreshRequired() {
    //std::lock_guard<std::mutex> guard(_loading);
    if (IsNewer(filename_source, filename_full)) return true;
    return false;
}

MegaFunc::MegaFunc(const std::string& filename) /*: m_cache(512) */
{ CheckIndex(filename); }

std::string MegaFunc::ReadString(const std::string& filename, uint32_t offset) {
    std::ifstream file(filename);
    std::string line;
    file.seekg(offset);
    file >> line;
    return line;
}

uint64_t MegaFunc::Lookup(cref_string function) {
    if (m_subs.count(function))
        return m_subs.at(function);
    return 0;
}

bool MegaFunc::Contains(uint64_t addr) {
    uint32_t addr32 = addr & 0x3fffffff;
    addr32 += 1;

    struct Comp {
        bool operator()(const mega_func_t& s, uint32_t i) const { return s.start < i; }
        bool operator()(uint32_t i, const mega_func_t& s) const { return i < s.start; }
    };

    addr = addr32;
    addr <<= 32;
    auto i = std::lower_bound(hashArray.begin(), hashArray.end(), addr);

    if (i != hashArray.end() && i != hashArray.begin())
        if (!filename_full.empty()) {
            --i;
            auto str = ReadString(filename_full, *i & 0xffffffff);
            if (strcmp(str.c_str(), "unknown")) return true;
        }

    return false;
}


std::string MegaFunc::Lookup(uint64_t addr) {
    uint32_t addr32 = addr & 0x3fffffff;
	// get past stupid bug
	addr32 += 1;

    //return m_cache.getOrCall(addr, [&](uint32_t _) {
        //std::lock_guard<std::mutex> guard(_loading);

        struct Comp {
            bool operator()(const mega_func_t& s, uint32_t i) const { return s.start < i; }
            bool operator()(uint32_t i, const mega_func_t& s) const { return i < s.start; }
        };

        addr = addr32;
        addr <<= 32;
        auto i = std::lower_bound(hashArray.begin(), hashArray.end(), addr);

        if (i != hashArray.end() && i != hashArray.begin())
            if (!filename_full.empty()) {
                --i;
                auto str = ReadString(filename_full, *i & 0xffffffff);
                if (strcmp(str.c_str(), "unknown")) return fmt::format("0x14{:07x} {:32}", addr32-1, fmt::format("({})", str.c_str()));
            }

        return fmt::format("0x14{:07x} {:32}", addr32-1, "");
    //});
}

void MegaFunc::ReadIndex(const std::string& filename) {
    std::ifstream file(filename, std::ofstream::binary);
    mega_func_t header = {};

    if (!file.read(reinterpret_cast<char*>(&header), sizeof header)) {
        LOG_ERROR("{}: {}", __FUNCTION__, "Couldn't read file");
        return;
    }

    int filetype;
    switch (header.magic) {
        // case JOAAT("MEGAFUNCS_INDEX"): filetype = 1; break;
        case JOAAT("MEGAFUNCS"): filetype = 3; break;
        default: throw megafunc_error("invalid magic");
    }

    std::vector<uint64_t> hashes;
    if (filetype & 1) {
        if (fs::file_size(filename) - sizeof header < header.count) {
            LOG_WARN("{}: {}", __FUNCTION__, "uint32_t index is truncated");
        }
        LOG_FUNC("reserving space for {} records", header.count);
        hashes.resize(header.count);
        auto count = header.count;
        uint64_t record;
        file.read((char*)hashes.data(), sizeof record * header.count);
        // hashes.emplace_back(record);

        // https://stackoverflow.com/questions/4761529/efficient-way-of-reading-a-file-into-an-stdvectorchar/4761779#4761779
        // fileContents.assign(std::istreambuf_iterator<char>(testFile),
        //    std::istreambuf_iterator<char>());

        //HexDump::dumpMemoryCallback(reinterpret_cast<char*>(hashes.data()), 128,
        //                            [&](std::string line, size_t offset) { LOG_FUNC("%-18s: {}", "HexDump", line.c_str()); });
        // I think it would make much more sense to read everything straight into hashArray, unless there is some
        // sort going on between.
        int indexCount = 0;
        hashArray.reserve(header.count);
        for (const auto& mh : hashes) {
            hashArray.emplace_back(mh);
            // hashIndex.insert_or_assign(mh.start, mh.offset);
            // if (mh.start == JOAAT("CVEHICLE")) {
            //    LOG_FUNC("cvehicle");
            //    LOG_FUNC("at: {}", hashIndex.at(JOAAT("CVEHICLE")));
            //}
            indexCount++;
        }
        std::sort(hashArray.begin(), hashArray.end());
        LOG_DEBUG("{}: read {} index records", __FUNCTION__, indexCount);
        // try {
        //    uint32_t o = hashIndex.at(JOAAT("CVEHICLE"));
        //    LOG_DEBUG("{}: testing index joaat(\"CVEHICLE\"): {} == {}", __FUNCTION__, JOAAT("CVEHICLE"), o);
        //    if (!(filetype & 2)) {
        //        auto s = ReadString(filename_source, o);
        //        LOG_DEBUG("{}: looking up value: {}", __FUNCTION__, C(s));
        //    }
        //} catch (std::out_of_range& e) {
        //    UNREFERENCED_PARAMETER(e);

        //    LOG_DEBUG("{}: error checking joaat(\"CVEHICLE\")", __FUNCTION__);
        //}

        // if (filetype & 2) {
        //    try {
        //        uint32_t o = hashIndex.at(JOAAT("CVEHICLE"));
        //        LOG_DEBUG("{}: testing index joaat(\"CVEHICLE\"): {} == {}", __FUNCTION__, JOAAT("CVEHICLE"), o);
        //        auto s = ReadString(filename_full, o);
        //        LOG_DEBUG("{}: looking up value: {}", __FUNCTION__, C(s));
        //    } catch (std::out_of_range& e) {
        //        UNREFERENCED_PARAMETER(e);
        //        LOG_DEBUG("{}: error checking joaat(\"CVEHICLE\")", __FUNCTION__);
        //    }
        //}
    }
}

void MegaFunc::lineHandlerFull(json& j) {
    std::map<uint32_t, std::string> megaFuncFull;
    for (auto& [name, value] : j.items()) {
        if (value.is_array() && !value.empty() /* && value[0].is_array() && value[0].size() == 2*/) {
            for (auto&& [i, pair] : _::enumerate(value)) {
                if (pair.is_array() && pair.size() == 2) {
                    uint32_t start = pair[0];
                    uint32_t end   = pair[1];

                    if (i == 0) {
                        if (!StringStartsWith(name, "sub_")) {
                            m_subs[name] = start;
                        }
                    }

                    auto [it1, happy1] = megaFuncFull.emplace(start, name);
                    auto [it2, happy2] = megaFuncFull.emplace(end, "unknown");
                    if (!happy1) {
                        auto existing = it1->second;
                        if (name != existing) {
                            //LOG_TRACE(__FUNCTION__ ": '0x14{:07x}' existing key '{}' clashed with '{}', overwriting.", start, existing.c_str(), name.c_str());
                            megaFuncFull[start] = name;
                        }
                    }
                    if (!happy2) {
                        auto existing = it1->second;
                        //LOG_TRACE(__FUNCTION__ ": '0x14{:07x}' existing key '{}' clashed with '{}', too bad", end, existing.c_str(), "unknown");
                    }
                }
            }
        }
    }

    LOG_DEBUG("write full start");
    size_t count = megaFuncFull.size();
    mega_func_t header{JOAAT("MEGAFUNCS"), {static_cast<uint32_t>(count)}};

    std::ofstream file(filename_full, std::ofstream::binary);
    std::ofstream::pos_type pIndex = 0;
    std::ofstream::pos_type pData  = sizeof header * count;

    file.write(reinterpret_cast<const char*>(&header), sizeof header);
    pIndex += sizeof header;

    for (const auto& [first, second] : megaFuncFull) {
        mega_func_t record{static_cast<uint32_t>(pData), {first}};
        file.write(reinterpret_cast<const char*>(&record), sizeof record);
        pIndex += sizeof record;
        file.seekp(pData, std::ofstream::beg);

        size_t string_len = second.length() + 1;
        file.write(second.c_str(), string_len);
        pData += string_len;
        file.seekp(pIndex);
    }
    LOG_DEBUG("write full end");
    return;
}

// 34M -rwxrw-r--+ 1 sfink sfink 34M Sep 24 04:13 megafunces.txt
// 5.M -rwxrw-r--+ 1 sfink sfink 5.2M Sep 24 19:11 megafunces.txt.gz
//
// 13M -rwxrwxr-x+ 1 sfink sfink 13M Sep 24 04:14 megafunces.idx
// 11M -rwxrwxr-x+ 1 sfink sfink  11M Sep 24 19:11 megafunces.idx.gz
//
// 46M -rwxrwxr-x+ 1 sfink sfink 46M Sep 24 04:14 megafunces.dat
// 21M -rwxrwxr-x+ 1 sfink sfink  21M Sep 24 19:11 megafunces.dat.gz
