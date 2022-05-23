#pragma once
#include <nlohmann/json_fwd.hpp>
using namespace nlohmann;

class MegaFunc {
public:
    void CheckIndex(const std::string& filename);
    bool IsRefreshRequired();
    MegaFunc(const std::string& filename);
    ~MegaFunc() = default;

    MegaFunc(const MegaFunc&) = delete;
    MegaFunc(MegaFunc&&)      = delete;

    MegaFunc& operator=(const MegaFunc&) = delete;
    MegaFunc& operator=(MegaFunc&&) = delete;

    struct mega_func_t {
        union {
            uint32_t offset;
            uint32_t magic;
        };
        union {
            uint32_t start;
            uint32_t count;
        };
        bool operator<(const mega_func_t& s) const { return start < s.start; }
    };

    std::vector<uint64_t> hashArray;
    //std::map<uint32_t, uint32_t> hashIndex;
    clock_t m_lastIndexCheck = {};
    // if this class is to be instantiated multiple times, these members will have to be made non-static
    std::string m_filename;
    std::string filename_source;
    std::string filename_full;

    // Reading
    void ReadIndex(const std::string& filename);
    std::string ReadString(const std::string& filename, uint32_t offset);
    std::string Lookup(uint64_t addr);
    uintptr_t Lookup(const std::string& function);
    bool Contains(uint64_t addr);

    // Writing
    void lineHandlerFull(json& j);

    // Locking
    std::mutex _loading;

    // Full reverse index of named functions
    std::unordered_map<std::string, uint32_t> m_subs;

    //private:
    //    LRUCache<uint32_t, std::string> m_cache;
};

extern MegaFunc* megafunc;
