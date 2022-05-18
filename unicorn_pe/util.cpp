#include <string>
#include <vector>
#include <chrono>
#include <sstream>
#include <functional>
#include <thread>
#include <optional>
#include <windows.h>
#include <utility>
#include "util.hpp"
#include "Filesystem.hpp"
#include "Logger.hpp"
#include "maclog.h"
#include "sniffing/nowide/convert.hpp"
#include <pystring/pystring.h>
#include "joaat.h"

namespace os = pystring::os;

using namespace nowide;

#include <regex>
using namespace std::literals::chrono_literals;

#ifdef PROCESSENTRY32
#undef PROCESSENTRY32
#undef Process32First
#undef Process32Next
//#define PROCESSENTRY32 PROCESSENTRY32
//#define Process32First Process32First
//#define Process32Next Process32Next
#endif

fs::path GetModulePath(std::string name) {
    auto module = GetModuleHandleA(name.c_str());
    char fileName[MAX_PATH];
    GetModuleFileNameA(module, fileName, MAX_PATH);

    return fs::path(fileName).parent_path();
}
std::string GetModuleName(const HMODULE module) {
    char fileName[MAX_PATH];
    GetModuleFileNameA(module, fileName, MAX_PATH);

    std::string fullPath = fileName;

    size_t lastIndex = fullPath.find_last_of("\\") + 1;
    return fullPath.substr(lastIndex, fullPath.length() - lastIndex);
}

// http://stackoverflow.com/a/236803/912236
void split(const std::string& s, char delim, std::vector<std::string>& elems) {
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
}

const char* escape_cchar(int ch) {
    static char buf[8];
    int c = ch;
    switch (c) {
        case '\a':
            return "\\a";  // 0x07
        case '\b':
            return "\\b";  // 0x08
        case '\t':
            return "\\t";  // 0x09
        case '\n':
            return "\\n";  // 0x0a
        case '\v':
            return "\\v";  // 0x0b
        case '\f':
            return "\\f";  // 0x0c
        case '\r':
            return "\\r";  // 0x0d
        case '\\':
            return "\\\\";
        case '\"':
            return "\\\"";
        // case '\'': return "\\'";
        // case '\?': return "\\\?";
        // case 0: return "\\0";
        default:
            if (c >= 32 && c < 126) {
                buf[0] = ch;
                buf[1] = 0;
            } else {
                sprintf(buf, "\\x%02x", c & 0xff);
            }
            return buf;
    }
    return "*error*";
}

std::string escape_cstring(const std::string& s) {
    std::ostringstream ss;
    for (char ch : s) {
        int c = ch;
        switch (c) {
            case '\a':
                ss << "\\a";
                break;  // 0x07
            case '\b':
                ss << "\\b";
                break;  // 0x08
            case '\t':
                ss << "\\t";
                break;  // 0x09
            case '\n':
                ss << "\\n";
                break;  // 0x0a
            case '\v':
                ss << "\\v";
                break;  // 0x0b
            case '\f':
                ss << "\\f";
                break;  // 0x0c
            case '\r':
                ss << "\\r";
                break;  // 0x0d
            case '\\':
                ss << "\\\\";
                break;
            case '\"':
                ss << "\\\"";
                break;
            // case '\'': ss <<  "\\'";
            // case '\?': ss <<  "\\\?";
            // case 0: ss <<  "\\0";
            default:
                if (c >= 32 && c < 126) {
                    ss << ch;
                } else {
                    ss << "\\x" << std::hex << std::setfill('0') << std::setw(2) << (c & 0xff);
                }
        }
    }
    return ss.str();
}

std::string escape_cstring(const char* p, size_t len) {
    std::ostringstream ss;
    for (size_t i = 0; i < len; i++) {
        ss << escape_cchar(p[i]);
    }
    return ss.str();
    constexpr int s = sizeof("\0\00\000\x14\x21");
}

std::string string_between_splice(const std::string& left, const std::string& right, std::string& subject, int flags,
                                  std::string repl, int repl_flags) {
    if (repl_flags == -1)
        repl_flags = flags;

    auto matched = string_between(left, right, subject, flags);
    if (matched.empty()) {
        return matched;
    }
    auto new_string = string_between(left, right, subject, repl_flags, [&repl](auto) { return repl; });
    subject         = new_string;
    return matched;
}

/// <summary>return the string -between two delimitters (non-inclusive)</summary>
/// <param name="subject">The quick brown fox</param>
/// <param name="left">quick</param>
/// <param name="right">fox</param>
/// <param name="repl">wolf</param>
/// <param name="flags">STRING_BETWEEN_(GREEDY|INCLUSIVE|TRIM_(RESULT|INPUT))</param>
/// <returns> brown </returns>
/// <remarks>Use an empty string to signify the beginning or end of the string</remarks>
std::string string_between(const std::string& left, const std::string& right, const std::string& subject, int flags,
                           std::function<std::string(std::string)> repl) {
    const bool inclusive    = flags & STRING_BETWEEN_INCLUSIVE;
    const bool greedy       = flags & STRING_BETWEEN_GREEDY;
    const bool ltrim_result = flags & STRING_BETWEEN_LTRIM_RESULT;
    const bool ltrim_input  = flags & STRING_BETWEEN_LTRIM_INPUT;
    const bool rtrim_result = flags & STRING_BETWEEN_RTRIM_RESULT;
    const bool rtrim_input  = flags & STRING_BETWEEN_RTRIM_INPUT;
    const auto npos         = std::string::npos;
    size_t l                = 0;
    size_t r                = npos;

    std::string _subject(subject);
    if (ltrim_input)
        ltrim(_subject);
    if (rtrim_input)
        rtrim(_subject);

    const size_t llen = left.length();
    const size_t rlen = right.length();

    if ((l = _subject.find(left)) == npos)
        return repl ? subject : "";
    if (!greedy && rlen)
        r = _subject.find(right, l + llen);
    else
        r = _subject.rfind(right);
    if (r == npos || r < (l + llen))
        return repl ? subject : "";
    if (!inclusive)
        l += llen;
    else
        r += rlen;

    // if (replstring) return s.substr(0, l) + repl + s.substr(r)
    std::string result;
    if (repl) {
        result = _subject.substr(0, l) + repl(_subject.substr(l, r)) + _subject.substr(r);
    } else {
        result = _subject.substr(l, r - l);
    }
    if (ltrim_result)
        ltrim(result);
    if (rtrim_result)
        rtrim(result);
    return result;
}

bool StringContains(const std::string& haystack, const std::string& needle, size_t* index, size_t* remainder) {
    size_t found = haystack.find(needle);
    if (found == -1)
        return false;
    if (index)
        *index = found;
    if (remainder)
        *remainder = haystack.length() - found - needle.length();
    return true;
}

bool StringEndsWith(const std::string& haystack, const std::string& needle) {
    if (needle.size() > haystack.size())
        return false;
    return std::equal(haystack.begin() + haystack.size() - needle.size(), haystack.end(), needle.begin());
}

bool StringStartsWith(const std::string& haystack, const std::string& needle) {
#if _MSC_VER >= 1916
    return haystack._Starts_with(needle);
#else
    if (needle.size() > haystack.size())
        return false;
    return std::equal(haystack.begin(), haystack.begin() + needle.size(), needle.begin());
#endif
}

#define PREG_PATTERN_ORDER 0
#define PREG_SET_ORDER 1
#define PREG_OFFSET_CAPTURE 2
/// <summary>
/// Searches subject for all matches to the regular expression given in pattern and puts them in matches in the order
/// specified by flags. After the first match is found, the subsequent searches are continued on from end of the last
/// match.
/// </summary>
/// <param name="pattern">The pattern to search for, as a string</param>
/// <param name="subject">The input string</param>
/// <param name="matches">Array of all matches in multi-dimensional array ordered according to flags</param>
/// <param name="flags">PREG_PATTERN_ORDER | PREG_SET_ORDER</param>
/// <param name="offset">Normally, the search starts from the beginning of the subject string. The optional parameter
/// offset can be used to specify the alternate place from which to start the search (in bytes)</param> <returns>Returns
/// the number of full pattern matches (which might be zero), or -1 if an error occurred</returns>
int preg_match_all(std::string pattern, std::string subject, std::vector<std::string>& matches, int flags, int offset) {
    // cobbled together from bits found at http://en.cppreference.com/w/cpp/regex/std::regex_search by sfink
    // (see also std::regex_iterator)
    int count = 0;
    try {
        std::regex r(pattern);
        std::smatch sm;
        while (std::regex_search(subject, sm, r)) {
            ++count;
            matches.push_back(sm.str());
            subject = sm.suffix();
        }
    } catch (...) {
        return -1;
    }

    return count;
}

#include <boost/config.hpp>
//#include <boost/regex.hpp>
#include <boost/xpressive/xpressive.hpp>
namespace bre = boost::xpressive;
int sregex_match(const std::string& pattern, const std::string& subject, std::vector<std::string>* matches, int flags) {
    bre::smatch sm;
    bre::sregex re = bre::sregex::compile(pattern);
    bool m         = bre::regex_search(subject, sm, re);
    if (m && matches) {
        for (auto i = 0; i < sm.size(); ++i)
            matches->emplace_back(sm[i]);
    }
    return m;
}

// int preg_match ( string $pattern , string $subject [, array &$matches [, int $flags = 0 [, int $offset = 0 ]]] )
int preg_match(const std::string& pattern, const std::string& subject, std::vector<std::string>* matches, int flags,
               int offset) {
    bool result     = false;
    bool ignoreCase = flags & PREG_MATCH_IGNORE_CASE;
    if (matches)
        matches->clear();
    try {
        std::regex r(pattern, (std::regex_constants::syntax_option_type)(ignoreCase ? std::regex_constants::icase : 0));
        std::smatch sm;
        result = std::regex_search(subject, sm, r);
        if (result && matches) {
            for (auto i = 0; i < sm.size(); ++i)
                matches->emplace_back(sm[i]);
        }
    } catch (std::regex_error e) {
        LOG_FUNC("%s (%s)", pattern.c_str(), e.what());
        return 0;
    }
    return result;
}

bool regex_match(const std::string& pattern, const std::string& subject, bool ignoreCase) {
    try {
        std::regex r(pattern, (std::regex_constants::syntax_option_type)(ignoreCase ? std::regex_constants::icase : 0));
        return std::regex_match(subject, r);
    } catch (...) {
        LOG_FUNC("clearly we need better exception handling");
    }
    return false;
}

std::string regex_search(const std::string& pattern, const std::string& subject, bool ignoreCase,
                         std::regex_constants::syntax_option_type options) {
    try {
        std::regex r(pattern, options | (std::regex_constants::syntax_option_type)(ignoreCase ? std::regex_constants::icase : 0));
        std::smatch sm;
        if (std::regex_search(subject, sm, r)) {
            return sm.str(sm.size() - 1);
            // return sm.str();
        }
    } catch (...) {
        LOG_FUNC("clearly we need better exception handling");
        return "";
    }

    return "";
}

int64_t parseInt(const std::string& str, int base, int64_t defaultValue) {
    std::size_t pos = -1;
    try {
        auto rv = std::stoll(str, &pos, base);
        if (pos != str.length()) {
            LOG_DEBUG(__FUNCTION__ ": pos != len (%llu, %llu) on %s", pos, str.length(), str.c_str());
            return defaultValue;
        }
        return rv;
    } catch (std::invalid_argument) {
    } catch (std::out_of_range) {
    }
    return defaultValue;
}

int64_t parseInt(const std::string& str, int base) {
    char* _     = nullptr;
    __int64 ret = _strtoi64(str.c_str(), &_, base);
    return ret;
}

int64_t parseInt(const std::wstring& str, int base) {
    char* _     = nullptr;
    __int64 ret = _strtoi64(narrow(str).c_str(), &_, base);
    return ret;
}

static const char fillchar = '=';
static const std::string cvt =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
std::string base64_decode(const std::string& data) {
    std::string::size_type i;
    char c;
    char c1;
    std::string::size_type len = data.length();
    std::vector<char> ret;

    for (i = 0; i < len; ++i) {
        c = (char)cvt.find(data[i]);
        ++i;
        c1 = (char)cvt.find(data[i]);
        c  = (c << 2) | ((c1 >> 4) & 0x3);
        ret.push_back(c);
        if (++i < len) {
            c = data[i];
            if (fillchar == c) break;
            c  = (char)cvt.find(c);
            c1 = ((c1 << 4) & 0xf0) | ((c >> 2) & 0xf);
            ret.push_back(c1);
        }
        if (++i < len) {
            c1 = data[i];
            if (fillchar == c1) break;
            c1 = (char)cvt.find(c1);
            c  = ((c << 6) & 0xc0) | c1;
            ret.push_back(c);
        }
    }
    return {ret.begin(), ret.end()};
}

std::vector<std::string> explode(char delimiter, const std::string& subject, int limit) {
    std::string buff;
    std::vector<std::string> v;

    --limit;
    for (auto ch : subject) {
        if (!limit || ch != delimiter)
            buff += ch;
        else if (limit && ch == delimiter && !buff.empty()) {
            v.emplace_back(std::move(buff));
            buff = "";
            --limit;
        }
    }
    if (!buff.empty()) v.push_back(buff);

    return v;
}

size_t file_put_contents(const std::string& filename, const char* start, size_t length, size_t member_size) {
    if (auto* fw = std::fopen(filename.c_str(), "wb")) {
        auto written = std::fwrite(start, member_size, length, fw);
        if (written < static_cast<size_t>(length * member_size)) {
            LOG_WARN("Couldn't write file all of file '%s', only wrote %lli bytes.", filename.c_str(), written);
        }
        fclose(fw);
        return written;
    }
    LOG_WARN("Couldn't open file for writing '%s'.", filename.c_str());
    return 0;
}

fs::path spread_filename(fs::path path) {
    auto dn = os::path::dirname(path.string());
    auto bn = os::path::basename(path.string());
    std::vector<std::string> subdirs;
    auto hash = joaat(bn.c_str(), 0);
    for (int i = 0; i < 2; ++i) {
        uint32_t part = hash & (64 - 1);
        hash >>= 6;
        subdirs.emplace_back(fmt::format("{:02}", part));
    }
    auto dstpath = os::path::join(dn, os::path::join(subdirs));
    return os::path::join(dstpath, bn);
}

void make_spread_folders(fs::path path) {
    if (fs::is_directory(path)) {
        for (int i = 0; i < 64; ++i) {
            auto path1 = path / fmt::format("{:02}", i);
            if (!fs::is_directory(path1)) {
                fs::create_directory(path1);
            }
            for (int j = 0; j < 64; ++j) {
                auto path2 = path1 / fmt::format("{:02}", j);
                if (!fs::is_directory(path2)) {
                    fs::create_directory(path2);
                }
            }
        }
    }
}

std::optional<uint64_t> asQword(const std::string& arg, int default_base) {
    uint64_t value = 0;
    std::optional<uint64_t> opt_value;
    int dereference        = 0;
    int offset_dereference = 0;

    auto haystack = arg;
    while (haystack[0] == '*') {
        dereference++;
        haystack = haystack.substr(1);
    }

    std::string _offset;
    uint64_t offset = 0;
    bool use_offset = {};
    if (~strpos(haystack, "+") && ~string_between_swap("+", "", haystack, _offset, STRING_BETWEEN_INCLUSIVE)) {
        _offset = _offset.substr(1);
        while (_offset[0] == '*') {
            offset_dereference++;
            _offset = _offset.substr(1);
        }
        if (auto o = asQword(_offset)) {
            offset     = *o;
            use_offset = true;
        }
    }

    if (auto match = regex_search(R"(^-((?:0[xX])?[0-9a-fA-F]+$)", haystack); !match.empty())
        opt_value = parseIntOpt(match, 16);
    else if (auto match = regex_search(R"(^((?:0[xX])?[0-9a-fA-F]+$)", haystack); !match.empty())
        opt_value = parseUintOpt(match, 16);
    else if (auto match = regex_search("^[0-9a-fA-F]+(?=h)$", haystack); !match.empty())
        opt_value = parseUintOpt(match, 16);
    else if (auto match = regex_search(R"(^exe\+([0-9a-fA-F]+)$)", haystack); !match.empty())
        opt_value = parseUintOpt(match, 16);
    else
        opt_value = parseUintOpt(match, default_base);

    if (!opt_value)
        return opt_value;
    value = *opt_value;

    if (dereference) {
        while (dereference--) {
            if (auto result = safeDereferenceOptRef(value))
                value = *result;
            else
                return std::nullopt;
        }
    }
    if (use_offset) {
        value += offset;
        while (offset_dereference--) {
            if (auto result = safeDereferenceOptRef(value))
                value = *result;
            else
                return std::nullopt;
        }
    }
    return value;
}

std::optional<uint32_t> asDword(const std::string& arg, int default_base) {
    if (auto o = asQword(arg, default_base)) {
        return static_cast<uint32_t>(*o);
    }
    return std::nullopt;
}

std::optional<bool> asBool(const std::string& rest) {
    if (auto match = regex_search("^(1|enable|enabled|on|true|yes)$", rest, true); !match.empty()) return true;
    if (auto match = regex_search("^(0|disable|disabled|off|false|no)$", rest, true); !match.empty()) return false;
    return std::nullopt;
}

std::optional<std::reference_wrapper<uintptr_t>> __Memory__internal__safeDereferenceInt64OptRef(uintptr_t address) {
    uintptr_t* p = reinterpret_cast<uintptr_t*>(address);
    static void* exceptionAddress;

    __try {
        auto& value = *p;
        return value;
        // std::optional<std::reference_wrapper<uintptr_t>>{value}
    } __except (exceptionAddress = (GetExceptionInformation())->ExceptionRecord->ExceptionAddress, EXCEPTION_EXECUTE_HANDLER) {
        // LOG_DEBUG("safeDereference: exception reading pointer at %p", (void*)p);
    }

    return std::nullopt;
}
