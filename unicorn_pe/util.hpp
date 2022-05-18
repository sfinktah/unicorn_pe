#pragma once

#include "Filesystem.hpp"
#include <regex>
using namespace std::literals::string_literals;
#include <iostream>
#include <optional>

std::string GetModuleName(const HMODULE module);
fs::path GetModulePath(std::string name);

inline std::pair<HMODULE, size_t> g_ProcessRange;

std::vector<std::string> split(const std::string& s, char delim);

static constexpr const char* whitespace = " \t\n\r\f\v";
inline std::string& ltrim(std::string& s, const char* t = whitespace) { return s.erase(0, s.find_first_not_of(t)); }
inline std::string& rtrim(std::string& s, const char* t = whitespace) { return s.erase(s.find_last_not_of(t) + 1); }
inline std::string& trim(std::string& s, const char* t = whitespace) { return ltrim(rtrim(s, t), t); }

inline std::string crtrim(std::string s, const char* t = whitespace) { return rtrim(s); }
inline std::string cltrim(std::string s, const char* t = whitespace) { return ltrim(s); }
inline std::string ctrim(std::string s, const char* t = whitespace) { return ltrim(rtrim(s, t), t); }

/// <summary>Find the position of the first occurrence of a substring in a string</summary>
/// <param name="haystack">The string to search in.</param>
/// <param name="needle">If <paramref name="needle" /> is not a string, it is converted to an integer and applied as the ordinal
/// value of a character.</param> <param name="offset">If specified, search will start this number of characters counted from
/// the beginning of the string. If the offset is negative, the search will start this number of characters counted from the end
/// of the string.</param> <returns>index of match or -1 on failure</returns>
template <typename T>
int strpos(const std::basic_string<T>& haystack, const std::basic_string<T>& needle, int offset = 0) {
    auto found = haystack.find(needle, offset);
    return (found == std::string::npos) ? -1 : (int)found;
}

template <class T>
auto strpos(T const* haystack, T const* needle, int offset = 0) {
    return strpos(std::basic_string<T>(haystack), std::basic_string<T>(needle), offset);
}
template <class T>
auto strpos(T const* haystack, const std::basic_string<T>& needle, int offset = 0) {
    return strpos(std::basic_string<T>(haystack), std::basic_string<T>(needle), offset);
}
template <class T>
auto strpos(const std::basic_string<T>& haystack, T const* needle, int offset = 0) {
    return strpos(std::basic_string<T>(haystack), std::basic_string<T>(needle), offset);
}

std::vector<uintptr_t> __declspec(noinline) StackTraceAsVector(std::size_t limit = 50, std::size_t skip = 2);
std::string __declspec(noinline) StackTraceAsString(std::size_t limit = 20, std::size_t skip = 2);

template <typename T>
std::string asHexString(T i) {
    static_assert(std::is_integral_v<std::remove_reference_t<T>>, "Integral required.");
    std::ostringstream stream;
    stream << std::setfill('0') << std::setw(16) << std::hex << static_cast<uintptr_t>(i);
    std::string s = stream.str();
    auto z        = 16 - sizeof(T) * 2;  // sizeof(T)
    return "0x"s + s.substr(z);
}

template <typename T>
std::string join(const T& elements, const std::string& separator = ",") {
    std::ostringstream os;
    // http://stackoverflow.com/a/5289170/912236
    // see also: https://stackoverflow.com/questions/191757/how-to-concatenate-a-stdstring-and-an-int

    std::string _separator;
    for (const auto& item : elements) {
        os << _separator << item;
        _separator = separator;
    }
    return os.str();
}

std::string escape_cstring(const std::string& s);
std::string escape_cstring(const char* p, size_t len);

inline int __cdecl strcmp(const std::string& str1, char const* str2) { return str1.compare(str2); }
inline int __cdecl strcmp(char const* str1, const std::string& str2) { return str2.compare(str1) * -1; }
inline int __cdecl strcmp(const std::string& str1, const std::string& str2) { return str1.compare(str2); }

#define STRING_BETWEEN_NOT_INCLUSIVE 0x00
#define STRING_BETWEEN_INCLUSIVE 0x01
#define STRING_BETWEEN_NOT_GREEDY 0x00
#define STRING_BETWEEN_GREEDY 0x02
#define STRING_BETWEEN_LTRIM_INPUT 0x10
#define STRING_BETWEEN_LTRIM_RESULT 0x20
#define STRING_BETWEEN_RTRIM_INPUT 0x40
#define STRING_BETWEEN_RTRIM_RESULT 0x40
#define STRING_BETWEEN_TRIM_INPUT (STRING_BETWEEN_LTRIM_INPUT | STRING_BETWEEN_RTRIM_INPUT)
#define STRING_BETWEEN_TRIM_RESULT (STRING_BETWEEN_LTRIM_RESULT | STRING_BETWEEN_RTRIM_RESULT)

std::string string_between(const std::string& left, const std::string& right, const std::string& subject, int flags = {},
                           std::function<std::string(std::string)> repl = nullptr);

inline std::string string_between_replace(const std::string& left, const std::string& right, const std::string& subject,
                                          std::function<std::string(std::string)> repl, int flags = {}) {
    return string_between(left, right, subject, flags, std::move(repl));
}

inline std::string string_between_replace(const std::string& left, const std::string& right, const std::string& subject,
                                          const std::string& repl, int flags = {}) {
    return string_between(left, right, subject, flags, [&repl](const auto&) -> std::string { return repl; });
}

std::string string_between_splice(const std::string& left, const std::string& right, std::string& subject, int flags = {}, std::string repl = "",
                                  int repl_flags = -1);

inline size_t string_between_swap(const std::string& left, const std::string& right, std::string& subject, std::string& into, int flags = {}) {
    size_t result = -1;

    string_between(left, right, subject, flags, [&](const auto& match) -> std::string {
        result    = match.length();
        auto repl = into;
        into      = match;
        return repl;
    });

    return result;
};

bool StringEndsWith(const std::string& haystack, const std::string& needle);
bool StringStartsWith(const std::string& haystack, const std::string& needle);
bool StringContains(const std::string& haystack, const std::string& needle, size_t* index = nullptr, size_t* remainder = nullptr);

#define PREG_MATCH_IGNORE_CASE (1 << 0)
int preg_match_all(std::string pattern, std::string subject, std::vector<std::string>& matches, int flags = 0, int offset = 0);
int sregex_match(const std::string& pattern, const std::string& subject, std::vector<std::string>* matches = nullptr, int flags = 0);
int preg_match(const std::string& pattern, const std::string& subject, std::vector<std::string>* matches = nullptr, int flags = 0, int offset = 0);
bool regex_match(const std::string& pattern, const std::string& subject, bool ignoreCase = 0);

//!  * \brief preg_replace(const CharType* pattern, const CharType* replacement, const CharType* subject)
template <typename CharType>
std::basic_string<CharType> preg_replace(const CharType* pattern, const CharType* replacement, const CharType* subject) {
    // https://stackoverflow.com/questions/23622622/c-regex-with-char-and-wchar-t/23623610#23623610
    std::basic_regex<CharType> _pattern(pattern);
    std::basic_string<CharType> _subject(subject);
    return std::regex_replace(_subject, _pattern, replacement);
}

// https://stackoverflow.com/questions/22617209/regex-replace-with-callback-in-c11
template <class BidirIt, class Traits, class CharT, class UnaryFunction>
std::basic_string<CharT> regex_replace(BidirIt first, BidirIt last, const std::basic_regex<CharT, Traits>& re,
                                       UnaryFunction function) {
    std::basic_string<CharT> s;

    typename std::match_results<BidirIt>::difference_type positionOfLastMatch = 0;
    auto endOfLastMatch                                                       = first;

    auto callback = [&](const std::match_results<BidirIt>& match) {
        auto positionOfThisMatch = match.position(0);
        auto diff                = positionOfThisMatch - positionOfLastMatch;

        auto startOfThisMatch = endOfLastMatch;
        std::advance(startOfThisMatch, diff);

        s.append(endOfLastMatch, startOfThisMatch);
        s.append(function(match));

        auto lengthOfMatch = match.length(0);

        positionOfLastMatch = positionOfThisMatch + lengthOfMatch;

        endOfLastMatch = startOfThisMatch;
        std::advance(endOfLastMatch, lengthOfMatch);
    };

    std::sregex_iterator begin(first, last, re), end;
    std::for_each(begin, end, callback);

    s.append(endOfLastMatch, last);

    return s;
}

template <class Traits, class CharT, class UnaryFunction>
std::string regex_replace(const std::string& s, const std::basic_regex<CharT, Traits>& re, UnaryFunction f) {
    return regex_replace(s.cbegin(), s.cend(), re, f);
}

//! \param options [ECMAScript|basic|extended|awk|grep|egrep] [icase] [nosubs] [optimize] [collate]
std::string regex_search(const std::string& pattern, const std::string& subject, bool ignoreCase = {},
                         std::regex_constants::syntax_option_type options = {});

template <typename CharT>
int64_t parseInt(const std::basic_string<CharT>& str, int base, int64_t defaultValue) {
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

template <typename T, typename R = uint64_t>
R parseUint(const T& str, int base, R defaultValue) {
    std::size_t pos = -1;
    try {
        auto rv = std::stoull(str, &pos, base);
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

template <typename T, typename R = uint64_t>
std::optional<R> parseUintOpt(const T& str, int base) {
    std::size_t pos = -1;
    try {
        auto rv = std::stoull(str, &pos, base);
        if (pos == str.length()) {
            return rv;
        }
    } catch (std::invalid_argument) {
    } catch (std::out_of_range) {
    }
    return std::nullopt;
}

template <typename T, typename R = uint64_t>
std::optional<R> parseIntOpt(const T& str, int base) {
    std::size_t pos = -1;
    try {
        auto rv = std::stoll(str, &pos, base);
        if (pos == str.length()) {
            return rv;
        }
    } catch (std::invalid_argument) {
    } catch (std::out_of_range) {
    }
    return std::nullopt;
}

int64_t parseInt(const std::string& str, int base, int64_t defaultValue);
int64_t parseInt(const std::string& str, int base = 10);
int64_t parseInt(const std::wstring& str, int base = 10);

std::vector<std::string> explode(char delimiter, const std::string& subject, int limit = LONG_MAX);
std::string base64_decode(const std::string& data);

template <class T>
auto strtolower(T const* p) {
    return strtolower(std::basic_string<T>(p));
}
template <typename T>
auto strtolower(std::basic_string<T> s) {
    return std::transform(s.begin(), s.end(), s.begin(), tolower), s;
}
std::optional<std::reference_wrapper<uintptr_t>> __Memory__internal__safeDereferenceInt64OptRef(uintptr_t address);

template <typename R = uintptr_t, typename T>
typename std::add_lvalue_reference<R>::type safeDereferenceRef(T address) {
    auto addr = (uintptr_t)address;
    return *reinterpret_cast<typename std::add_pointer<R>::type>(addr);
}

template <typename R = uintptr_t, typename T>
typename std::optional<std::reference_wrapper<R>> safeDereferenceOptRef(T address) {
    auto addr = (uintptr_t)address;
    if (auto ptr = __Memory__internal__safeDereferenceInt64OptRef(addr)) {
        // return *reinterpret_cast<R*>(addr);
        return safeDereferenceRef<R>(addr);
    }
    return std::nullopt;
}

std::optional<uint64_t> asQword(const std::string& arg, int default_base = 0);
std::optional<uint32_t> asDword(const std::string& arg, int default_base = 0);
std::optional<bool> asBool(const std::string& arg);

class executable_meta {
private:
    uintptr_t m_begin;
    uintptr_t m_end;
    DWORD m_size;

public:
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeader;
    template <typename TReturn, typename TOffset>
    TReturn* getRVA(TOffset rva) {
        return (TReturn*)(m_begin + rva);
    }

    executable_meta(void* module) : m_begin((uintptr_t)module), m_end(0) {
        dosHeader = getRVA<IMAGE_DOS_HEADER>(0);
        ntHeader  = getRVA<IMAGE_NT_HEADERS>(dosHeader->e_lfanew);

        m_end  = m_begin + ntHeader->OptionalHeader.SizeOfCode;
        m_size = ntHeader->OptionalHeader.SizeOfImage;
    }

    uintptr_t base() const { return m_begin; }
    uintptr_t end() const { return m_end; }
    DWORD size() const { return m_size; }
};

size_t file_put_contents(const std::string& filename, const char* start, size_t length, size_t member_size = 1);
fs::path spread_filename(fs::path path);
void make_spread_folders(fs::path path);

class Timer {
public:
    using clock = std::chrono::steady_clock;

    Timer() : m_Time(clock::now()){}

                  [[nodiscard]] clock::duration GetElapsed() const { return clock::now() - m_Time; }

    void ShowElapsed() const {
        auto secondsSinceLaunch = std::chrono::duration_cast<std::chrono::seconds>(GetElapsed()).count();
        int hours               = secondsSinceLaunch / 3600 % 24;
        int minutes             = secondsSinceLaunch / 60 % 60;
        int seconds             = secondsSinceLaunch % 60;

        std::cout << "\nTime wasted: " << std::dec << hours << " hours " << minutes << " minutes "
                  << seconds << " seconds"
                  << "\n";
    }

    [[nodiscard]] bool HasElapsed(const clock::duration& delay) const { return GetElapsed() >= delay; }

    void Reset() { m_Time = clock::now(); }

private:
    clock::time_point m_Time;
};
