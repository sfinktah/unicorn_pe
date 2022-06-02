#pragma once
#include <string>
#include <utility>
#include <vector>
#include <iostream>
#include <optional>
#include <regex>
#include <sstream>
#include <functional>

using namespace std::string_literals;

// from https://stackoverflow.com/questions/51077383/does-structured-binding-work-with-stdvector
template <class T, std::size_t N>
struct vector_binder {
    std::vector<T>& vec;

    template <std::size_t I>
    T& get() {
        return vec.at(I, 1);
    }
};

namespace std {
    template <class T, std::size_t N>
    struct tuple_size<vector_binder<T, N>> : std::integral_constant<std::size_t, N> {};

    template <std::size_t I, std::size_t N, class T>
    struct tuple_element<I, vector_binder<T, N>> {
        using type = T;
    };
}  // namespace std

/*
template <std::size_t N, class T>
static auto dissect(std::vector<T>& vec) {
    return vector_binder<T, N>{vec};
}

static int example() {
    std::vector<int> v{1, 2, 3};
    auto [a, b] = dissect<2>(v);

    a = 5;
    std::cout << v[0] << '\n';  // Has changed v through a as expected.
}
*/

namespace pogo {
    using vector_string  = std::vector<std::string>;
    using cref_string    = const std::string&;
    using ref_string     = std::string&;
    using movable_string = std::string;

#ifndef LOG_TRACE
#define LOG_TRACE(X, ...)
#define LOG_FUNC(X, ...)
#endif
    static vector_string explode(char delimiter, cref_string subject) {
        std::string buff;
        std::vector<std::string> v;

        for (auto ch : subject) {
            if (ch != delimiter)
                buff += ch;
            else if (ch == delimiter && !buff.empty()) {
                v.emplace_back(std::move(buff));
                buff = "";
            }
        }
        if (!buff.empty()) v.push_back(buff);

        return v;
    }

    static std::string regex_search(cref_string pattern, cref_string subject, bool ignoreCase = {},
                                    std::regex_constants::syntax_option_type options = {}) {
        try {
            std::regex r(pattern,
                         options | (std::regex_constants::syntax_option_type)(ignoreCase ? std::regex_constants::icase : 0));
            std::smatch sm;
            if (std::regex_search(subject, sm, r)) {
                if (sm.size() > 1) {
                    LOG_TRACE(__FUNCTION__ ": matches: %llx", sm.size());
                }
                return sm.str(sm.size() - 1);
                // return sm.str();
            }
        } catch (...) {
            LOG_FUNC("clearly we need better exception handling");
            return "";
        }

        return "";
    }
    // ReSharper disable CppDeclarationHidesLocal
    template <typename T>
    static std::optional<T> asNumeric(cref_string str) {
        T value;
        if (auto match = regex_search("^[0-9-+]+$", str); !match.empty())
            value = T(std::strtoull(match.c_str(), nullptr, 10));
        else if (auto match = regex_search("^[0-9-+.eE]+$", str); !match.empty())
            value = T(std::strtof(match.c_str(), nullptr));
        else if (auto match = regex_search("^0[xX][0-9a-fA-F]+$", str); !match.empty())
            value = T(std::strtoull(match.c_str(), nullptr, 16));
        else if (auto match = regex_search("^(1|enabled|enable|on|true|yes)$", str, true); !match.empty())
            value = T(1);
        else if (auto match = regex_search("^(0|disabled|disable|off|false|no)$", str, true); !match.empty())
            value = T(0);
        else
            return std::nullopt;

        return value;
    }

    static constexpr const char* whitespace = " \t\n\r\f\v";
    inline std::string& rtrim(std::string& s, const char* t = whitespace) { return s.erase(s.find_last_not_of(t) + 1); }
    inline std::string& ltrim(std::string& s, const char* t = whitespace) { return s.erase(0, s.find_first_not_of(t)); }
    inline std::string& trim(std::string& s, const char* t = whitespace) { return ltrim(rtrim(s, t), t); }
    static std::optional<bool> asBool(cref_string str) {
        if (auto rv = asNumeric<bool>(str)) return *rv;
        return std::nullopt;
    }

    static bool asBool(cref_string str, bool _default) {
        if (auto rv = asBool(str)) return bool(*rv);
        return _default;
    }

    static std::optional<uint64_t> asQword(cref_string str) {
        if (auto rv = asNumeric<uint64_t>(str)) return *rv;
        return std::nullopt;
    }

    static uint64_t asQword(cref_string str, uint64_t _default) {
        if (auto rv = asQword(str)) return uint64_t(*rv);
        return _default;
    }

    template <typename T>
    static T asNumeric(cref_string str, T _default) {
        if (auto rv = asNumeric<T>(str)) return T(*rv);
        return _default;
    }

    template <typename T>
    std::string join(const T& elements, std::string separator = ",") {
        std::ostringstream os;
        // http://stackoverflow.com/a/5289170/912236
        // see also: https://stackoverflow.com/questions/191757/how-to-concatenate-a-stdstring-and-an-int

        /* zorg and clang m_source say:
        auto separator = "";
        for (auto& item : collection) {
            stream << separator << item;
            separator = ", ";
        }
        */
        std::string _separator = "";
        for (const auto& item : elements) {
            os << _separator << item;
            _separator = separator;
        }
        return os.str();

        // This method balked at integer values
        // auto v = lodash::values<std::vector<value_type_t>>(elements);
        // std::copy(v.begin(), v.end() - 1, std::ostream_iterator<std::string>(os, separator));
        // os << *v.rbegin();
        // return os.str();
    }
    // ReSharper restore CppDeclarationHidesLocal

    struct WhitespaceTokeniser {
        enum token_types_t { TOK_QWORD,
                             TOK_CSTR };
        WhitespaceTokeniser(movable_string p_source, char p_delimiter);
        WhitespaceTokeniser();
        explicit WhitespaceTokeniser(vector_string tokens);

    public:  // public methods
        cref_string get_current() const;
        cref_string get_next() const;
        cref_string get_next_or(cref_string defaultValue) const;
        cref_string get_next_or(std::function<std::string(WhitespaceTokeniser)> defaultFunction) const;
        vector_string slice(size_t start) const;
        vector_string get_args() const;
        std::string get_rest() const;
        std::string get_string() const;
        std::string get_original() const;
        enum token_types_t get_type() const { return m_token_types[m_position]; }
        bool is_string() const { return m_token_types[m_position] == TOK_CSTR; }
        bool advance() const;
        size_t size() const;
        bool empty() const;
        void replode(cref_string p_source);
        void parse(cref_string cs);
        void insert(vector_string subject);
        auto begin() { return m_tokens.begin(); }
        auto end() { return m_tokens.end(); }
        auto eof() const { return empty(); }

        template <size_t N>
        auto next_multiple() const {
            return vector_binder<std::string, N>(slice(m_position + 1));
        }

        cref_string peek(int offset = 1) const;

        // static helpers
        static WhitespaceTokeniser fromCommandLineArguments(int argc, const char** argv) {
            std::vector<std::string> arguments(argv + 1, argv + argc);
            return WhitespaceTokeniser(arguments);
        }

    protected:                 // variables
        std::string m_source;  // the full original m_source
        vector_string m_tokens;
        std::vector<token_types_t> m_token_types;
        size_t mutable m_position = 0;
        std::string empty_string;
        char m_delimiter = ' ';

    protected:  // helper functions
        bool valid_index(size_t index) const;

    public:  // properties
        // vector of all elements, excluding current
        __declspec(property(get = get_args)) vector_string args;

        // string of all elements, starting at current + 1
        __declspec(property(get = get_rest)) std::string rest;

        // current element
        __declspec(property(get = get_current)) std::string current;

        // advance to next element and return value
        __declspec(property(get = get_next)) std::string next;

        // string of all elements, starting at current
        __declspec(property(get = get_string)) std::string string;

        // original string passed for tokenisation
        __declspec(property(get = get_original)) std::string original;

        // token type
        __declspec(property(get = get_type)) token_types_t type;
    };

    inline bool WhitespaceTokeniser::valid_index(size_t index) const { return index < m_tokens.size(); }

    inline cref_string WhitespaceTokeniser::get_current() const {
        return valid_index(m_position) ? m_tokens.at(m_position) : empty_string;
    }

    inline cref_string WhitespaceTokeniser::get_next() const { return advance() ? get_current() : empty_string; }

    inline cref_string WhitespaceTokeniser::get_next_or(cref_string& defaultValue) const {
        return advance() ? get_current() : defaultValue;
    }

    inline cref_string WhitespaceTokeniser::get_next_or(std::function<std::string(WhitespaceTokeniser)> defaultFunction) const {
        return advance() ? get_current() : defaultFunction(*this);
    }

    inline cref_string WhitespaceTokeniser::peek(int offset) const {
        return valid_index(m_position + offset) ? m_tokens.at(m_position + offset) : empty_string;
    }

    // template <std::size_t N, class T>
    // static auto dissect(std::vector<T>& vec) {
    //    return vector_binder<T, N>{vec};
    //}

    inline vector_string WhitespaceTokeniser::slice(size_t start) const {
        vector_string result;
        if (start < m_tokens.size()) {
            for (auto it = std::next(m_tokens.begin(), start); it != m_tokens.end(); ++it) {
                result.emplace_back(*it);
            }
        }
        return result;
    }

    inline void WhitespaceTokeniser::insert(vector_string subject) {
        m_tokens.insert(m_tokens.begin() + (m_position + 1), subject.begin(), subject.end());
    }

    inline vector_string WhitespaceTokeniser::get_args() const {
        return valid_index(m_position + 1) ? slice(m_position + 1) : vector_string{};
    }

    inline std::string WhitespaceTokeniser::get_rest() const {
        return valid_index(m_position + 1) ? join(get_args(), ""s + m_delimiter) : empty_string;
    }

    inline std::string WhitespaceTokeniser::get_string() const {
        return valid_index(m_position) ? join(slice(m_position), ""s + m_delimiter) : empty_string;
    }

    inline std::string WhitespaceTokeniser::get_original() const { return m_source; }

    inline bool WhitespaceTokeniser::advance() const {
        if (valid_index(m_position)) {
            if (valid_index(++m_position)) {
                return true;
            }
        }
        return false;
    }

    inline size_t WhitespaceTokeniser::size() const { return m_tokens.size() - m_position; }

    inline bool WhitespaceTokeniser::empty() const { return !valid_index(m_position); }

    inline void WhitespaceTokeniser::replode(cref_string p_source) { m_tokens = explode(m_delimiter, p_source); }

    inline WhitespaceTokeniser::WhitespaceTokeniser(movable_string p_source, char p_delimiter = ' ')
        : m_source(std::move(p_source)), m_delimiter(p_delimiter) {
        parse(trim(m_source));
        // tokens = explode(p_delimiter, p_source);
        // std::for_each(tokens.begin(), tokens.end(), [](ref_string _) { trim(_); });
        // for (auto i = tokens.begin(); i != tokens.end();) ([](cref_string _) { return _.empty(); })(*i) ? i = tokens.erase(i) :
        // ++i;
    }

    inline WhitespaceTokeniser::WhitespaceTokeniser() : m_source(""), m_delimiter('\x00') {}

    inline WhitespaceTokeniser::WhitespaceTokeniser(vector_string tokens) : m_tokens(std::move(tokens)) {}

}  // namespace pogo

#if 0
// example usage

while (true) {
    const char *line = linenoise(prompt);
    auto parser = pogo::WhitespaceTokeniser(line);
    free(line);

    if (parser.empty())
        continue;

    linenoiseHistoryAdd(parser.original);
    auto command = parser.current;

    if (command == "serialize") {
        continue;
    }
    if (command == "fibers") {
        continue;
    }
    if (command == "alloc") {
        std::string _arg = parser.next;
        linenoiseWrite(MyGtaAllocDebug(_arg));
    }
}

#endif
