#include "BraceExpander.h"
//#include <ostream>
#include <optional>
#include <regex>
#include <functional>
#include <fmt/format.h>
#include "../vendor/lodash/014_filter.h"

namespace sfinktah::string::brace_expander {

    struct m_t {
        size_t i;
        size_t start;
        size_t end;
        std::string pre;
        std::string body;
        std::string post;
    };

    std::string String(long long value) {
        std::ostringstream out;
        out << value;
        return out.str();
    }

    std::string HexString(long long value) {
        return fmt::format("{:#x}", value);
    }

    int64_t parseInt(const std::string& str, int base) {
        char* _       = 0;
        long long ret = _strtoi64(str.c_str(), &_, base);
        return ret;
    }

    auto numeric(const std::string& str) {
        if (str[0] == '0' && str[1] == 'x')
            return parseInt(str, 16);

        return String(parseInt(str, 10)) == str
                   ? parseInt(str, 10)
                   : str[0];
    }

    // this is retardation
    std::string chr(int c) {
        std::ostringstream oss;
        oss << static_cast<char>(c);
        return oss.str();
    }

    auto concatMap(std::vector<std::string> xs, std::function<std::vector<std::string>(std::string)> fn) {
        std::vector<std::string> res;
        for (auto elem : xs)
            for (auto elem : fn(elem))
                res.push_back(elem);
        return res;
    };

    std::optional<m_t> isBalanced(char a, char b, const std::string& str) {
        auto bal = 0;
        m_t m    = {};
        m.start  = -1;
        m.end    = -1;

        for (auto i = 0; i < str.length(); i++) {
            if (str[i] == a) {
                if (m.start == -1)
                    m.start = i;
                bal++;
            } else if (str[i] == b) {
                if (!--bal) {
                    m.end  = i;
                    m.pre  = str.substr(0, m.start);
                    m.body = (m.end - m.start > 1)
                                 ? str.substr(m.start + 1, m.end - m.start - 1)  // str.substring(m.start + 1, m.end)
                                 : "";
                    m.post = str.substr(m.end + 1);  // str.slice(m.end + 1);
                    return m;
                }
            }
        }

        return {};
    };

    std::vector<std::string> expand(const std::string& str) {
        std::vector<std::string> expansions;

        m_t m    = {};
        auto val = isBalanced('{', '}', str);
        if (val.has_value()) {
            m = val.value();
        }

        std::smatch match;
        if (!val.has_value() || std::regex_search(m.pre, match, std::regex(R"(\$$)"))) return {str};

        auto isNumericSequence = std::regex_search(m.body, match, std::regex(R"(^-?\d+\.\.-?\d+(\.\.-?\d+)?$)"));
        auto isHexSequence     = std::regex_search(m.body, match, std::regex(R"(^-?0x[0-9a-fA-F]+\.\.-?0x[0-9a-fA-F]+(\.\.-?(0x)?[0-9a-fA-F]+)?$)"));
        auto isAlphaSequence   = !isHexSequence && std::regex_search(m.body, match, std::regex(R"(^[^0-9]\.\.[^0-9](\.\.\d+)?$)"));
        auto isOptions         = std::regex_search(m.body, match, std::regex(R"(^(.*,)+(.+)?$)"));
        auto isSequence        = isNumericSequence || isHexSequence || isAlphaSequence;

        if (!isSequence && !isOptions) return {str};

        auto pre = m.pre.length()
                       ? expand(m.pre)
                       : std::vector<std::string>{""};
        auto post = m.post.length()
                        ? expand(m.post)
                        : std::vector<std::string>{""};

        std::vector<std::string> n;
        auto balance    = 0;
        std::string buf = "";
        auto separator  = isSequence
                             ? std::regex(R"(^\.\.)")
                             : std::regex(R"(^,)");

        for (auto i = 0; i < m.body.length(); i++) {
            auto c            = m.body[i];
            std::string slice = m.body.substr(i);
            if (!balance && std::regex_search(slice, match, separator)) {  // .test(m.body.slice(i))) {
                n.push_back(buf);
                buf = "";
            } else if (!(isSequence && c == '.')) {
                buf += c;
                if (c == '{')
                    balance++;
                else if (c == '}')
                    balance--;
            }
            if (i == m.body.length() - 1) {
                n.push_back(buf);
            }
        }
        n = concatMap(n, expand);

        std::vector<std::string> N;

        if (!isSequence) {
            N = n;
        } else {
            auto x     = numeric(n[0]);
            auto y     = numeric(n[1]);
            auto width = std::max(n[0].length(), n[1].length());
            auto incr  = n.size() == 3
                            ? std::abs(numeric(n[2]))
                            : 1;
            auto reverse = y < x;
            auto pad     = _::filter<std::vector<std::string>>(n, [](const auto& el) {
                           std::smatch match;
                           return std::regex_search(el, match, std::regex(R"(^-?0\d)"));
                       })
                           .size();

            N.clear();

            auto push = [&](auto i) {
                if (isAlphaSequence) {
                    N.push_back(chr(i));
                } else if (isHexSequence) {
                    std::string outstr(HexString(i));  // i = String(i);
                    if (pad) {
                        while (outstr.length() < width) i = '0' + i;
                    }
                    N.push_back(outstr);
                } else {
                    std::string outstr(String(i));  // i = String(i);
                    if (pad) {
                        while (outstr.length() < width) i = '0' + i;
                    }
                    N.push_back(outstr);
                }
            };

            if (reverse)
                for (auto i = x; i >= y; i -= incr) push(i);
            else
                for (auto i = x; i <= y; i += incr) push(i);

            if (std::abs(y - x) % incr) push(y);
        }

        for (auto i = 0; i < pre.size(); i++) {
            for (auto j = 0; j < N.size(); j++) {
                for (auto k = 0; k < post.size(); k++) {
                    expansions.push_back(join(std::vector<std::string>{pre[i], N[j], post[k]}, ""));
                }
            }
        }

        return expansions;
    }
};  // namespace sfinktah::string::brace_expander