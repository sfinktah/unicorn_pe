#include <windows.h>
#include <boost/config.hpp>
#include <boost/circular_buffer.hpp>
//#include <boost/regex.hpp>
#include <boost/xpressive/xpressive.hpp>
namespace bre = boost::xpressive;
#include <pystring/pystring.h>
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include "util.hpp"
#include "multimatch.h"
#include "../vendor/lodash/lodash_common.h"
#include "../vendor/lodash/001_each.h"
#include "../vendor/lodash/024_keys.h"
#include "../vendor/lodash/026_slice.h"
#include "../vendor/lodash/071_join.h"
#include "../vendor/lodash/095_uniq.h"
#ifndef NOMINMAX
#undef min
#undef max
#endif

// clang-format off
static std::string wrap_pattern(std::string pattern) {
    pattern = pystring::replace(pattern, R"'(\x)'",                             R"'([0-9a-fA-F])'");
    pattern = pystring::replace(pattern, R"'(\w\+)'",                           R"'(\w+)'");
    pattern = pystring::replace(pattern, R"'([::address::])'",                  R"'((?:(?:0x|loc_)?[0-9a-fA-F]{9,}))'");
    pattern = string_between("({", "}", pattern, STRING_BETWEEN_INCLUSIVE,
                                                [](std::string v) { return fmt::format("(?P<{}>", string_between("({", "}", v)); });
    // pattern = pystring::replace(pattern, R"'( += )'",                           R"'( \+= )'")
    // pattern = pystring::replace(pattern, R"'( ^ )'",                            R"'( \^ )'")
    // pattern = pystring::replace(pattern, R"'([::reinterpret_pointer_cast::])'", R"'((?:\*\([^)]+\*\)))'")
    // pattern = pystring::replace(pattern, R"'([::pointer_cast::])'",             R"'((?:\([^)]+\*\)))'")
    // pattern = pystring::replace(pattern, R"'([::static_cast::])'",              R"'((?:\([^)]+\)))'")
    // pattern = pystring::replace(pattern, R"'([::reference_cast::])'",           R"'((?:\([^)]+\)&))'")
    // pattern = pystring::replace(pattern, R"'([::reinterpet_cast::])'",          R"'((?:\*\([^)]+\)&))'")
    // pattern = pystring::replace(pattern, R"'([::deref_static_cast::])'",        R"'((?:\*\([^)]+\)))'")
    // pattern = pystring::replace(pattern, R"'([::v::])'",                        R"'((?:v\d+))'")
    return pattern;
}
// clang-format on

bool multimatch(boost::circular_buffer<std::string> container, const std::vector<std::string>& pattern_list, group_t& capture_groups, int anchor) {
    constexpr bool debug = true;
    std::vector<bre::smatch> results;
    std::string front = container.front();
    std::string back  = container.back();

    auto last_pattern  = wrap_pattern(pattern_list.back());
    auto first_pattern = wrap_pattern(pattern_list.front());
    if (anchor == '$' && !sregex_match(last_pattern, back)) {
        //*outs << fmt::format("failed to match {} against end: {}\n", last_pattern, back);
        return false;  // argh::parser("false");
    } else if (anchor == '^' && !sregex_match(first_pattern, front)) {
        //*outs << fmt::format("failed to match {} against start: {}\n", last_pattern, back);
        return false;
    }
    auto patterns         = _::map2(pattern_list, wrap_pattern);
    auto pattern_iter1    = patterns.begin();
    auto pattern_iter2    = ++patterns.begin();
    auto pattern          = *pattern_iter1++;
    auto pattern_peek     = *pattern_iter2++;
    auto pattern_end      = pattern_iter1 == patterns.end();
    auto pattern_peek_end = pattern_iter2 == patterns.end();
    auto pattern_count    = 0;
    auto pattern_size     = pattern_list.size();
    auto csize            = container.size();
    auto min              = 1;
    bool multi            = false;
    bool greedy;
    bool next_pattern = false;
    bool next_line    = false;
    bool restart      = false;
    std::map<size_t, std::vector<std::string>> repetitions;

    int i            = 0;
    std::string line = container[i];
    while (i + 1 < csize) {
        if (next_line) {
            // LOG_FUNC("next_line");
            next_line = 0;
            i += 1;
            if (i == csize) {
                // *outs << "reached end of container\n";
                return false;
            }
            line = container[i];
        }
        if (restart) {
            restart = 0;
            if (pattern_count) {
                // LOG_FUNC("restart");
                pattern_iter1    = patterns.begin();
                pattern_iter2    = ++patterns.begin();
                pattern          = *pattern_iter1++;
                pattern_peek     = *pattern_iter2++;
                pattern_end      = pattern_iter1 == patterns.end();
                pattern_peek_end = pattern_iter2 == patterns.end();
                pattern_count    = 0;
            }
        }
        if (next_pattern) {
            // LOG_FUNC("next_pattern");
            next_pattern = false;
            pattern_count += 1;
            if (pattern_end)
                return true;
            pattern = *pattern_iter1++;
            if (!pattern_peek_end)
                pattern_peek = *pattern_iter2++;
            pattern_end      = pattern_iter1 == patterns.end();
            pattern_peek_end = pattern_iter2 == patterns.end();

            multi  = false;
            greedy = true;
            min    = 1;  // optional = !min

            bool trailing_question = false;

            if (pystring::endswith(pattern, "?")) {
                trailing_question = true;
                pattern.resize(pattern.size() - 1);
            }

            if (pystring::endswith(pattern, "?")) {
                trailing_question = false;
                min               = 0;
                pattern.resize(pattern.size() - 1);
            }

            if (pystring::endswith(pattern, "**")) {
                min    = 0;
                multi  = true;
                greedy = !trailing_question;
                pattern.resize(pattern.size() - 2);
            }

            if (pystring::endswith(pattern, "++")) {
                min    = 1;
                multi  = true;
                greedy = !trailing_question;
                pattern.resize(pattern.size() - 2);
            }

            if (!multi)
                greedy = 0;
        }

        bre::smatch matches;
        bre::smatch matches_peek;

        // this can be optimised to only occur when new_pattern is set
        bre::sregex re = bre::sregex::compile(pattern);
        bool m         = bre::regex_search(line, matches, re);
        bool mpeek     = false;
        auto matchline = line;

        if (!pattern_end) {
            // this can be optimised to only run if the result will be used
            bre::sregex re_peek = bre::sregex::compile(pattern_peek);
            mpeek               = bre::regex_search(line, matches_peek, re_peek);
        }

        if (m) {
            repetitions[pattern_count].emplace_back(matchline);
#ifndef _DEBUG
            //template <typename Sub>
            //const_reference operator[](Sub const& sub) const {
            //    return this->at_(sub);
            //}

            //+++ std::vector<string_type> groupnames() const {
            //+++     std::vector<string_type> names;
            //+++     for (std::size_t i = 0; i < this->named_marks_.size(); ++i) {
            //+++         names.emplace_back(this->named_marks_[i].name_);
            //+++     }
            //+++     return names;
            //+++ }
            for (auto groupname : matches.groupnames()) {
                capture_groups[groupname].emplace_back(matches[groupname].str());
                // LOG("capture_group: {}: {}", groupname, matches[groupname].str());
            }
#endif
        }

        // LOG("[-----] m:{}, mpeek:{}, multi:{}, greedy:{}, min:{}, pattern_end:{} {}, count:{}, pattern:{}, line:{}", m, mpeek, multi, greedy, min, pattern_end, pattern_peek_end, repetitions[pattern_count].size(), pattern, line);
        if (!m) {
            if (repetitions[pattern_count].size() >= min) {
                next_pattern = 1;
                continue;
            }
            restart   = 1;
            next_line = 1;
            continue;
        }

        //[-----] m:true, mpeek:false, multi:false, min:1, pattern:xchg qword ptr \[rsp\], rbp, line:xchg qword ptr [rsp], rbp
        //[-----] m:false, mpeek:false, multi:false, min:1, pattern:xchg qword ptr \[rsp\], rbp, line:jmp 0x142fd556b
        //[multimatch] shouldn't reach this point???
        //[multimatch] fell through: i:31, csize:32, pattern_count:2, pattern_size:4
        //[multimatch] pattern_list[pattern_count]:xchg qword ptr \[rsp\], rbp

        // if matched this pattern and next pattern, then move to next pattern if appropriate
        if (m && mpeek && !greedy && repetitions[pattern_count].size() >= min) {
            next_pattern = 1;
            next_line    = 1;
            continue;
        }

        if (m && !greedy) {
            next_pattern = 1;
            next_line    = 1;
            continue;
        }

        next_line = 1;
    }
    // LOG("[-----] pattern_end:{} {}, count:{}, pattern:{}, line:{}", pattern_end, pattern_peek_end, repetitions[pattern_count].size(), pattern, line);
    if (pattern_end)
		return true;

    // *outs << fmt::format("[multimatch] shouldn't reach this point???\n");
    if (multi && repetitions[pattern_count].size() >= min) {
        // *outs << fmt::format("[multimatch] adding 1 for repeating pattern at end\n");
        pattern_count += 1;
    }
    if (debug) {
        // *outs << fmt::format("[multimatch] fell through: i:{}, csize:{}, pattern_count:{}, pattern_size:{}\n", i, csize, pattern_count, pattern_size);
        if (pattern_count < pattern_size) {
            // *outs << fmt::format("[multimatch] pattern_list[pattern_count]:{}\n", pattern_list[pattern_count]);
        }
    }

    if (pattern_count >= pattern_size) {
        if (debug) {
            // *outs << fmt::format("but saved by being at end of pattern_list\n");
        }

        return true;  // matches;
    }
    return false;
}
