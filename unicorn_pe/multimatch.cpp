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

extern std::ostream* outs;

bool multimatch(boost::circular_buffer<std::string> container, const std::vector<std::string>& pattern_list, group_t& capture_groups, int anchor) {
    auto pattern_transform = [](std::string pattern) {
        return pystring::replace(string_between("({", "}", pattern, STRING_BETWEEN_INCLUSIVE,
                                                [](std::string v) { return fmt::format("(?P<{}>", string_between("({", "}", v)); }),
                                 "\\x", "[0-9a-fA-F]");
    };

    constexpr bool debug = true;
    std::vector<bre::smatch> results;
    std::string back = container.back();

    auto last_pattern  = pattern_transform(pattern_list.back());
    auto first_pattern = pattern_transform(pattern_list.back());
    if (anchor == '$' && !sregex_match(last_pattern, back)) {
        //*outs << fmt::format("failed to match {} against end: {}\n", last_pattern, back);
        return false;  // argh::parser("false");
    } else if (anchor == '^' && !sregex_match(last_pattern, back)) {
        //*outs << fmt::format("failed to match {} against start: {}\n", last_pattern, back);
        false;
    }
    auto patterns      = _::map2(pattern_list, pattern_transform);
    auto pattern_iter1 = patterns.begin();
    auto pattern_iter2 = ++patterns.begin();
    auto pattern       = *pattern_iter1++;
    auto pattern_peek  = *pattern_iter2++;
    auto pattern_end   = pattern_iter2 == patterns.end();
    auto pattern_count = 0;
    auto pattern_size  = pattern_list.size();
    auto csize         = container.size();
    auto min           = 1;
    bool multi;
    bool greedy;
    bool next_pattern = false;
    bool next_line    = false;
    bool restart      = false;
    std::map<size_t, std::vector<std::string>> repetitions;

    int i            = 0;
    std::string line = container[i];
    while (i + 1 < csize) {
        if (next_line) {
            next_line = 0;
            i += 1;
            if (i == csize) {
                *outs << "reached end of container\n";
                return false;
            }
            line = container[i];
        }
        if (restart) {
            restart       = 0;
            pattern_iter1 = patterns.begin();
            pattern_iter2 = ++patterns.begin();
            pattern       = *pattern_iter1++;
            pattern_peek  = *pattern_iter2++;
            pattern_end   = pattern_iter2 == patterns.end();
            pattern_count = 0;
        }
        if (next_pattern) {
            next_pattern = false;
            if (pattern_end)
                return true;
            pattern      = *pattern_iter1++;
            pattern_peek = *pattern_iter2++;
            pattern_end  = pattern_iter2 == patterns.end();
            pattern_count += 1;

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

        *outs << fmt::format("[-----] m:{}, mpeek:{}, multi:{}, min:{}, pattern:{}, line:{}\n", m, mpeek, multi, min, pattern, line);
        if (!m) {
            if (repetitions[pattern_count].size() >= min) {
                next_pattern = 1;
                continue;
            }
            restart = 1;
            continue;
        }
        // if matched this pattern and next pattern, then move to next pattern if appropriate
        if (m && mpeek && !greedy && repetitions[pattern_count].size() >= min) {
            next_pattern = 1;
            next_line    = 1;
            continue;
        }

#ifndef _DEBUG
        for (auto groupname : matches.groupnames()) {
            capture_groups[groupname].emplace_back(matches[groupname]);
        }
#endif

        repetitions[pattern_count].emplace_back(matchline);
        next_line = 1;
    }
    *outs << fmt::format("[multimatch] shouldn't reach this point???\n");

    if (multi && repetitions[pattern_count].size() >= min) {
        *outs << fmt::format("[multimatch] adding 1 for repeating pattern at end\n");
        pattern_count += 1;
    }
    if (debug) {
        *outs << fmt::format("[multimatch] fell through: i:{}, csize:{}, pattern_count:{}, pattern_size:{}\n", i, csize, pattern_count, pattern_size);
        if (pattern_count < pattern_size) {
            *outs << fmt::format("[multimatch] pattern_list[pattern_count]:{}\n", pattern_list[pattern_count]);
        }
    }

    if (pattern_count >= pattern_size) {
        if (debug) {
            *outs << fmt::format("but saved by being at end of pattern_list\n");
        }

        return true;  // matches;
    }
    return false;
}
