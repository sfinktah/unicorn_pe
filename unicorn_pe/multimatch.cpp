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
#include "FuncTailInsn.h"
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

using vector_string = std::vector<std::string>;
// clang-format off
static std::string wrap_pattern(std::string pattern, vector_string& groupnames, group_t& capture_groups, int format = 0) {
    pattern = pystring::replace(pattern, R"(\x)",                             R"([0-9a-fA-F])");
    pattern = pystring::replace(pattern, R"(\w\+)",                           R"(\w+)");
    pattern = pystring::replace(pattern, R"([::address::])",                  R"((?:(?:0x|loc_)?[0-9a-fA-F]{9,}))");
    pattern = pystring::replace(pattern, R"([::r64::])",                      R"((?:\br(?:(?:[a-d])x|(?:[sb])p|(?:[sd])i|(?:8|9|1[0-5]))\b))");
    pattern = pystring::replace(pattern, R"([::r64-8::])",                    R"((?:\br(?:(?:[a-d])x|(?:[sb])p|(?:[sd])i)\b))");
    pattern = pystring::replace(pattern, R"([::r32::])",                      R"((?:\b(?:e(?:(?:[a-d])x|(?:[sb])p|(?:[sd])i)|r(?:8|9|1[0-5])d)\b))");
    pattern = pystring::replace(pattern, R"([::r32-8::])",                    R"((?:\b(?:e(?:(?:[a-d])x|(?:[sb])p|(?:[sd])i))\b))");
	if (format == 1) {
		try {
			pattern = regex_replace(pattern, std::regex(R"(\$\{[a-zA-Z]\w+\})"), [&](const std::smatch& match) -> std::string { 
				std::string name = string_between("{", "}", match[0].str());
				return fmt::format("(?P={})", name);
			});
		} catch (std::regex_error e) {
			LOG_FUNC("%s (%s)", pattern.c_str(), e.what());
			return 0;
		}
	} else {
		try {
			pattern = regex_replace(pattern, std::regex(R"(\$\{[a-zA-Z]\w+\})"), [&](const std::smatch& match) -> std::string { 
				std::string name = string_between("{", "}", match[0].str());
				if (capture_groups.count(name))
					return capture_groups[name][0]; 
				LOG("Couldn't find capture group '{}'", name);
				return "XXX";
			});
		} catch (std::regex_error e) {
			LOG_FUNC("%s (%s)", pattern.c_str(), e.what());
			return 0;
		}
	}
    pattern = string_between("({", "}", pattern, STRING_BETWEEN_INCLUSIVE,
                                                [&](std::string v) { 
		std::string name = string_between("({", "}", v);
		if (!_::contains(groupnames, name)) 
			groupnames.emplace_back(name);
		return fmt::format("(?P<{}>", name); 
	});
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

bool multimatch(const boost::circular_buffer<FuncTailInsn>& container, const std::vector<std::string>& pattern_list, group_t& _capture_groups, map_fti& _insn_groups, vector_fti& _insn_list, int anchor) {
    constexpr bool debug = true;
    group_t capture_groups;
    map_fti insn_groups;
    vector_fti insn_list;
    std::vector<bre::smatch> results;
    std::vector<std::string> groupnames;

    auto get_text = [&](const FuncTailInsn& fti) -> std::string { return fti.text(); };

    {
        auto quick_test_pattern = pystring::join(";", _::map _VECTOR(std::string)(pattern_list, [&](const std::string& p) { return wrap_pattern(p, groupnames, capture_groups, 1); })) + (char)(anchor);
        auto quick_test_string  = pystring::join(";", _::map _VECTOR(std::string)(container, get_text));  // [&](const std::string& p) { return wrap_pattern(p, groupnames, capture_groups, 1); }));
        bre::smatch matches;
        bre::sregex re  = bre::sregex::compile(quick_test_pattern);
        bool quick_test = bre::regex_search(quick_test_string, matches, re);
        if (quick_test) {
            LOG("quick_test_matched: {}", quick_test_pattern);
            LOG("quick_test_string : {}", quick_test_string);
        } else {
            return false;
        }
    }

    //std::string front  = get_text(container.front());
    //std::string back   = get_text(container.back());
    //auto last_pattern  = wrap_pattern(pattern_list.back(), groupnames, capture_groups);
    //auto first_pattern = wrap_pattern(pattern_list.front(), groupnames, capture_groups);
    //if (anchor == '$' && !sregex_match(last_pattern, back)) {
    //    //*outs << fmt::format("failed to match {} against end: {}\n", last_pattern, back);
    //    return false;  // argh::parser("false");
    //} else if (anchor == '^' && !sregex_match(first_pattern, front)) {
    //    //*outs << fmt::format("failed to match {} against start: {}\n", last_pattern, back);
    //    return false;
    //}
    auto pattern_iter1     = pattern_list.cbegin();
    auto pattern_iter2     = ++pattern_list.cbegin();
    auto pattern           = wrap_pattern(*pattern_iter1++, groupnames, capture_groups);
    auto pattern_peek      = wrap_pattern(*pattern_iter2++, groupnames, capture_groups);
    auto pattern_end       = pattern_iter1 == pattern_list.end();
    auto pattern_peek_end  = pattern_iter2 == pattern_list.end();
    auto pattern_count     = 0;
    auto pattern_list_size = pattern_list.size();
    auto csize             = container.size();
    auto min               = 1;
    bool multi             = false;
    bool greedy            = false;
    bool next_pattern      = false;
    bool next_line         = false;
    bool restart           = false;
    std::map<size_t, std::vector<std::string>> repetitions;

    int i            = 0;
    std::string line = get_text(container[i]);
    while (i + 1 < csize) {
        if (next_line) {
            // LOG_FUNC("next_line");
            next_line = 0;
            i += 1;
            if (i == csize) {
                // *outs << "reached end of container\n";
                break;
            }
            line = get_text(container[i]);
        }
        if (restart) {
            restart = 0;
            capture_groups.clear();
            insn_groups.clear();
            insn_list.clear();
            if (pattern_count) {
                // LOG_FUNC("restart");
                pattern_iter1    = pattern_list.cbegin();
                pattern_iter2    = ++pattern_list.cbegin();
                pattern          = wrap_pattern(*pattern_iter1++, groupnames, capture_groups);
                pattern_peek     = wrap_pattern(*pattern_iter2++, groupnames, capture_groups);
                pattern_end      = pattern_iter1 == pattern_list.end();
                pattern_peek_end = pattern_iter2 == pattern_list.end();
                pattern_count    = 0;
            }
        }
        if (next_pattern) {
            // LOG_FUNC("next_pattern");
            next_pattern = false;
            pattern_count += 1;
            if (pattern_end)
                break;
            pattern = wrap_pattern(*pattern_iter1++, groupnames, capture_groups);
            if (!pattern_peek_end)
                pattern_peek = wrap_pattern(*pattern_iter2++, groupnames, capture_groups);
            pattern_end      = pattern_iter1 == pattern_list.end();
            pattern_peek_end = pattern_iter2 == pattern_list.end();

            multi  = false;
            greedy = false;
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

        // TODO: this shouldn't necessarily always be called, e.g. in non-greedy mode
        // a match may be rejected for a later match.
        if (m) {
            repetitions[pattern_count].emplace_back(matchline);
            insn_list.emplace_back(container[i]);
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
            for (auto name : matches.groupnames()) {
#ifdef _DEBUG
                LOG("updating capture group '{}'", name);
#endif
                capture_groups[name].emplace_back(matches[name].str());
                insn_groups[name].emplace_back(container[i]);
                //for (auto& pattern : patterns) {
                //    pattern = wrap_pattern(pattern, groupnames, capture_groups);
                //}
                // LOG("capture_group: {}: {}", name, matches[name].str());
            }
#else
            for (auto name : groupnames) {
                try {
                    if (matches[name]) {
                        LOG("updating capture group '{}'", name);
                        capture_groups[name].emplace_back(matches[name].str());
                        insn_groups[name].emplace_back(container[i]);
                    }
                } catch (boost::xpressive::regex_error) {
                }
            }
#endif
        }

#ifdef _DEBUG
        if (m)
            LOG("[-----] m:{}, mpeek:{}, multi:{}, greedy:{}, min:{}, pattern_end:{} {}, count:{}, pattern:{}, line:{}", m, mpeek, multi, greedy, min, pattern_end, pattern_peek_end, repetitions[pattern_count].size(), pattern, line);
#endif
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
        //[multimatch] fell through: i:31, csize:32, pattern_count:2, pattern_list_size:4
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
    if (pattern_end && pattern_count + 1 == pattern_list_size && i + 1 == csize) {
        //LOG("[-----] pattern_end:{} {}, pattern_count:{}/{}, line:{}/{}", pattern_end, pattern_peek_end, pattern_count, pattern_list_size, i, csize);
        std::swap(capture_groups, _capture_groups);
        std::swap(insn_groups, _insn_groups);
        std::swap(insn_list, _insn_list);
        return true;
    }
	//LOG("[-----] pattern_end:{} {}, pattern_count:{}/{}, line:{}/{}", pattern_end, pattern_peek_end, pattern_count, pattern_list_size, i, csize);

    // *outs << fmt::format("[multimatch] shouldn't reach this point???\n");
    //if (multi && repetitions[pattern_count].size() >= min) {
    //    // *outs << fmt::format("[multimatch] adding 1 for repeating pattern at end\n");
    //    pattern_count += 1;
    //}
    //if (debug) {
    //    // *outs << fmt::format("[multimatch] fell through: i:{}, csize:{}, pattern_count:{}, pattern_list_size:{}\n", i, csize, pattern_count, pattern_size);
    //    if (pattern_count < pattern_list_size) {
    //        // *outs << fmt::format("[multimatch] pattern_list[pattern_count]:{}\n", pattern_list[pattern_count]);
    //    }
    //}

    //if (pattern_count >= pattern_list_size) {
    //    if (debug) {
    //         *outs << fmt::format("but saved by being at end of pattern_list\n");
    //    }

    //    return true;  // matches;
    //}
    return false;
}

#if 0
							const int count = 15;
							static const asmjit::GpReg regs[] =
							{
								asmjit::host::rax, asmjit::host::rbx, asmjit::host::rcx, asmjit::host::rdx, asmjit::host::rsi,
								asmjit::host::rdi, asmjit::host::r8,  asmjit::host::r9,  asmjit::host::r10, asmjit::host::r11,
								asmjit::host::r12, asmjit::host::r13, asmjit::host::r14, asmjit::host::r15, asmjit::host::rbp
							};
							static const std::array<std::string, 16> register_order 
								{ "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
							static const std::array<asmjit::GpReg, 16>
							gp_regs { asmjit::host::rax, asmjit::host::rcx,
								asmjit::host::rdx, asmjit::host::rbx,
								asmjit::host::rsp, asmjit::host::rbp,
								asmjit::host::rsi, asmjit::host::rdi,
								asmjit::host::r8, asmjit::host::r9,
								asmjit::host::r10, asmjit::host::r11,
								asmjit::host::r12, asmjit::host::r13,
								asmjit::host::r14, asmjit::host::r15 };
							auto jmpToHook  = AsmFactory::GetAssembler(AsmFactory::asm64);
							//(*jmpToHook)->jmp( (asmjit::Ptr)&HookHandler<Fn, C>::Handler );
#endif
