#pragma once
#ifdef USE_BOOST
#include <deque>
#include <map>
#include <string>
#include <utility>
#include <vector>
#include "s_multimatch.h"
#include <boost/xpressive/xpressive.hpp>
#include "FuncTailInsn.h"
namespace bre = boost::xpressive;

// using group_t = std::map<std::string, std::vector<std::string>>;
using vector_fti_index = std::vector<size_t>;
using map_fti_index = std::map<std::string,vector_fti_index>;

static std::string empty_string;

class MultiMatch
{
public:
	MultiMatch(std::string comment, const std::vector<std::string>& patterns, const std::vector<std::string>& replacements) : comment(std::move(comment)) {
        for (const auto& pattern : patterns) {
            match_patterns.emplace_back(wrap_pattern(pattern, groupnames, capture_groups));
        }
        for (const auto& pattern : replacements) {
            match_replacements.emplace_back(wrap_replacement(pattern));
        }
	}

	MultiMatch(std::string comment, const std::vector<std::string>& patterns, std::function<std::string(void*, group_t, map_fti_index, vector_fti_index)> replFunc) : comment(std::move(comment)), match_replFunc(std::move(replFunc)) {
        for (const auto& pattern : patterns) {
            match_patterns.emplace_back(wrap_pattern(pattern, groupnames, capture_groups));
        }
	}

    void match_complete();

    bool test(std::vector<FuncTailInsn>& instructions, size_t index, const FuncTailInsn& fti);

    bool match(size_t index, const std::string& pattern, const std::string& line);

    [[nodiscard]] const std::string& get_current_pattern() const {
        if (insn_list.size() < match_patterns.size()) {
            return match_patterns[insn_list.size()];
        }
        return empty_string;
	}

    [[nodiscard]] size_t get_current_pattern_index() const {
        return insn_list.size();
	}

    std::string comment;
    // capture_groups, insn_groups, insn_list
    // group_t, map_fti_index, vector_fti_index
    group_t capture_groups;
    map_fti_index insn_groups;
    vector_fti_index insn_list;
    std::vector<bre::smatch> results;
    std::vector<std::string> groupnames;

	//std::deque<size_t> match_indexes;
	//std::deque<group_t> match_groups;
	std::vector<std::string> match_patterns;
	std::vector<std::string> match_replacements;
    // capture_groups, insn_groups, insn_list
    std::function<std::string(void*, group_t, map_fti_index, vector_fti_index)> match_replFunc;
};

#endif
