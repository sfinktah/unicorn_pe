#include "MultiMatch.h"
#ifdef USE_BOOST
class PeEmulation;

void MultiMatch::match_complete() {
    LOG("    \033[31mmatch complete: \033[32m{}\033[39m", comment);
    insn_list.clear();
}

bool MultiMatch::test(std::vector<FuncTailInsn>& instructions, size_t index, const FuncTailInsn& fti) {
    auto current_pattern_index = get_current_pattern_index();
    auto current_pattern = get_current_pattern();
    auto rv              = match(index, current_pattern, fti.text());
    if (rv) {
        if (insn_list.size() >= match_patterns.size()) {
            match_complete();
        }
    }
    else {
        insn_list.clear();
        // if we just reset, retry again at start
        if (current_pattern_index) {
            rv = match(index, get_current_pattern(), fti.text());
        }
    }
    return rv;
}

bool MultiMatch::match(size_t index, const std::string& pattern, const std::string& line) {
    bre::smatch matches;

    // this can be optimised to only occur when new_pattern is set
    bre::sregex re = bre::sregex::compile(pattern);

    // TODO: this shouldn't necessarily always be called, e.g. in non-greedy mode
    // a match may be rejected for a later match.
    if (bre::regex_search(line, matches, re)) {
        LOG("    matched: \033[33m{}\033[39m in \033[32m{}\033[39m", matches[0].str(), comment);
        insn_list.emplace_back(index);
#ifndef _DEBUG
        for (const auto& name : matches.groupnames()) {
            LOG("    updated capture group \033[35m{}\033[39m with \033[36m{}\033[39m for \033[32m{}\033[39m", name, matches[name].str(), comment);
            capture_groups[name].emplace_back(matches[name].str());
            insn_groups[name].emplace_back(index);
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
        return true;
    }
    return false;
}
#endif

