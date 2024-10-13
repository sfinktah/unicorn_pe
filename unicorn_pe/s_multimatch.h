#pragma once
#if USE_BOOST
#include "util.hpp"
#include "FuncTailInsn.h"
#include <boost/circular_buffer.hpp>
using group_t = std::map<std::string, std::vector<std::string>>;
using vector_fti = std::vector<FuncTailInsn>;
using map_fti = std::map<std::string, vector_fti>;
bool multimatch(const boost::circular_buffer<FuncTailInsn>& container, const std::vector<std::string>& pattern_list, group_t& capture_groups, map_fti& insn_groups, vector_fti& insn_list, int anchor);
std::string wrap_replacement(std::string pattern);
std::string wrap_pattern(std::string pattern, vector_string& groupnames, group_t& capture_groups, int format = 0);
std::string color_disasm(std::string pattern);
#endif
