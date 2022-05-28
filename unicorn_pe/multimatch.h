#pragma once
#if USE_BOOST
using group_t = std::map<std::string, std::vector<std::string>>;
using vector_fti = std::vector<FuncTailInsn>;
using map_fti = std::map<std::string, vector_fti>;
bool multimatch(const boost::circular_buffer<FuncTailInsn>& container, const std::vector<std::string>& pattern_list, group_t& capture_groups, map_fti& insn_groups, vector_fti& insn_list, int anchor);
#endif
