#pragma once
using group_t = std::map<std::string, std::vector<std::string>>;
bool multimatch(boost::circular_buffer<std::string> container, const std::vector<std::string>& pattern_list, group_t& capture_groups, int anchor);
