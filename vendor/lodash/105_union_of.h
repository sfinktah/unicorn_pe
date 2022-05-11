#pragma once
#include "lodash_common.h"
namespace _ {
    // union_of
    template <typename ResultContainer, typename Container1, typename Container2>
    ResultContainer union_of(Container1 const& container1, Container2 const& container2)
    {
        std::vector<typename ResultContainer::value_type> left(container1.begin(), container1.end());
        std::vector<typename ResultContainer::value_type> right(container2.begin(), container2.end());
        std::sort(left.begin(), left.end());
        std::sort(right.begin(), right.end());

        std::vector<typename ResultContainer::value_type> union_result;
        std::set_union(left.begin(), left.end(), right.begin(), right.end(), std::back_inserter(union_result));
        return ResultContainer(union_result.begin(), union_result.end());
    }
}
