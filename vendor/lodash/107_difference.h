#pragma once
#include "lodash_common.h"
#include "045_contains.h"
namespace _ {
    // difference
    /**
     * \brief Similar to without, but returns the values from array that are not present in array2 [the other arrays.]
     * \tparam Container1 
     * \tparam Container2 
     * \param array 
     * \param array2 
     * \return 
     */
    template <typename Container1, typename Container2> // enable_if value_types are the same after decay
    auto difference(Container1 const& array, Container2 const& array2)
    {
        std::vector<typename Container1::value_type> left(array.begin(), array.end());
        std::vector<typename Container2::value_type> right(array2.begin(), array2.end());
        std::sort(left.begin(), left.end());
        std::sort(right.begin(), right.end());

        std::vector<typename Container1::value_type> union_result;
        std::set_difference(left.begin(), left.end(), right.begin(), right.end(), std::back_inserter(union_result));
        return std::vector<typename Container1::value_type>(union_result.begin(), union_result.end());
    }

    // difference2 - because `difference` doesn't work for all types
    template <typename ResultContainer, typename Container1, typename Container2>
    ResultContainer difference2(Container1 const& container1, Container2 const& container2)
    {
        return filter<ResultContainer>(container1, [&](const auto& value) { return !contains(container2, value); });
    }
}
