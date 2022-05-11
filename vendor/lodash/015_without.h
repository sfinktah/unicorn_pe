#pragma once
#include "lodash_common.h"
#include "014_filter.h"

namespace _ {
    // without - Creates an array excluding all given values using SameValueZero for equality comparisons.
    // Note: Unlike `pull`, this method returns a new array.
    template <typename ResultContainer, typename Container>
    ResultContainer without(Container const& container, typename Container::value_type const& value)
    {
        // sorry, you'll have to work out your own checks for C++17
        return filter<ResultContainer>(container, [value](const auto& _) {
            return value != _;
            // return std::not_equal_to<typename Container::value_type>(_, value);
        });
#if 0
        // deprecated in c++11, removed in c++17
        return filter<ResultContainer>(
            container, std::bind2nd(std::not_equal_to<typename Container::value_type>(), value));
#endif
    }
}
