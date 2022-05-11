#pragma once
#include "lodash_common.h"
namespace _ {
    // all/every
    template <typename Container, typename Predicate>
    bool all(Container& container, Predicate&& predicate)
    {
        return std::all_of(std::begin(container), std::end(container), std::forward<Predicate>(predicate));
    }
}
