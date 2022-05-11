#pragma once
#include "lodash_common.h"
namespace _ {
    template <typename Container, typename Predicate>
    bool every(const Container& container, Predicate&& predicate)
    {
        return all(container, std::forward<Predicate>(predicate));
    }
}
