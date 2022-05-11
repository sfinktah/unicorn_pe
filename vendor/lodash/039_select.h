#pragma once
#include "lodash_common.h"
#include "014_filter.h"

namespace _ {
    template <typename ResultContainer, typename Container, typename Predicate>
    ResultContainer select(const Container& container, Predicate predicate)
    {
        return filter<ResultContainer>(container, predicate);
    }
}
