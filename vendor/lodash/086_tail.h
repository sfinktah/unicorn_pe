#pragma once
#include "lodash_common.h"
#include "084_rest.h"

namespace _ {
    template <typename ResultContainer, typename Container>
    ResultContainer tail(Container& container)
    {
        return rest<ResultContainer>(container);
    }

    template <typename ResultContainer, typename Container>
    ResultContainer tail(Container& container, int index)
    {
        return rest<ResultContainer>(container, index);
    }
}
