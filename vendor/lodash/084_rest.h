#pragma once
#include "lodash_common.h"
namespace _ {
    // rest/tail
    template <typename ResultContainer, typename Container>
    ResultContainer rest(Container& container)
    {
        return ResultContainer(++container.begin(), container.end());
    }

    template <typename ResultContainer, typename Container>
    ResultContainer rest(Container& container, int index)
    {
        typename Container::iterator begin = container.begin();
        std::advance(begin, index);
        return ResultContainer(begin, container.end());
    }
}
