#pragma once
#include "lodash_common.h"
namespace _ {
    // initial
    template <typename ResultContainer, typename Container>
    ResultContainer initial(Container& container)
    {
        typename Container::iterator end = container.begin();
        std::advance(end, container.size() - 1);
        return ResultContainer(container.begin(), end);
    }

    template <typename ResultContainer, typename Container>
    ResultContainer initial(Container& container, int n)
    {
        typename Container::iterator end = container.begin();
        std::advance(end, container.size() - n);
        return ResultContainer(container.begin(), end);
    }
}
