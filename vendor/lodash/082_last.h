#pragma once
#include "lodash_common.h"
namespace _ {
    // last
    template <typename Container>
    typename Container::iterator last(Container& container)
    {
        typename Container::iterator last = container.begin();
        std::advance(last, container.size() - 1);
        return last;
    }

    template <typename ResultContainer, typename Container>
    ResultContainer last(Container& container, int n)
    {
        typename Container::iterator begin = container.begin();
        std::advance(begin, container.size() - n);
        return ResultContainer(begin, container.end());
    }
}
