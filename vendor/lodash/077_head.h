#pragma once
#include "075_first.h"
namespace _ {
    template <typename Container>
    typename Container::iterator head(Container& container)
    {
        return first(container);
    }
    template <typename ResultContainer, typename Container>
    ResultContainer head(Container& container, int count)
    {
        return first<ResultContainer>(container, count);
    }
}
