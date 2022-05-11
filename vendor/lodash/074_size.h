#pragma once
#include "lodash_common.h"
namespace _ {
    // size
    template <typename Container>
    int size(const Container& container)
    {
        return container.size();
    }
}
