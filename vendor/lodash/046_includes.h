#pragma once
#include "lodash_common.h"
#include "045_contains.h"

namespace _ {
    template <typename Container>
    bool includes(const Container& container, const typename Container::value_type& value)
    {
        return contains(container, value);
    }
}
