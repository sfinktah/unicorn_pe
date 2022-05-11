#pragma once
#include "lodash_common.h"
#include "024_keys.h"
namespace _ {
    template <typename Container>
    typename std::vector<typename Container::value_type> vectorize(const Container& container)
    {
        return values<std::vector<typename Container::value_type>>(container);
    }
}
