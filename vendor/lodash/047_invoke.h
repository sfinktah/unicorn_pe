#pragma once
#include "lodash_common.h"
namespace _ {
    // invoke
    template <typename ResultContainer, typename Container, typename Function>
    typename std::enable_if<!std::is_void<ResultContainer>::value, ResultContainer>::type invoke(
        const Container& container, Function&& function)
    {
        return map(container, std::mem_fn(std::forward<Function>(function)));
    }
}
