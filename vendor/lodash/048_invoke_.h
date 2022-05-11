#pragma once
#include "lodash_common.h"
namespace _ {
    template <typename ResultContainer, typename Container, typename Function>
    typename std::enable_if<std::is_void<ResultContainer>::value, void>::type invoke(const Container& container, Function function)
    {
        each(container, std::mem_fn(std::forward<Function>(function)));
    }
}
