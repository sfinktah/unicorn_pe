#pragma once
#include "lodash_common.h"
namespace _ {
    template <typename ResultContainer, typename Container, typename Function>
    ResultContainer collect(const Container& container, Function&& function)
    {
        return map<ResultContainer>(container, std::forward<Function>(function));
    }
}
