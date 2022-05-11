#pragma once
#include "043_any.h"
#include "lodash_common.h"
namespace _ {
    template <typename Container, typename Predicate>
    bool some(const Container& container, Predicate&& predicate)
    {
        return any(container, std::forward<Predicate>(predicate));
    }
}
