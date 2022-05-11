#pragma once
#include "lodash_common.h"
#include "helper.h"
namespace _ {
    // reject
    template <typename ResultContainer, typename Container, typename Predicate>
    ResultContainer reject(const Container& container, Predicate predicate)
    {
        ResultContainer result;
        for (auto i = container.begin(); i != container.end(); ++i) {
            if (!predicate(*i)) {
                helper::add_to_container(result, *i);
            }
        }
        return result;
    }
}
