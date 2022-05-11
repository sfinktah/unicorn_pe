#pragma once
#include "lodash_common.h"
#include "036_find.h"
namespace _ {
    // contains (alias includes)
    template <typename Container, typename T>
    bool contains(const Container& container, T&& valueOrPredicate)
    {
        return find(std::begin(container), std::end(container), std::forward<T>(valueOrPredicate)) != container.end();
    }
}

namespace _ {
    // `contains` that accepts `Container::value_type = std::pair<K, V>`
    template <typename Container, typename Value>
    bool containsMap(const Container& container, Value value)
    {
        return indexOfMap(container, value) != -1;
    }
}
