#pragma once
#include "lodash_common.h"
#include <map>

namespace _ {
    // group_by
    template <typename Key, typename Container, typename Function>
    std::multimap<Key, typename Container::value_type> group_by(const Container& container, Function function) {
        std::multimap<Key, typename Container::value_type> result;
        for (auto i = container.begin(); i != container.end(); ++i) {
            result.insert(std::pair<Key, typename Container::value_type>(function(*i), *i));
        }
        return result;
    }
}  // namespace _