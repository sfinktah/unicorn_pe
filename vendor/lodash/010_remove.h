#pragma once
#include "lodash_common.h"
namespace _ {
    // remove (lodash) - Removes all elements from array that predicate returns truthy for and returns an array of the removed
    // elements.
    // Note: Unlike _.filter, this method mutates array. Use _.pull to pull elements from an array by value.
    // Note: for ease of use, this function does not return removed elements, use `removeAndReturn` instead
    template <typename Container, typename Function>
    void remove(Container& container, Function&& function)
    {
        for (auto i = container.begin(); i != container.end();) function(*i) ? i = container.erase(i) : ++i;
    }

    // remove (lodash) - Removes all elements from array that predicate returns truthy for and returns an array of the removed
    // elements.
    // Note: Unlike _.filter, this method mutates array. Use _.pull to pull elements from an array by value.
    template <typename ResultContainer, typename Container, typename Function>
    ResultContainer removeAndReturn(Container& container, Function function)
    {
        ResultContainer result;
        for (auto i = container.begin(); i != container.end();) {
            if (function(*i))
                helper::add_to_container(result, *i), i = container.erase(i);
            else
                ++i;
        }
        return result;
    }
}
