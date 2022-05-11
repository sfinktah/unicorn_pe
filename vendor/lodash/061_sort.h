#pragma once
#include "lodash_common.h"
#include "helper.h"
namespace _ {
    // sort_by
    template <typename Container, typename Function>
    std::vector<typename Container::value_type> sortBy(const Container& container, Function function)
    {
        return sort_by(container, [=](const auto& left, const auto& right) { 
            return function(left) < function(right); 
        });
    }

    template <typename Container, typename Function>
    std::vector<typename Container::value_type> sort_by(const Container& container, Function function)
    {
        std::vector<typename Container::value_type> to_sort(container.begin(), container.end());
        std::sort(to_sort.begin(), to_sort.end(), function);
        return to_sort;
    }

    template <typename Container>
    void sort_mutate(Container& container)
    {
        std::sort(container.begin(), container.end());
    }

    template <typename Container, typename Function>
    void sortBy_mutate(Container& container, Function iteratee)
    {
        std::sort(container.begin(), container.end(), [&](const auto& lhs, const auto&rhs) {
            return iteratee(lhs) < iteratee(rhs);
        });
    }
    // sorted_index
    template <typename Container>
    typename Container::iterator sorted_index(const Container& container, typename Container::value_type const& value)
    {
        return std::upper_bound(container.begin(), container.end(), value);
    }

    template <typename Container, typename Function>
    typename Container::iterator sorted_index(
        const Container& container, typename Container::value_type const& value, Function function)
    {
        return std::upper_bound(
            container.begin(), container.end(), value,
            helper::TransformCompare<typename Container::value_type, Function>(function));
    }
}
