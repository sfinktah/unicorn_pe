#pragma once
#include "helper.h"
namespace _ {

    // first/head
    template <typename Container>
    typename Container::iterator first(Container& container)
    {
        return container.begin();
    }

    // first n elements
    template <typename ResultContainer, typename Container>
    ResultContainer first(Container& container, int count)
    {
        typename Container::iterator end = container.begin();
        std::advance(end, count);
        return ResultContainer(container.begin(), end);
    }

    /// <summary>Similar to <paramref="first" /> but returns an array of between 0 and 1 elements</summary>
    /// <param name="container">The container.</param>
    /// <returns></returns>
    template <typename ResultContainer, typename Container>
    ResultContainer first_jquery(Container& container)
    {

        ResultContainer result;
        for (auto i = container.begin(); i != container.end(); ++i) {
            helper::add_to_container(result, *i);
            break;
        }
        return result;
    }
}
