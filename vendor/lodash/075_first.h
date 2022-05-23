#pragma once
#include "helper.h"
namespace _ {
	// lodash: return first element of array or undefined
    template <typename Container>
    typename Container::value_type first(const Container& container) {
        return *container.cbegin();
    }

	// lodash: return first element of array or nullopt
    template <typename Container>
    typename std::optional<typename Container::value_type> firstOpt(const Container& container) {
        if (container.cbegin() != container.cend()) {
			return *container.begin();
        }
		return std::nullopt;
    }

    // first n elements
    template <typename ResultContainer, typename Container>
    ResultContainer first(Container& container, int count) {
        typename Container::iterator end = container.begin();
        std::advance(end, count);
        return ResultContainer(container.begin(), end);
    }

    /// <summary>Similar to <paramref="first" /> but returns an array of between 0 and 1 elements</summary>
    /// <param name="container">The container.</param>
    /// <returns></returns>
    template <typename ResultContainer, typename Container>
    ResultContainer first_jquery(Container& container) {

        ResultContainer result;
        for (auto i = container.begin(); i != container.end(); ++i) {
            helper::add_to_container(result, *i);
            break;
        }
        return result;
    }
}  // namespace _
