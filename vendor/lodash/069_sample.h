#pragma once
#include "lodash_common.h"
#include "018_tuple_values.h"
#include "021_values.h"
#include "067_baseRandom.h"

namespace _ {
    template <typename Container>
    typename Container::value_type arraySample(const Container& container)
    {
        auto vector                 = values<std::vector<typename Container::value_type>>(container);
        auto                 length = std::size(vector);
        return vector[baseRandom<size_t>(0, length - 1)];
    }


    template <typename Container>
    typename Container::value_type baseSample(const Container& container)
    {
        auto values                       = tuple_values _VECTOR(typename Container::value_type)(container);
        auto                       length = std::size(values);
        return values[baseRandom(0, length - 1)];
    }

    // Gets a random element from `collection`.
    template <typename Container>
    typename Container::value_type sample(const Container& container)
    {
        if
            constexpr(traits::has_mapped_type<Container>::value) { return baseSample(container); }
        else {
            return arraySample(container);
        }
    }
}
