#pragma once
#include "lodash_common.h"
#include "helper.h"
namespace _ {
    /// <summary>Perumtate the specified containers.</summary>
    /// <param name="container1">container 1.</param>
    /// <param name="container2">container 2.</param>
    /// <param name="iteratee">The iteratee, iteratee(a, b)</param>
    /// <returns>Unique permutations of the two containers passed through iteratee</returns>
    template <typename ResultContainer, typename Container1, typename Container2, typename Function>
    ResultContainer permutate(const Container1& container1, const Container2& container2, Function iteratee)
    {
        ResultContainer result;
        for (typename Container1::size_type i = 0; i < container1.size(); ++i) {
            for (typename Container2::size_type j = 0; j < container2.size(); ++j) {
                helper::add_to_container(result, iteratee(container1[i], container2[j]));
            }
        }
        return result;
    }
}
