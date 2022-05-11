#pragma once
#include "lodash_common.h"
#include "helper.h"
namespace _ {
    /// <summary>Returns an array of the elements in container1 and container2 that match, terminating at the first
    /// mismatch</summary>
    /// <param name="container1">container1.</param>
    /// <param name="container2">container2.</param>
    /// <returns></returns>
    /// <remarks>not an underscore or lodash function</remarks>
    template <typename ResultContainer, typename Container1, typename Container2>
    ResultContainer match_consecutive(Container1 const& container1, Container2 const& container2)
    {
        ResultContainer result;

        typename Container1::const_iterator left  = container1.begin();
        typename Container2::const_iterator right = container2.begin();
        while (left != container1.end() && right != container2.end()) {
            if (*left != *right) break;
            helper::add_to_container(result, *left);

            left++, right++;
        }

        return result;
    }
}
