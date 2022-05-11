#pragma once
#include "lodash_common.h"
namespace _ {
    // compare
    /// <summary>Compares the contents of two arrays</summary>
    /// <param name="container1">container1.</param>
    /// <param name="container2">container2.</param>
    /// <returns>-1, 0 or 1 as per <c>strcmp</c></returns>
    /// <remarks>not an underscore or lodash function</remarks>
    template <typename Container1, typename Container2>
    int compare(const Container1& container1, const Container2& container2)
    {
        typename Container1::const_iterator left  = container1.begin();
        typename Container2::const_iterator right = container2.begin();
        while (left != container1.end() && right != container2.end()) {
            if (*left != *right) return *left < *right ? -1 : 1;

            left++, right++;
        }

        // shorter container "win" (is less than)
        return
            // right is longer, ergo left is less
            (right != container2.end()) ? -1
                                        :
                                        // left is longer, ergo right is less
                (left != container1.end()) ? +1 :
                                           // both of equal length, ergo equal
                    0;
    }
}
