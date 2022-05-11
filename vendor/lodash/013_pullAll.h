#pragma once
#include "lodash_common.h"
namespace _ {
    // pullAll (lodash) - This method is like _.pull except that it accepts an array of values to remove.
    // Note: Unlike _.difference, this method mutates array.
    template <typename Container1, typename Container2>
    void pullAll(Container1& container, Container2 const& values)
    {

        // Hmmm.... if it's similar to difference, maybe we could leverage the existing `difference` function...
        // However, that function looks complicated. Lets leverage `contains` instead. It's possibly less
        // efficient that using `difference` but simplicity wins today.
        for (auto i = container.begin(); i != container.end();) contains(values, *i) ? i = container.erase(i) : ++i;
    }
}
