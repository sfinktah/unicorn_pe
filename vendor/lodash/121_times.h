#pragma once
#include "lodash_common.h"
#include "117_range.h"
#include "008_map.h"

namespace _ {
    /// <summary>Invokes the iteratee n times, returning an array of the results of each invocation. The iteratee is invoked with
    /// one argument; (index).</summary>
    /// <param name="n">The number of times to invoke <paramref="iteratee" /></param>
    /// <param name="iteratee">The iteratee, iteratee(size_t n)</param>
    /// <returns>Array of the returned values</returns>
    template <typename ResultContainer, typename Function>
    ResultContainer times(size_t n, Function iteratee)
    {
        auto accum = range<size_t>(n);
        return map<ResultContainer>(accum, iteratee);
    }

    /// <summary>The same as `times` but doesn't collate return values or pass iteration</summary>
    /// <param name="n">The number of times to invoke <paramref="iteratee" /></param>
    /// <param name="iteratee">The iteratee, void iteratee()</param>
    /// <returns>Array of the returned values</returns>
    template <typename Function>
    void timesSimple(size_t n, Function iteratee)
    {
        while (n-- > 0)
            iteratee();
    }
}
