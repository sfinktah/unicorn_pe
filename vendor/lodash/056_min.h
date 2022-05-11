#pragma once
#include "lodash_common.h"
#include "029_reduce.h"
namespace _ {
    // Returns an iterator to the minimum value in list. TODO: If an iteratee function is provided, it will be used on each value to generate the criterion by which the value is ranked.
    template <typename Container>
    typename Container::iterator minIterator(const Container& container)
    {
        if (container.begin() == container.end()) {
            return container.end();
        }

        typename Container::iterator min = container.begin();
        for (typename Container::iterator i = ++container.begin(); i != container.end(); ++i) {
            if (*i < *min) {
                min = i;
            }
        }
        return min;
    }

    /// <summary>Obtains the minimum element</summary>
    /// <param name="container">The container.</param>
    /// <param name="function">Function to compute value of each element</param>
    /// <returns>iterator to minimum element or end()</returns>
    /// <example>
    /// auto it = lodash::min<float>(players, [player](const auto& _) {
    ///     return player.distanceToSquared(_); // function returns float
    /// });
    /// if (it != players.end())
    ///     closestPlayer = *it;
    /// </example>

    template <typename Compared, typename Container, typename Function>
    typename Container::const_iterator minIteratorBy(const Container& container, Function function)
    {
        if (container.begin() == container.end()) {
            return container.end();
        }

        struct {
            typename Container::const_iterator position;
            Compared                           computed;
        } min = {container.begin(), function(*container.begin())};

        for (typename Container::const_iterator i = ++container.begin(); i != container.end(); ++i) {
            Compared computed = function(*i);
            if (computed < min.computed) {
                min.position = i;
                min.computed = computed;
            }
        }
        return min.position;
    }
}

/*** underscore.js
 
   _.min = function(obj, iteratee, context) {
    var result = Infinity, lastComputed = Infinity,
        value, computed;
    if (iteratee == null || typeof iteratee == 'number' && typeof obj[0] != 'object' && obj != null) {
      obj = isArrayLike(obj) ? obj : _.values(obj);
      for (var i = 0, length = obj.length; i < length; i++) {
        value = obj[i];
        if (value != null && value < result) {
          result = value;
        }
      }
    } else {
      iteratee = cb(iteratee, context);
      _.each(obj, function(v, index, list) {
        computed = iteratee(v, index, list);
        if (computed < lastComputed || computed === Infinity && result === Infinity) {
          result = v;
          lastComputed = computed;
        }
      });
    }
    return result;
  };
***/
