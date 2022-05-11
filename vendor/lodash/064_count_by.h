#pragma once
#include "lodash_common.h"
#include <unordered_map>

namespace _ {
    // An internal function used for aggregate “group by” operations.
    //group = function(behavior) {
    //    return function(obj, iteratee, context) {
    //        var result = {};
    //        iteratee = cb(iteratee, context);
    //        _.each(obj, function(value, index) {
    //            var key = iteratee(value, index, obj);
    //            behavior(result, value, key);
    //        });
    //        return result;
    //    };
    //};

    // count_by
    template <typename Key, typename Container, typename Function>
    std::unordered_map<Key, size_t> count_by(const Container& container, Function function)
    {
        std::unordered_map<Key, size_t> result;
        for (auto i = container.cbegin(); i != container.cend(); ++i) {
            const auto key = function(*i);
            if (result.count(key))
                result[key] ++;
            else
                result[key] = 1;
        }
        return result;
    }

    template <typename Container, typename Function>
    auto count_by(const Container& container, Function function)
    {
        std::unordered_map<std::invoke_result_t<Function, typename Container::value_type>, size_t> result;
        for (auto i = container.cbegin(); i != container.cend(); ++i) {
            const auto key = function(*i);
            if (result.count(key))
                result[key] ++;
            else
                result[key] = 1;
        }
        return result;
    }
}
