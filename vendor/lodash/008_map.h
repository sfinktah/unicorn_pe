#pragma once
#include "002_each.h"
#include "lodash_common.h"
#include "helper.h"
namespace _ {
    // map/collect
    template <typename ResultContainer, typename Container, typename Function>
    ResultContainer map(const Container& container, Function&& function) {
        ResultContainer result;
        if constexpr (traits::has_push_back<Container>::value)
            std::transform(std::begin(container), std::end(container), std::back_inserter(result),
                           std::forward<Function>(function));
        else
            std::transform(std::begin(container), std::end(container), std::inserter(result, std::end(result)),
                           std::forward<Function>(function));

        // if all else fails:
        // for (const typename Container::value_type& item : container) helper::add_to_container(result,
        // std::forward<Function>(function)(item));
        return result;
    }

    template <typename Container, typename Function>
    auto map2(const Container& obj, Function&& iteratee) {
        using value_t = typename Container::value_type;
        std::vector<std::invoke_result_t<Function, value_t>> result;
        result.reserve(obj.size());
        each2(obj, [&](const value_t& value) {
            // result.emplace_back(std::invoke<Function, value_t>(iteratee, value));
            result.emplace_back(iteratee(value));
        });
        return result;
    }
    // mapObject - Creates an array of values by running each element in collection thru iteratee.
    // The iteratee is invoked with two arguments: (value, key). -- sfink
    template <typename ResultContainer, typename Container, typename Function>
    ResultContainer mapObject(const Container& container, Function&& function) {
        return map<ResultContainer>(keys2(container),
                                    [&](auto& key) { return std::forward<Function>(function)(container.at(key, 1), key); });
    }

#if __has_include("json.hpp") || defined(INCLUDE_NLOHMANN_JSON_HPP_)
    template <typename ResultContainer, typename Container, typename Function>
    ResultContainer mapJsonObject(const Container& container, Function function) {
        ResultContainer result;
        for (auto& [key, value] : container.items()) {
            helper::add_to_container(result, function(value, key));
        }
        return result;
    }
#endif

    /**
     * @brief copy container
     * @param container source
     * @tparam ResultContainer type of container to return
     * @returns container as type ResultContainer
     */
    template <typename ResultContainer, typename Container>
    ResultContainer copy(const Container& container) {
        ResultContainer result(std::begin(container), std::end(container));
        return result;
    }
}  // namespace _
