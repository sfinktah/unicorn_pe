#pragma once
#include "lodash_common.h"
#include "helper.h"
#include "001_each.h"
namespace _ {
    // filter/select
    template <typename ResultContainer, typename Container, typename Predicate>
    ResultContainer filter(Container& container, Predicate&& predicate)
    {
        ResultContainer result;

        each(container, [&](auto& value) {
            if (std::forward<Predicate>(predicate)(value)) {
                helper::add_to_container(result, value);
            }
        });

        return result;
    }

    template <typename Container, typename Predicate, typename ResultContainer = std::vector<typename Container::value_type>>
    ResultContainer filter_v(Container& container, Predicate&& predicate)
    {
        return filter<ResultContainer>(container, predicate);
    }

    template <typename Container, typename Predicate>
    std::vector<typename Container::value_type> filter_v2(Container& container, Predicate&& predicate)
    {
        std::vector<typename Container::value_type> result;

        each(container, [&](auto& value) {
            if (std::forward<Predicate>(predicate)(value)) {
                helper::add_to_container(result, value);
            }
        });

        return result;
    }
}
