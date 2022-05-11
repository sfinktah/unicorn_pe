#pragma once
#include "lodash_common.h"
#include "helper.h"
namespace _ {
    // compact
    template <typename ResultContainer, typename Container>
    ResultContainer compact(Container const& container)
    {
        ResultContainer result;
        for (auto i = container.begin(); i != container.end(); ++i) {
            if (static_cast<bool>(*i)) {
                helper::add_to_container(result, *i);
            }
        }
        return result;
    }
}
