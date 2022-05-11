#pragma once
#include "lodash_common.h"
namespace _ {
    // pluck
    // Called like `lodash::pluck<vector<int>>(container, &value_type::member)`
    template <typename ResultContainer, typename Container, typename Member>
    ResultContainer pluck(Container const& container, Member member)
    {
        return invoke(container, member);
    }
}
