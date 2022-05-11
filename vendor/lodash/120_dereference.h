#pragma once
#include "lodash_common.h"
namespace _ {
    template <typename T>
    auto dereference(T _)
    {
        return *_;
    }
}
