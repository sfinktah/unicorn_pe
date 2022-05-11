#pragma once
#include "lodash_common.h"
namespace _ {
    // to_array
    template <typename Container>
    typename Container::value_type* to_array(const Container& container)
    {
        typename Container::value_type* array = new typename Container::value_type[container.size()];
        struct {
            int                          numeric;
            typename Container::iterator iterator;
        } i;
        for (i.numeric = 0, i.iterator = container.begin(); i.iterator != container.end(); ++i.numeric, ++i.iterator) {
            array[i.numeric] = *i.iterator;
        }

        return array;
    }
}
