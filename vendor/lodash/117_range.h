#pragma once
#include <cstdlib>
#include "lodash_common.h"
#include "helper.h"
namespace _ {
    // range

    template <typename T=size_t, typename ResultContainer = std::vector<T>>
    ResultContainer range(T start, T stop, T step)
    {
        //T             length = std::max((stop - start) / step, 0);
        //auto step_pos = step < 0 ? std::negate<T>()(step) : step;
        //T step_neg = std::negate<T>()(step_pos);
        T             length = (std::max(stop, start) - std::min(stop, start)) / step;
        //T             length = std::negate<T>()((std::max(stop, start) - std::min(stop, start)) / step_neg);
        T             index  = 0;
        if (step != 1) {
            bool modulo  = (std::max(stop, start) - std::min(stop, start)) % step;
            if (modulo)
                length += 1;
        }
        ResultContainer result;
        result.reserve((size_t)length);

        printf("length: %llu\n", (size_t)length);
        printf("step: %llu\n", (size_t)step);
        printf("index: %llu\n", (size_t)index);
        printf("start: %llu\n", (size_t)index);
        printf("stop: %llu\n", (size_t)index);

        while (index < length) {
            helper::add_to_container(result, start);
            start += step;
            ++index;
        }

        return result;
    }

    template <typename T, typename ResultContainer = std::vector<T>>
    ResultContainer range(T start, T stop)
    {
        return range<T, ResultContainer>(start, stop, 1);
    }

    template <typename T, typename ResultContainer = std::vector<T>>
    ResultContainer range(T stop)
    {
        return range<T, ResultContainer>(0, stop);
    }
}
