#pragma once
#include "lodash_common.h"
#include <random>
namespace _ {
    template <typename T>
    T baseRandom(T min, T max)
    {
        static std::random_device rd;
        static std::mt19937       gen(rd());
        if (min == max) return max;
        std::uniform_int_distribution<> dis(min, max);
        return dis(gen);
    }
}
