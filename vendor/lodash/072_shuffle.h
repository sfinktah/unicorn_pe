#pragma once
#include "lodash_common.h"
namespace _ {
    // shuffle
    // This assumes srand has already been called.
    template <typename ResultContainer, typename Container>
    ResultContainer shuffle(const Container& container)
    {
        std::vector<typename Container::value_type> deck(container.begin(), container.end());
        for (int i = deck.size() - 1; i > 1; --i) {
            int j = std::rand() % (i + 1);
            std::swap(deck[i], deck[j]);
        }
        return ResultContainer(deck.begin(), deck.end());
    }
}
