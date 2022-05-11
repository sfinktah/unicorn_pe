#pragma once
#include "lodash_common.h"
#include "helper.h"
#include <limits>
namespace _ {
    // reverse

    //template<class BidirIt>
    //void reverse(BidirIt first, BidirIt last)
    //{
    //    while ((first != last) && (first != --last)) {
    //        std::iter_swap(first++, last);
    //    }
    //}

    //template<class BidirIt, class OutputIt>
    //OutputIt reverse_copy(BidirIt first, BidirIt last, OutputIt d_first)
    //{
    //    while (first != last) {
    //        *(d_first++) = *(--last);
    //    }
    //    return d_first;
    //}
    template <typename Container>
    auto reverse(const Container& container, typename Container::size_type limit = std::numeric_limits<typename Container::size_type>::max())
    {
        // see also: std::reverse
        //std::vector<typename Container::value_type> destination(container.size());
        //std::reverse_copy(std::begin(container), std::end(container), std::begin(destination));

        std::vector<typename Container::value_type> result;
        if constexpr(traits::has_reserve<Container>::value) { 
            result.reserve(container.size());
        }

        typename Container::size_type count = {};
        for (typename Container::const_reverse_iterator i = container.rbegin(); count < limit && i != container.rend(); ++i, ++count) {
            helper::add_to_container(result, *i);
        }
        return result;
    }
}
