#pragma once
#include "lodash_common.h"
namespace _ {
    // indexOf
    template <typename Container>
    int indexOf(const Container& container, typename Container::value_type value)
    {
        auto value_position = std::find(container.begin(), container.end(), value);
        return value_position == container.end() ? -1 : std::distance(container.begin(), value_position);
    }

  //  TODO: needs a stupid compare struct - https://en.cppreference.com/w/cpp/algorithm/equal_range
  //  template <typename Container, typename Value, typename Function>
  //  size_t indexOf_if_sorted(const Container& container, Value value, Function getValue)
  //  {
  //      auto [first, second] = std::equal_range(std::begin(container), std::end(container), value, [&](const Container::value_type& a, const Container::value_type& b) {
  //          return getValue(a) < getValue(b);
  //      });
  //      if (first != second) {
  //          return std::distance(std::begin(container), first);
  //      }
		//return -1;
  //  }

    template <typename Container>
    bool containsSorted(const Container& container, typename Container::value_type value)
    {
        return std::binary_search(std::begin(container), std::end(container), value);
    }

    template <typename Container>
    size_t countSorted(const Container& container, typename Container::value_type value)
    {
        auto [first, second] = std::equal_range(std::begin(container), std::end(container), value);
        if (first != second) {
            return std::distance(first, second);
        }
		return false;
    }
}
namespace _ {
    template <typename Container, typename Function>
    int indexOf_if(const Container& container, Function&& predicate)
    {
        auto value_position = std::find_if(container.begin(), container.end(), std::forward<Function>(predicate));
        return value_position == container.end() ? -1 : std::distance(container.begin(), value_position);
    }
}
namespace _ {
    // `indexOf` that accepts `Container::value_type = std::pair<K, V>`
    template <typename Container, typename Value>
    int indexOfMap(const Container& container, Value value)
    {
        // https://stackoverflow.com/questions/12742472/how-to-get-matching-key-using-the-value-in-a-map-c

        auto value_position =
            std::find_if(std::begin(container), std::end(container), [&](const auto& pair) { return pair.second == value; });

        return value_position == container.end() ? -1 : std::distance(container.begin(), value_position);
    }
}
namespace _ {
    template <typename Container>
    int indexOf(const Container& container, typename Container::value_type value, bool is_sorted)
    {
        if (!is_sorted) {
            return indexOf(container, value);
        }
        typename Container::iterator value_lower_bound = std::lower_bound(container.begin(), container.end(), value);
        return value_lower_bound == container.end() || *value_lower_bound != value ? -1 : std::distance(
                                                                                              container.begin(), value_lower_bound);
    }
}
namespace _ {
    // last_index_of
    template <typename Container>
    int last_index_of(Container const& container, typename Container::value_type value)
    {
        typename Container::const_iterator result = std::find(container.begin(), container.end(), value);
        typename Container::const_iterator i      = result;
        while (i != container.end()) {
            i = std::find(++i, container.end(), value);
            if (i != container.end()) {
                result = i;
            }
        }
        return result == container.end() ? -1 : std::distance(container.begin(), result);
    }
}
