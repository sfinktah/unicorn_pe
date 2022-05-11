#pragma once
#include "lodash_common.h"
#include "helper.h"
namespace _ {
    // at
    template <typename Container>
    auto& at(Container& container, typename Container::key_type key)
    {
        return container.at(key);
    }
}
namespace _ {
    template <typename Container>
    auto tryAndGet(const Container& container, const typename Container::key_type key, typename Container::value_type& value)
    {
        if (contains(container, key)) {
            value = at(container, key);
            return true;
        }
        return false;
    }
}
namespace _ {
    template <typename Container>
    auto& getOrCall(
        const Container& container, const typename Container::key_type key,
        typename Container::value_type (*function)(typename Container::key_type))
    {
        if (!contains(container, key)) helper::add_to_container(container, key, function(key));
        return at(container, key);
    }
}
namespace _ {
    template <typename Container>
    auto& getOrDefault(
        const Container& container, const typename Container::key_type key, const typename Container::value_type& value)
    {
        if (!contains(container, key)) helper::add_to_container(container, key, value);
        return at(container, key);
    }
}
namespace _ {
    template <typename Container>
    bool tryAndPop(Container& the_queue, typename Container::value_type& popped_value)
    {
        if (the_queue.empty()) {
            return false;
        }

        popped_value = the_queue.front();
        the_queue.pop_front();
        return true;
    }
}
