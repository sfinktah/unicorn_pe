#pragma once
#include "lodash_common.h"
#include "helper.h"
namespace _ {
    template <typename Container, typename Value>
    Container spliceItem(Container& container, long long start, long long deleteCount, const Value& item)
    {
        const size_t len = container.size();
        if (deleteCount < 1) deleteCount = 0;
        if (start < 0) start = len + start;

        start = helper::clamp<size_t>(start, 0, len);
        size_t end = start + deleteCount;
        end   = helper::clamp<size_t>(end, start, len);
        deleteCount = end - start;

        Container result;
        if (deleteCount > 0)
        for (auto it = std::next(std::begin(container), start); deleteCount; deleteCount--) {
            helper::add_to_container(result, *it), it = container.erase(it);
        }
        auto pos = std::next(std::begin(container), start);
        container.emplace(pos, item);
        //each(items, [&container, &pos](const auto& item) {
        //    helper::add_to_container(container, item, pos)
        //});
        //result = slice<Container>(container, start, end);
        //size_t       _index = 0;
        //for (auto i = container.begin(); i != container.end(); /* ++i */) {
        //    auto index = _index++;
        //    if (index >= end) break;
        //    if (index >= start) helper::add_to_container(result, *i);
        //}
        return result;
    }
}
