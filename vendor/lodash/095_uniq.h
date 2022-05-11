#pragma once
#pragma once
#include "lodash_common.h"
#include "helper.h"
#include "008_map.h"
#include "046_includes.h"
#include "082_last.h"
#include "088_concat.h"

namespace _ {
    // uniq/unique
    template <typename ResultContainer, typename Key, typename Container, typename Function>
    ResultContainer uniq(Container const& container, bool is_sorted, Function function) {
        ResultContainer result;
        std::vector<Key> keys = map<std::vector<Key>>(container, function);
        if (container.size() < 3) {
            is_sorted = true;
        }

        std::vector<Key> memo;

        for (std::pair<typename std::vector<Key>::const_iterator, typename Container::const_iterator> i = std::make_pair(keys.begin(), container.begin()); i.first != keys.end(); ++i.first, ++i.second) {
            if (is_sorted ? !memo.size() || *last(memo) != *i.first : !includes(memo, *i.first)) {
                memo.push_back(*i.first);
                helper::add_to_container(result, *i.second);
            }
        }
        return result;
    }

    template <typename ResultContainer, typename Container>
    ResultContainer uniq(Container const& container, bool is_sorted) {
        ResultContainer result;
        if (container.size() < 3) {
            is_sorted = true;
        }

        std::vector<typename Container::value_type> memo;
        for (auto i = container.begin(); i != container.end(); ++i) {
            if (is_sorted ? !memo.size() || *last(memo) != *i : !includes(memo, *i)) {
                memo.push_back(*i);
                helper::add_to_container(result, *i);
            }
        }
        return result;
    }

    template <typename ResultContainer, typename Key, typename Container, typename Function>
    ResultContainer uniq(Container const& container, Function function) {
        return uniq<ResultContainer, Key>(container, false, function);
    }

    template <typename ResultContainer, typename Container>
    ResultContainer uniq(Container const& container) {
        return uniq<ResultContainer>(container, false);
    }

    template <typename Container>
    std::vector<typename Container::key_type> uniq2(const Container& container, bool is_sorted = false)
    {
        return uniq<std::vector<typename Container::key_type>>(container, is_sorted);
    }


    /// <summary>This method is like _.uniq except that it accepts iteratee which is invoked for each element in array to generate
    /// the criterion by which uniqueness is computed. The order of result values is determined by the order they occur in the
    /// array. The iteratee is invoked with one argument</summary>
    /// <param name="container">The container.</param>
    /// <param name="function">iteratee(<paramref name="Key" /> identity)</param>
    /// <returns></returns>
    template <typename ResultContainer, typename Key, typename Container, typename Function>
    ResultContainer uniqBy(Container const& container, Function function) {
        return uniq<ResultContainer, Key>(container, false, function);
    }

    template <typename ResultContainer, typename Key, typename Container, typename Function>
    ResultContainer unique(Container const& container, bool is_sorted, Function function) {
        return uniq<ResultContainer, Key>(container, is_sorted, function);
    }

    template <typename ResultContainer, typename Key, typename Container, typename Function>
    ResultContainer unique(Container const& container, Function function) {
        return uniq<ResultContainer, Key>(container, false, function);
    }

    template <typename ResultContainer, typename Container>
    ResultContainer unique(Container const& container, bool is_sorted) {
        return uniq<ResultContainer>(container, is_sorted);
    }

    template <typename ResultContainer, typename Container>
    ResultContainer unique(Container const& container) {
        return uniq<ResultContainer>(container, false);
    }

    template <typename ResultContainer, typename Container, typename Function>
    ResultContainer unique(Container const& container, Function function) {
        return uniq<ResultContainer>(container, false);
    }

    template <typename T, class... Args>
    auto A(Args&&... args) {
        std::vector<T> result;
        (_::helper::add_to_container(result, std::forward<Args>(args)), ...);
        return result;
    }
}  // namespace _
