#pragma once
#include <type_traits>
#include "lodash_common.h"
#include "024_keys.h"
#include "002_each.h"

namespace _ {
    /// <summary>A copy of std::find_if</summary>
    /// <param name="first">Iterator first.</param>
    /// <param name="last">Iterator last.</param>
    /// <param name="predicate">predicate</param>
    /// <returns></returns>
    template <class InputIterator, class UnaryPredicate>
    InputIterator find_if(InputIterator first, InputIterator last, UnaryPredicate predicate) {
        while (first != last) {
            if (predicate(*first)) return first;
            ++first;
        }
        return last;
    }

    // find/detect
    /// <summary>Iterates over elements of collection, returning the first element predicate returns truthy for. The predicate is
    /// invoked with one argument: (value).</summary>
    /// <param name="container">The container.</param>
    /// <param name="predicate">The predicate.</param>
    /// <returns></returns>
    /// <remarks>This doesn't translate well into C++, as it should (by JavaScript underscore standards) return an actual element,
    /// or <c>undefined</c>.  While we could simulate <c>undefined</c> with C++17 <c>std::optional</c> usage would not be more
    /// convenient that returning an iterator.
    //template <typename Container, typename Predicate>
    //typename Container::iterator find(Container& container, Predicate predicate, std::enable_if_t<std::is_invocable_v<Predicate>, Predicate>)
    //{
    //    return _::find_if(container.begin(), container.end(), predicate);
    //}

    //template <typename Container>
    //typename Container::iterator find(Container& container, typename Container::value_type value)
    //{
    //    return _::find_if(container.begin(), container.end(), value);
    //}

    //  error C2440: 'return': cannot convert from 'unsigned int' to 'std::_List_iterator<std::_List_val<std::_List_simple_types<_Ty>>>'
    template <typename Container, typename Predicate>
    typename Container::iterator find(Container& container, Predicate&& predicate) {
        if constexpr (std::is_same_v<Predicate, typename Container::value_type>) {
            return std::find(container.begin(), container.end(), std::forward<Predicate>(predicate));
        }
        // else if constexpr (std::is_invocable_r<bool, Predicate(typename Container::value_type)>::value)
        else if constexpr (std::is_invocable<Predicate>::value) {
            return std::find_if(container.begin(), container.end(), std::forward<Predicate>(predicate));
        }
        //else if constexpr (std::is_convertible<Predicate, typename Container::value_type>::value)
        //{
        //    return std::find(container.begin(), container.end(), std::forward<Predicate>(predicate));
        //}
        else {
            // static_assert(!"Suck my dongle");
            throw std::runtime_error("couldn't find appropriate method for _::find");
        }
    }

    template <
        typename CompatibleObjectType, typename Predicate, typename Default,
        std::enable_if_t<is_compatible_object_type<
                        CompatibleObjectType>::value &&
                        !is_basic_json<CompatibleObjectType>::value,
                    int> = 0>
    typename CompatibleObjectType::value_type& find(CompatibleObjectType& container, Predicate predicate, Default function) {
        if constexpr (std::is_invocable_r<typename CompatibleObjectType::value_type, Predicate()>::value)
        // else if constexpr (std::is_invocable<Default>::value)
        {
            auto it = _::find_if(container.begin(), container.end(), predicate);
            if (it != container.end())
                return it->second;
        } else if constexpr (std::is_convertible<Predicate, typename CompatibleObjectType::value_type>::value) {
            if (auto it = container.find(predicate); it != container.end()) {
                return it->second;
            }
        }

        if constexpr (std::is_convertible<Default, typename CompatibleObjectType::value_type>::value) {
            return function;
        }

        else if constexpr (std::is_invocable_r<typename CompatibleObjectType::value_type, Default()>::value)
        // else if constexpr (std::is_invocable<Default>::value)
        {
            return function();
        } else {
            // static_assert(!"Suck my dongle");
            throw std::runtime_error("couldn't find appropiate method for _::find");
        }
    }

    template <typename CompatibleArrayType, typename Predicate, typename Default,
              std::enable_if_t<is_compatible_array_type<
                              CompatibleArrayType>::value &&
                              !is_compatible_object_type<CompatibleArrayType>::value &&
                              //!is_compatible_string_type<CompatibleArrayType>::value &&
                              !is_basic_json<CompatibleArrayType>::value,
                          int> = 0>
    typename CompatibleArrayType::value_type& find(CompatibleArrayType& container, Predicate predicate, Default function) {
        auto it = _::find_if(container.begin(), container.end(), predicate);
        if (it != container.end())
            return *it;

        if constexpr (std::is_convertible<Default, typename CompatibleArrayType::value_type>::value) {
            return function;
        }

        else if constexpr (std::is_invocable_r<typename CompatibleArrayType::value_type, Default()>::value)
        // else if constexpr (std::is_invocable<Default>::value)
        {
            return function();
        } else {
            // static_assert(!"Suck my dongle");
            throw std::runtime_error("couldn't find appropiate method for _::find");
        }
    }

    /// <summary>Iterates over elements of an associate collection, returning the first key the predicate returns truthy for. The
    /// predicate is invoked with three arguments: (value, index|key, collection).</summary>
    /// <param name="container">The container.</param>
    /// <param name="predicate">The predicate (value, key, collection)</param>
    /// <returns>The key of the first object found, or {}</returns>
    //template <typename Container, typename Function, typename Memo>
    //Memo findObject(const Container& container, Function predicate)
    template <typename Container, typename Function>
    typename Container::key_type findObject(const Container& container, Function predicate) {
        // ResultContainer result;
        auto keys = _::keys2(container);
        for (const auto& key : keys) {
            // const auto& value = container.at(key);
            auto value = container.at(key, 1);
            auto found = predicate(value, key, container);
            if (found) return key;
        }
        return {};
    }
}  // namespace _
