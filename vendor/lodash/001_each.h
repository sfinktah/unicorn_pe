#pragma once
#include "lodash_common.h"
#include <algorithm>
#include "helper.h"
#include <tuple>
#include "lodash_common.h"
#include <experimental/string>
#include "meta/detected.hpp"

namespace _ {
    using namespace from_nlohmann::detail;
    // http://en.cppreference.com/w/cpp/algorithm/for_each

    // non-const container
    template <typename Container, typename Function>
    void each(Container& container, Function&& iteratee) {
        // This version is required for associative container
        // if constexpr(traits::has_mapped_type<Container>::value) {
        //    each(tuple_values _VECTOR(typename Container::value_type) (container, std::forward<Function>(iteratee)));
        //}
        // else {
        std::for_each(std::begin(container), std::end(container), std::forward<Function>(iteratee));
        //}
    }

    // const container
    template <typename Container, typename Function>
    void each(const Container& container, Function&& iteratee) {
        // This version is required for associative container
        // if constexpr(traits::has_mapped_type<Container>::value) {
        //    each(tuple_values _VECTOR(typename Container::value_type) (container, std::forward<Function>(iteratee)));
        //}
        // else {
        std::for_each(std::begin(container), std::end(container), std::forward<Function>(iteratee));
        //}
    }

    // const container
    template <typename Container, typename Function, typename FunctionUntil>
    void each_until(Container& container, Function&& iteratee, FunctionUntil&& until) {
        for (auto i = container.begin(); i != container.end(); ++i) {
            std::forward<Function>(iteratee)(*i);
            if (until(*i)) return;
        }
    }

    template <typename Container, typename Function>
    void each_with_distance(const Container& container, Function&& iteratee) {
        // The signature of the iteratee should be equivalent to the following :
        //    void fun(const Type &a, const size_t d);
        for (auto i = container.begin(); i != container.end(); ++i)
            std::forward<Function>(iteratee)(*i, std::distance(container.begin(), i));
    }

    template <typename Container, typename Function>
    void each_iter(const Container& container, Function iteratee) {
        // The signature of the iteratee should be equivalent to the following :

        //    void fun(const Type &a, const size_t d);
        for (auto i = container.begin(); i != container.end(); ++i)
            iteratee(i);
    }

    template <typename Container, typename Function>
    void each_magic(Container& container, Function&& iteratee) {
        //if constexpr (std::is_invocable_r<bool, Function(typename Container::value_type)>::value)
        // if constexpr (std::is_invocable<Function()>::value)
        if constexpr (helper::count_arg<decltype(&Function::operator())>::value == 1) {
            std::for_each(std::begin(container), std::end(container), std::forward<Function>(iteratee));
        }
#if __has_include("json.hpp") || defined(INCLUDE_NLOHMANN_JSON_HPP_)
        else if constexpr (helper::count_arg<decltype(&Function::operator())>::value == 2 && traits::has_is_object<Container>::value) {
            for (auto i = std::begin(container); i != std::end(container); ++i)
                std::forward<Function>(iteratee)(i.value(), i.key());
        } else if constexpr (helper::count_arg<decltype(&Function::operator())>::value == 1 && traits::has_is_object<Container>::value) {
            for (auto i = std::begin(container); i != std::end(container); ++i)
                std::forward<Function>(iteratee)(i.value());
        }
        //else if constexpr (std::is_same_v<Container, nlohmann::basic_json<>>)
        //{
        //    for (auto i = std::begin(container); i != std::end(container); ++i)
        //        std::forward<Function>(iteratee)(i.value(), i.key());
        //}
#endif
        else if constexpr (helper::count_arg<decltype(&Function::operator())>::value == 2) {
            for (auto i = std::begin(container); i != std::end(container); ++i)
                std::forward<Function>(iteratee)(i->second, i->first);
        }
        //else if constexpr (std::is_convertible<Function, typename Container::value_type>::value)
        //{
        //    return std::find(container.begin(), container.end(), std::forward<Function>(predicate));
        //}
        else {
            // static_assert(!"Suck my dongle");
            throw std::runtime_error("couldn't find appropriate method for _::find");
        }
    }

    /**
     * The full power of `each`.  Each invocation of iteratee is called
     * with three arguments: (element, index, list). If list is an object,
     * iteratee's arguments will be (value, key, list).  (MDN)
     *
     *
     * \param container associative container
     * \param iteratee iteratee(value, key, container)
     */
    template <typename Container, typename Function>
    void each_value_key(const Container& container, Function&& iteratee) {
        for (auto i = container.begin(); i != container.end(); ++i)
            std::forward<Function>(iteratee)(i->second, i->first, container);
    }

    template <typename Iterator, typename Function>
    void each_value_key(Iterator i, Iterator end, Function&& iteratee) {
        for (; i != end; ++i) {
            auto key   = i->first;
            auto value = i->second;
            std::forward<Function>(iteratee)(value, key);
        }
    }

    //  each - for nlohmann::json associative containers. iteratee has two arguments: (value, key).
    template <typename Container, typename Function>
    void each_json(const Container& container, Function&& iteratee) {
        for (auto i = container.begin(); i != container.end(); ++i) {
            std::forward<Function>(iteratee)(i.value(), i.key());
        }
    }

    // alias for _::each
    template <typename Container, typename Function>
    void for_each(const Container& container, Function&& iteratee) {
        each(container, std::forward<Function>(iteratee));
    }

    // credit: http://reedbeta.com/blog/python-like-enumerate-in-cpp17/
    template <typename T, typename TIter = decltype(std::begin(std::declval<T>())),
              typename = decltype(std::end(std::declval<T>()))>
    constexpr auto enumerate(T&& iterable) {
        struct iterator {
            size_t i;
            TIter iter;
            bool operator!=(const iterator& other) const { return iter != other.iter; }
            void operator++() {
                ++i;
                ++iter;
            }
            auto operator*() const { return std::tie(i, *iter); }
        };
        struct iterable_wrapper {
            T iterable;
            auto begin() { return iterator{0, std::begin(iterable)}; }
            auto end() { return iterator{0, std::end(iterable)}; }
        };
        return iterable_wrapper{std::forward<T>(iterable)};
    }
}  // namespace _
