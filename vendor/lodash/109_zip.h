#pragma once
#include "lodash_common.h"
#include "helper.h"
#include <algorithm>
#include <tuple>
#include <vector>

namespace _ {
    // zip
    /// <summary>Merges together the values of each of the arrays with the values at the corresponding position. Useful when you
    /// have separate data sources that are coordinated through matching array indexes.
    /// </summary>
    /// <param name="container1">The container1.</param>
    /// <param name="container2">The container2.</param>
    /// <returns>A sequential container of size <c>min(keys.size(), values.size())</c></returns>
    /// <example><code><![CDATA[// JavaScript example from underscore.org
    /// _.zip(['moe', 'larry', 'curly'], [30, 40, 50], [true, false, false]);
    /// // => [["moe", 30, true], ["larry", 40, false], ["curly", 50, false]]    /// }]]></code></example>
    /// <remarks>Limited to 2 arrays</remarks>
    /// <remarks>lodash version should actually take an array of arrays as a single argument</remarks>
    template <typename ResultContainer, typename Container1, typename Container2>
    ResultContainer zip(const Container1& container1, const Container2& container2) {
        ResultContainer result;
        typename Container1::const_iterator left  = container1.begin();
        typename Container2::const_iterator right = container2.begin();
        while (left != container1.end() && right != container2.end()) {
            // helper::add_to_container(result, typename ResultContainer::value_type(*left++, *right++));
            helper::add_to_container(result, {*left++, *right++});
        }
        return result;
    }

    //template <typename... Container>
    //auto zip3(const Container... container) {
    //    using value_t = typename Container::value_type;
    //    std::vector<std::vector<value_t>> result;

    //    // get shortest input array
    //    // (probably a better way)
    //    std::vector<size_t> lengths;
    //    (helper::add_to_container(lengths, container.size()), ...);
    //    auto shortest = _::min(lengths);

    //    // if our containers were lists or deques:
    //    std::vector<value_t> entry;
    //    (helper::add_to_container(entry, container.front()), ...);
    //    (container.pop_front(), ...);

    //    helper::add_to_container(result, entry);

    //    // can we use iterators? how would we start them?
    //    helper::add_to_container(result, {((*container_it++ ... // idk

    //    // what about a variadic helper::add_to_container?
    //}

    /// <summary>Converts arrays into objects. Pass a list of keys, and a list of values. If duplicate keys exist, the last value
    /// wins.</summary>
    /// <param name="keys">The keys.</param>
    /// <param name="values">The values.</param>
    /// <returns>An associative container of size <c>min(keys.size(), values.size())</c></returns>
    /// <example><code><![CDATA[// JavaScript example from https://lodash.com/docs/4.17.4#zipObject
    /// _.zipObject(['a', 'b'], [1, 2]);
    /// // => { 'a': 1, 'b': 2 }    /// <remarks>Limited to 2 arrays</remarks>
    /// <remarks>a.k.a. underscore's <c>object()</c> function, when passing a list of keys, and a list of values</remarks>
    /// <remarks></remarks>
    template <typename ResultContainer, typename Container1, typename Container2>
    ResultContainer zipObject(const Container1& keys, const Container2& values) {
        ResultContainer result;
        typename Container1::const_iterator left  = keys.begin();
        typename Container2::const_iterator right = values.begin();
        while (left != keys.end() && right != values.end()) {
            helper::add_to_container(result, typename ResultContainer::value_type(*left++, *right++));
        }
        return result;
    }

    template <typename... Containers, std::size_t... Is>
    auto zip_(const Containers&... containers, std::index_sequence<Is...>) {
        std::vector<std::tuple<typename Containers::value_type...>> results;

        results.reserve(std::min({std::size(containers)...}));  // Optional

        std::tuple begin_iterators{std::begin(containers)...};
        std::tuple end_iterators{std::end(containers)...};

        while (((std::get<Is>(begin_iterators) != std::get<Is>(end_iterators)) && ...)) {
            results.emplace_back(*std::get<Is>(begin_iterators)...);
            (std::get<Is>(begin_iterators)++, ...);
        }

        return results;
    }

    /**
     * \brief Merges together the values of each of the arrays with the values at the corresponding position.
     *
     * Useful when you have separate data sources that are coordinated through matching array indexes.
     * \param containers 2 or more containers
     * \return a vector of tuples
     * \code
     * _.zip(['moe', 'larry', 'curly'], [30, 40, 50], [true, false, false]);
     *   => [["moe", 30, true], ["larry", 40, false], ["curly", 50, false]]
     * \endcode
     */
    template <typename... Containers>
    auto zip(const Containers&... containers) {
        return zip_<Containers...>(containers..., std::index_sequence_for<Containers...>{});
    }

    template <std::size_t I, typename Container>
    auto nth_elements(const Container& container) {
        std::vector<std::tuple_element_t<I, typename Container::value_type>> results;

        for (auto&& value : container) results.emplace_back(std::get<I>(value));

        return results;
    }

    template <typename Container>
    auto keysT(const Container& container) {
        return nth_elements<0>(container);
    }

    template <typename Container>
    auto valuesT(const Container& container) {
        return nth_elements<1>(container);
    }

}  // namespace _
