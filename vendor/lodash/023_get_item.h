#pragma once
#include "lodash_common.h"
#include "008_map.h"

namespace _ {
    // template <class T, class Enable = void>
    // class value_type_from
    //{
    //    typedef T type;
    //};

    // template <class T>
    // class value_type_from<T, typename std::enable_if_has_type<typename T::value_type>::type>
    //{
    //    typedef typename T::value_type type;
    //};
    // typename Container::iterator

    template <typename ResultContainer, std::size_t I, typename Container>
    ResultContainer get_item(const Container& container)
    {
        return map<ResultContainer>(container, [](auto& value) { return std::get<I>(value); });
    }

    template <typename ResultContainer, typename Container>
    ResultContainer tuple_keys(const Container& container)
    {
        return get_item<ResultContainer, 0>(container);
    }

    template <typename ResultContainer, typename Container>
    ResultContainer tuple_values(const Container& container)
    {
        return get_item<ResultContainer, 1>(container);
    }

    template <typename ResultContainer, typename Container>
    ResultContainer arrayValues(const Container& container)
    {
        // @brick This fails on associative containers
        return ResultContainer(std::begin(container), std::end(container));

        // ResultContainer result;
        // for (const auto& item : container) helper::add_to_container(result, item);
        // return result;
    }

    template <typename ResultContainer, typename Container>
    ResultContainer objectValues(const Container& container)
    {
        // @brick This fails on associative containers
        return tuple_values<ResultContainer>(container);

        // ResultContainer result;
        // for (const auto& item : container) helper::add_to_container(result, item);
        // return result;
    }

    //template <typename Container>
    //typename Container::value_type sample(const Container& container)
    //{
    //}
    // sfink - values
    template <typename ResultContainer, typename Container>
    ResultContainer values(const Container& container)
    {
        if constexpr(traits::has_mapped_type<Container>::value) { 
            return objectValues<ResultContainer>(container); 
        }
        else {
            return arrayValues<ResultContainer>(container);
        }
    }


    template <typename Container>
    auto values_auto(const Container& container)
    {
        /*
         * std::unordered_map
         * ------------------
         * key_type	Key
         * mapped_type	T
         * value_type	std::pair<const Key, T>
         */
        //using key_t = typename Container::key_type;
        using value_t = typename Container::value_type;
        //std::cout << "key_t: " << typeid(value_t).name() << std::endl;
        //std::cout << "value_t: " << typeid(value_t).name() << std::endl;
        //std::cout << "mapped_t: " << typeid(mapped_t).name() << std::endl;
        if constexpr(traits::has_mapped_type<Container>::value) { 
            using mapped_t = typename Container::mapped_type;
            return objectValues<std::vector<mapped_t>>(container); 
        }
        else {
            return arrayValues<std::vector<typename Container::value_type>>(container);
        }
    }

    // sfink - needed to process json objects, and any other crap that doesn't fully comply to STL
    template <typename ResultContainer, typename Container>
    ResultContainer values2(const Container& container)
    {
        ResultContainer result;
        for (const typename Container::value_type& item : container) helper::add_to_container(result, item);
        return result;
    }
}
