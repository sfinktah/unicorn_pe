#pragma once
#include "lodash_common.h"
#include "017_tuple_keys.h"
namespace _ {
    // template <typename ResultContainer, typename Container>
    // ResultContainer values(const Container& container)
    //{
    //    return tuple_values<ResultContainer>(container);
    //}

    template <typename ResultContainer, typename Container>
    ResultContainer arrayKeys(const Container& container)
    {
        // @brick This fails on associative containers
        return ResultContainer(std::begin(container), std::end(container));

        // ResultContainer result;
        // for (const auto& item : container) helper::add_to_container(result, item);
        // return result;
    }

    template <typename ResultContainer, typename Container>
    ResultContainer objectKeys(const Container& container)
    {
        // @brick This fails on associative containers
        return tuple_keys<ResultContainer>(container);

        // ResultContainer result;
        // for (const auto& item : container) helper::add_to_container(result, item);
        // return result;
    }

    //template <typename Container>
    //typename Container::key_type sample(const Container& container)
    //{
    //}
    // sfink - keys
    template <typename ResultContainer, typename Container>
    ResultContainer keys(const Container& container)
    {
        if constexpr(traits::has_mapped_type<Container>::value) { 
            return objectKeys<ResultContainer>(container); 
        }
        else {
            return arrayKeys<ResultContainer>(container);
        }
    }

    // template <typename ResultContainer, typename Container>
    // ResultContainer keys(const Container& container)
    // {
        // return tuple_keys<ResultContainer>(container);
    // }

    // sfink - keys2
    template <typename Container>
    std::vector<typename Container::key_type> keys2(const Container& container)
    {
        return keys<std::vector<typename Container::key_type>>(container);
    }

    /*
     * std::unordered_map
     * ------------------
     * key_type	Key
     * mapped_type	T
     * value_type	std::pair<const Key, T>
     */

    template <typename Container>
    auto keys_auto(const Container& container)
    {
        if constexpr(traits::has_mapped_type<Container>::value) { 
            using key_t = typename Container::key_type;
            using value_t = typename Container::value_type;
            using mapped_t = typename Container::mapped_type;
            std::cout << "key_t: " << typeid(value_t).name() << std::endl;
            std::cout << "value_t: " << typeid(value_t).name() << std::endl;
            std::cout << "mapped_t: " << typeid(mapped_t).name() << std::endl;
            return objectKeys<std::vector<mapped_t>>(container); 
        }
#if __has_include("json.hpp") || defined(INCLUDE_NLOHMANN_JSON_HPP_)
        else if constexpr(traits::has_is_object<Container>::value)
        {
            return _::mapJsonObject<std::vector<nlohmann::json>>(container, [](const auto &value, const auto& key) -> nlohmann::json { return key; });
        }
#endif
        else {
            using value_t = typename Container::value_type;
            std::cout << "value_t: " << typeid(value_t).name() << std::endl;
            return arrayKeys<std::vector<typename Container::value_type>>(container);
        }
    }

}
