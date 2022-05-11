#pragma once
#include "lodash_common.h"
#include "helper.h"
#include "001_each.h"
namespace _ {
    // concat
    /// <summary>Creates a new array concatenating array <paramref="container1" /> with <paramref="container2" /></summary>
    /// <param name="container1">container1</param>
    /// <param name="container2">container2</param>
    /// <returns></returns>
    template <typename ResultContainer, typename Container1, typename Container2>
    ResultContainer concat_two(const Container1& container1, const Container2& container2)
    {
        ResultContainer result;

        // This may be a terrible idea, if reserve or size is not defined.
        // result.reserve(container1.size() + container2.size());
        each(container1, [&result](auto value) { helper::add_to_container(result, value); });
        each(container2, [&result](auto value) { helper::add_to_container(result, value); });

        // vector1.insert(vector1.end(), vector2.begin(), vector2.end());
        // for (auto i = container.begin(); i != container.end(); ++i)
        //{
        //    if (static_cast<bool>(*i))
        //    {
        //        helper::add_to_container(result, *i);
        //    }
        //}
        return result;
    }

    template <typename ResultContainer, typename... Args>
    ResultContainer concat(Args&& ... args)
    {
        ResultContainer result;
        // static_assert((std::is_constructible_v<T, Args&&> && ...));
        (concat_inplace(result, std::forward<Args>(args)), ...);
        return result;
    }

    /// <summary>Append the contents of <paramref="source" /> to <paramref="destination" /></summary>
    /// Allows a method to add either a collection or an item using the same function
    /// <param name="destination">The destination array</param>
    /// <param name="source">The source array</param>
    /// <returns>void</returns>
               
    template <typename Container1, typename Container2>
    // MEM_FUNC typename std::enable_if<std::is_integral<T>::value, T>::type safeDereferenceOpt(_Ty address) noexcept {
    // typename std::enable_if<std::is_same_v<std::decay_t<typename Container1::value_type>, std::decay_t<typename Container2::value_type>>, void>::type
    typename std::enable_if<std::is_convertible_v<std::decay_t<typename Container1::value_type>, std::decay_t<typename Container2::value_type>>, void>::type
    concat_inplace(Container1& destination, const Container2& source)
    {
        // This may be a terrible idea, if reserve or size is not defined.
        // result.reserve(container1.size() + source.size());
        each(source, [&destination](const auto& value) { helper::add_to_container(destination, value); });

    }

    /// <summary>Append the single item<paramref="source" /> to <paramref="destination" /></summary>
    /// Allows a method to add either a collection or an item using the same function
    /// <param name="destination">The destination array</param>
    /// <param name="item">The item to add</param>
    /// <returns>void</returns>
    template <typename Container>
    void concat_inplace(Container& destination, const typename Container::value_type& item)
    {
        helper::add_to_container(destination, item);
    }

    template <typename Container>
    void concat_inplace(Container& destination, typename Container::value_type&& item)
    {
        // helper::add_to_container(destination, std::forward<Container::value_type>(item));
        helper::add_to_container(destination, std::move(item));
    }
}
