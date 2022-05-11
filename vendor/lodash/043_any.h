#pragma once
#include "lodash_common.h"
namespace _ {
    /// <summary>
    /// The signature of the predicate function should be equivalent to the following :
    /// <code>
    /// bool pred(const T& a);
    /// </code>
    /// The signature does not need to have const &amp;, but the function must not modify the objects passed to it.
    /// The type Type must be such that an object of type InputIt can be dereferenced and then implicitly converted to Type.​
    /// </summary>
    template <typename Container, typename Predicate>
    bool any(const Container& container, Predicate&& predicate)
    {
        return std::any_of(std::begin(container), std::end(container), std::forward<Predicate>(predicate));
    }

    /**
     * \brief Checks if (value equals | unary predicate returns true) for at least one element in the collection
     * \tparam Container auto
     * \tparam Predicate auto
     * \param container elements to examine
     * \param predicate (unary predicate | value)
     *
     * The expression predicate(v) (if used as a predicate, rather than a value
     * to match)  must be convertible to bool for every argument v of
     * type (possibly const) VT, where VT is the value type of the container,
     * regardless of value category, and must not modify v. Thus, a parameter
     * type of VT& is not allowed, nor is VT unless for VT a move is equivalent
     * to a copy.
     *
     * \return true if (value equals | unary predicate returns true) for at least one element in the collection, false otherwise. Returns false if the collection is empty.
     * \sa std::any_of
     */
    template <typename Container, typename Predicate>
    bool any_of(const Container& container, Predicate predicate)
    {
        if constexpr (std::is_convertible_v<Predicate, typename Container::value_type>)
        {
            return std::any_of(std::begin(container), std::end(container), [predicate](const auto& v){ return v == predicate; });
        }
        // else if constexpr (std::is_invocable_r<bool, Predicate(typename Container::value_type)>::value)
        else // if constexpr (std::is_invocable<Predicate>::value) 
        {
            return std::any_of(std::begin(container), std::end(container), std::forward<Predicate>(predicate));
        }
    }

    /**
     * \brief Checks if (value equals | unary predicate returns true) for all elements in the collection
     * \tparam Container auto
     * \tparam Predicate auto
     * \param container elements to examine
     * \param predicate (unary predicate | value)
     *
     * The expression predicate(v) (if used as a predicate, rather than a value
     * to match)  must be convertible to bool for every argument v of
     * type (possibly const) VT, where VT is the value type of the container,
     * regardless of value category, and must not modify v. Thus, a parameter
     * type of VT& is not allowed, nor is VT unless for VT a move is equivalent
     * to a copy.
     *
     * \return true if (value equals | unary predicate returns true) for all elements in the collection, false otherwise. Returns true if the collection is empty.
     * \sa std::all_of
     */
    template <typename Container, typename Predicate>
    bool all_of(const Container& container, Predicate predicate)
    {
        if constexpr (std::is_convertible_v<Predicate, typename Container::value_type>)
        {
            return std::all_of(std::begin(container), std::end(container), [predicate](const auto& v){ return v == predicate; });
        }
        // else if constexpr (std::is_invocable_r<bool, Predicate(typename Container::value_type)>::value)
        else // if constexpr (std::is_invocable<Predicate>::value) 
        {
            return std::all_of(std::begin(container), std::end(container), std::forward<Predicate>(predicate));
        }
    }

    /**
     * \brief Checks if (value equals | unary predicate returns true) for no elements in the collection
     * \tparam Container auto
     * \tparam Predicate auto
     * \param container elements to examine
     * \param predicate (unary predicate | value)
     *
     * The expression predicate(v) (if used as a predicate, rather than a value
     * to match)  must be convertible to bool for every argument v of
     * type (possibly const) VT, where VT is the value type of the container,
     * regardless of value category, and must not modify v. Thus, a parameter
     * type of VT& is not allowed, nor is VT unless for VT a move is equivalent
     * to a copy.
     *
     * \return true if (value equals | unary predicate returns true) for no elements in the collection, false otherwise. Returns true if the collection is empty.
     * \sa std::none_of
     */
    template <typename Container, typename Predicate>
    bool none_of(const Container& container, Predicate predicate)
    {
        if constexpr (std::is_convertible_v<Predicate, typename Container::value_type>)
        {
            return std::none_of(std::begin(container), std::end(container), [predicate](const auto& v){ return v == predicate; });
        }
        // else if constexpr (std::is_invocable_r<bool, Predicate(typename Container::value_type)>::value)
        else // if constexpr (std::is_invocable<Predicate>::value) 
        {
            return std::none_of(std::begin(container), std::end(container), std::forward<Predicate>(predicate));
        }
    }

}
