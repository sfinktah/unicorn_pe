#pragma once
#include "lodash_common.h"
namespace _ {
    
    

    /**
     * Removes all given values from array
     *
     * \warning Unlike `_.without`, this method mutates `array`. Use `_.remove`
     * to remove elements from an array by predicate.
     *
     * @category Array
     * @param[mutable] array The array to modify.
     * @param[in] value The value to remove.
     * @returns {Container} removed elements
     *
     * @related pull
     * @related without
     * @relatedalso remove
     * @relatedalso removeAndReturn
     * @code
     *
     * var array = ['a', 'b', 'c', 'a', 'b', 'c'];
     *
     * _.pull(array, 'a', 'c');
     * console.log(array);
     * // => ['b', 'b']
     * @endcode
     */
    template <typename Container>
    Container pull(Container& array, typename Container::value_type const& value)
    {
        Container result;

        // This version is required for associative array
        // if constexpr(traits::has_mapped_type<Container>::value) {
        //    return map<ResultContainer>(tuple_values<std::vector<typename Container::value_type>>(array));
        //    //for (const typename Container::value_type& item : array) helper::add_to_container(result, item);
        //}
        // else {
        for (auto i = array.begin(); i != array.end();) {
            if (*i == value) {
                helper::add_to_container(result, *i);
                i = array.erase(i);
            }
            else {
                ++i;
            }
        }

        return result;
    }

    //! related to pull (lodash) - Removes all given values from array BUT don't return them and optionally limit the amount of erasures
    //! Note: Unlike `without`, this method mutates array. Use _.remove to remove elements from an array by predicate.
    template <typename Container>
    void erase(Container& array, typename Container::value_type const& value, size_t count = -1)
    {
        for (auto i = array.begin(); i != array.end(); count) (*i == value) ? (--count, i = array.erase(i)) : ++i;
    }
}
