#pragma once
#include <numeric>
#include "lodash_common.h"
#include "001_each.h"

// https://www.doxygen.nl/manual/docblocks.html
// https://www.doxygen.nl/manual/commands.html#cmda

namespace _ {
    /// <summary>`reduce` for sequence containers with 4 argument callback</summary>
    /// <param name="container">The container.</param>
    /// <param name="function">callback(<paramref name="initialValue" />, currentValue, currentIndex, <paramref name="container"
    /// />)</param>
    /// <param name="initialValue">Value to use as the first argument to the first call of the callback.</param>
    /// <returns>The value that results from the reduction.</returns>
    /// <example><code>
    /// std::vector<int> v{ 1, 2, 3 };
    /// count << lodash::reduceArray(v, [](auto accumulator, auto currentValue, auto currentIndex, auto container) {
    ///     return accumulator + "Index: "s + std::to_string(currentIndex) + " = "s + std::to_string(currentValue) + '\n';
    /// }, std::string{})
    /// </code></example>
    /// TODO Implement initialValue as optional: "[Optional] Value to use as the first argument to the first call of the callback.
    /// If no initial value is supplied, the first element in the array will be used. Calling reduce on an empty array without an
    /// initial value is an error."
    template <typename Container, typename Function, typename Memo>
    Memo reduceArray(const Container& container, Function function, Memo initialValue)
    {
        each_with_distance(container, [&](const typename Container::value_type& value, const size_t index) {
/*err*/     initialValue = function(initialValue, value, index, container);
        });
        return initialValue;
    }

    /// <summary>`reduce` for associative containers with 4 argument callback</summary>
    /// <see cref="reduce" />
    /// <seealso cref="reduceArray" />
    /// <param name="container">The container.</param>
    /// <param name="function">callback(<paramref name="initialValue" />, currentValue, currentKey, <paramref name="container"
    /// />)</param>
    /// <param name="initialValue">Value to use as the first argument to the first call of the callback.</param>
    /// <returns>The value that results from the reduction.</returns>
    /// TODO Implement initialValue as optional: "[Optional] Value to use as the first argument to the first call of the callback.
    /// If no initial value is supplied, the first element in the array will be used. Calling reduce on an empty array without an
    /// initial value is an error."
    template <typename Container, typename Function, typename Memo>
    Memo reduceObject(const Container& container, Function function, Memo initialValue)
    {
        // ResultContainer result;
        auto keys = _::keys2(container);
        for (const auto& key : keys) {
            // const auto& value = container.at(key);
            auto value   = container.at(key, 1);
            initialValue = function(initialValue, value, key, container);
        }
        return initialValue;
    }

    template <typename Container, typename Function, typename Memo>
    Memo inject(const Container& container, Function function, Memo initialValue)
    {
        return reduce(container, function, initialValue);
    }

    template <typename Container, typename Function, typename Memo>
    Memo foldl(const Container& container, Function function, Memo initialValue)
    {
        return reduce(container, function, initialValue);
    }

}
namespace _ {


    // reduce_right/foldr
    template <typename Container, typename Memo, typename BinaryOperation>
    Memo reduce_right(const Container& container, BinaryOperation function, Memo initialValue)
    {
        for (typename Container::const_reverse_iterator i = container.rbegin(); i != container.rend(); ++i) {
            initialValue = function(initialValue, *i);
        }
        return initialValue;
    }

    template <typename Container, typename Function, typename Memo>
    Memo foldr(const Container& container, Function function, Memo initialValue)
    {
        return reduce_right(container, function, initialValue);
    }

    // reduce/inject/foldl

    /// <summary>Applies a function against an accumulator and each element in the container (from left to right) to reduce it to a single value.</summary>
    /// <param name="container">The container.</param>
    /// <param name="function">The callback, callback(accumulatedValue, currentValue)</param>
    /// <param name="initialValue">Value to use as the first argument to the first call of the callback.</param>
    /// <returns>The value that results from the reduction.</returns>
    /// <example><code><![CDATA[
    /// using fspath = std::filesystem::path;
    /// std::string pathCombine(const std::string& path, const std::vector<std::string>& more) {
    ///     fspath full_path = lodash::reduce(more, [](const fspath _path, const std::string& segment) {
    ///         return _path / filepath(segment);
    ///     }, filepath(path));
    /// 
    ///     full_path.string();
    /// }
    /// ]]></code></example>
    template <typename Container, typename BinaryOperation, typename Memo>
    Memo reduce(const Container& container, BinaryOperation&& function, Memo initialValue)
    {
        // TODO Implement initialValue as optional: "[Optional] Value to use as the first argument to the first call of the callback. If no initial value is supplied, the first element in the array will be used. Calling reduce on an empty array without an initial value is an error."
        // TODO Implement full range of functionality as described in https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/Reduce?v=b
        return std::accumulate(std::begin(container), std::end(container), initialValue, std::forward<BinaryOperation>(function));
        //each(container, [&](const auto& i) {
        //    initialValue = function(initialValue, i);
        //});
    }

    /**
     * \brief add all \a container elements using \c std::plus
     * \tparam Container auto
     * \tparam T auto
     * \param container sequential container
     * \param init initial value (defaults to {} or 0)
     * \return summation of elements
     */
    template <typename Container, typename T = typename Container::value_type>
    T sum(const Container& container, T init = T())
    {

        // underscore.js:
        //  var sum = _.reduce([1, 2, 3], function(memo, num) { return memo + num; }, 0);
		//  => 6
        return reduce(container, std::plus<T>(), init);
    }

    /// <summary>This method is like _.sum except that it accepts iteratee which is invoked for each element in array to generate the value to be summed. The iteratee is invoked with one argument: (value).</summary>
    /// <param name="container">The container.</param>
    /// <param name="iteratee">The iteratee invoked per element.</param>
    /// <returns>The sum.</returns>
    template <typename R, typename Container, typename Function, typename T = typename Container::value_type>
    R sumBy(const Container& container, Function iteratee, R init = R())
    {
        // TODO: is this the optimal way to handle Function? (passed as reference into lambda, and pass by value into function)
        return reduce(container, [&](R total, T element) { return total + iteratee(element); }, std::move(init));
    }

    template <typename T, typename Container>
    T mean(const Container& container, T init = T())
    {
        if (std::empty(container)) return T();
        return reduce(container, std::plus<T>(), std::move(init)) / std::size(container);
    }

    template <typename T>
    T identity(T value) {
        return value;
    }

	namespace helper {
		template <class _Ty = void>
		struct _max {  // functor for operator min
			typedef _Ty first_argument_type;
			typedef _Ty second_argument_type;
			typedef _Ty result_type;

			constexpr _Ty operator()(const _Ty& _Left, const _Ty& _Right) const { return _Left < _Right ? _Right : _Left; }
		};

		template <class _Ty = void>
		struct _min {  // functor for operator min
			typedef _Ty first_argument_type;
			typedef _Ty second_argument_type;
			typedef _Ty result_type;

			constexpr _Ty operator()(const _Ty& _Left, const _Ty& _Right) const { return _Right < _Left ? _Right : _Left; }
		};
	}

    // max

    // Returns the maximum value in list. TODO: If an iteratee function is provided, it will be used on each value to generate the criterion by which the value is ranked.
    template <typename Container, typename T = typename Container::value_type>
    T max(const Container& container)
    {
        return reduce(container, helper::_max<T>(), *std::begin(container));
    }

    /**
     * \brief Returns the maximum value in list. 
     * \param container {Object} or {Array}, only the values will be passed to iteratee
     * \param iteratee used on each value to generate the criterion by which the value is ranked
     * \return {Container::value_type} the maximum value from the values returned by iteratee
     */
    /**
     * This method is like `_.max` except that it accepts `iteratee` which is
     * invoked for each element in `array` to generate the criterion by which
     * the value is ranked. The iteratee is invoked with one argument: (value).
     *
     * @static
     * @memberOf _
     * @since 4.0.0
     * @category Math
     * @param {Array} array The array to iterate over.
     * @param {Function} [iteratee=_.identity] The iteratee invoked per element.
     * @returns {*} Returns the maximum value.
     * @example
     *
     * var objects = [{ 'n': 1 }, { 'n': 2 }];
     *
     * _.maxBy(objects, function(o) { return o.n; });
     * // => { 'n': 2 }
     *
     * // The `_.property` iteratee shorthand.
     * _.maxBy(objects, 'n');
     * // => { 'n': 2 }
     */
    template <typename Container, typename T = typename Container::value_type, typename Function>
    T maxBy(const Container& container, Function&& iteratee)
    {

        return reduce(map2(container, iteratee), helper::_max<T>(), *std::begin(container));
    }
    //function maxBy(array, iteratee) {
    //  return (array && array.length)
    //    ? baseExtremum(array, getIteratee(iteratee, 2), baseGt)
    //    : undefined;
    //}
    ///**
    // * The base implementation of methods like `_.max` and `_.min` which accepts a
    // * `comparator` to determine the extremum value.
    // *
    // * @private
    // * @param {Array} array The array to iterate over.
    // * @param {Function} iteratee The iteratee invoked per iteration.
    // * @param {Function} comparator The comparator used to compare values.
    // * @returns {*} Returns the extremum value.
    // */
    //function baseExtremum(array, iteratee, comparator) {
    //  var index = -1,
    //      length = array.length;

    //  while (++index < length) {
    //    var value = array[index],
    //        current = iteratee(value);

    //    if (current != null && (computed === undefined
    //          ? (current === current && !isSymbol(current))
    //          : comparator(current, computed)
    //        )) {
    //      var computed = current,
    //          result = value;
    //    }
    //  }
    //  return result;
    //}
    // Returns the minimum value in list. TODO: If an iteratee function is provided, it will be used on each value to generate the criterion by which the value is ranked.
    template <typename Container, typename T = typename Container::value_type>
    T min(const Container& container)
    {
        return reduce(container, helper::_min<T>(), *std::begin(container));
    }


    // max
    template <typename Container>
    typename Container::iterator maxIterator(const Container& container)
    {
        if (container.begin() == container.end()) {
            return container.end();
        }

        typename Container::iterator max = container.begin();
        for (typename Container::iterator i = ++container.begin(); i != container.end(); ++i) {
            if (*i < *max) {
                max = i;
            }
        }
        return max;
    }

    template <typename Compared, typename Container, typename Function>
    typename Container::iterator maxIteratorBy(const Container& container, Function function)
    {
        if (container.begin() == container.end()) {
            return container.end();
        }

        struct {
            typename Container::iterator position;
            Compared                     computed;
        } max = {container.begin(), function(*container.begin())};

        for (typename Container::iterator i = ++container.begin(); i != container.end(); ++i) {
            Compared computed = function(*i);
            if (max.computed < computed) {
                max.position = i;
                max.computed = computed;
            }
        }
        return max.position;
    }

	/**
	* A brief history of JavaDoc-style (C-style) comments.
	*
	* This is the typical JavaDoc-style C-style comment. It starts with two
	* asterisks.
	*
	* @param theory Even if there is only one possible unified theory. it is just a
	*               set of rules and equations.
	*/
	void cstyle( int theory );

}
