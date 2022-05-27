#pragma once
#include "lodash_common.h"
#include "helper.h"
#include <climits>
#include <array>
#ifdef max
#undef min
#undef max
#endif
#include <gsl/gsl>
#pragma once
namespace _ {
    /** 
     *  \brief MDN - The slice() method returns a shallow copy of a portion of an array into a new array object selected from begin
     *  to end (end not included).  The original array will not be modified. \tparam ResultContainer Sequence Container \tparam
     * Container Sequence Container \param container Sequence Container \param begin Zero based index at which to begin extraction.
     *              A negative index can be used, indicating an offset from the end of the sequence.
     *              slice(-2) extracts the last two elements in the sequence.
     *              If begin is undefined, slice begins from index 0.
     * \param end
     *              Zero based index before which to end extraction. Slice extracts up to but not including end.
     *              For example, slice(1, 4) extracts the second element through the fourth element(elements indexed 1, 2, and 3).
     *              A negative index can be used, indicating an offset from the end of the sequence.
     *              slice(2, -1) extracts the third element through the second - to - last element in the sequence.
     *              If end is omitted, slice extracts through the end of the sequence(arr.length).
     *              If end is greater than the length of the sequence, slice extracts through the end of the sequence(arr.length).
     * \return Sequence Container
     */
    template <typename Container>
    auto slice(const Container& container, intptr_t begin = 0, intptr_t end = LLONG_MAX) {
        std::vector<typename Container::value_type> result;

        const size_t len = std::size(container);
        if (len == 0) return result;

        if (begin >= 0 && static_cast<size_t>(begin) > (len - 1)) return result;

        if (end < 1) end = len + end;
        if (begin < 0) begin = len + begin;

        begin      = helper::clamp<intptr_t>(begin, 0, len - 1);
        end        = helper::clamp<intptr_t>(end, begin, len);
        auto count = end - begin;
        // paranoia?
        count = helper::clamp<intptr_t>(count, 0, len - begin);

        if (count > 0)
            for (auto it = std::next(std::begin(container), (int)begin); count; count--, ++it) {
                helper::add_to_container(result, *it);
            }
        return result;
    }

    /**
     * The base implementation of `_.slice` without an iteratee call guard.
     *
     * @private
     * @param array The array to slice.
     * @param start The start position.
     * @param end The end position.
     * @returns Returns the slice of `array`.
     */
    template <typename Container>
    auto baseSlice(const Container& array, intptr_t start, intptr_t end) {
        std::vector<typename Container::value_type> result;
        intptr_t index = -1, length = array.size();

        if (start < 0) {
            start = -start > length ? 0 : (length + start);
        }
        end = end > length ? length : end;
        if (end < 0) {
            end += length;
        }
        length = start > end ? 0 : ((end - start));

        result.reserve(length);
        while (++index < length) {
            helper::add_to_container(result, array[index + start]);
        }
        return result;
    }

/* helper macro to fixup start/end slice values */
#define ADJUST_INDICES(start, end, len) \
    if (end > len)                      \
        end = len;                      \
    else if (end < 0) {                 \
        end += len;                     \
        if (end < 0)                    \
            end = 0;                    \
    }                                   \
    if (start < 0) {                    \
        start += len;                   \
        if (start < 0)                  \
            start = 0;                  \
    }

    template <typename Container>
    std::vector<typename Container::value_type> pyslice(const Container& array, intptr_t start, intptr_t end) {
        ADJUST_INDICES(start, end, (intptr_t)array.size());
        if (start >= end) return {};
        return std::vector<typename Container::value_type>(std::next(array.cbegin(), start), std::next(array.cbegin(), end - start));
        // return std::vector<typename Container::value_type>(std::next(array.cbegin(), start), std::prev(array.cend(), array.size() - end));
        //return array.substr(start, end - start);
    }

    template <int start = 0, int end = 0, typename Container>
    constexpr auto pyslice_span(Container&& container) {
        ADJUST_INDICES(start, end, (int)array.size());
        return gsl::span(std::begin(std::forward<Container>(container)) + start, std::begin(std::forward<Container>(container)) + end);
	}

    /**
     * Creates an array of elements split into groups the length of `size`.
     * If `array` can't be split evenly, the final chunk will be the remaining
     * elements.
     *
     * @param {Array} array The array to process.
     * @param {number} [size=1] The length of each chunk
     * @returns {Array} Returns the new array of chunks.
     * @code
     *
     * _.chunk(['a', 'b', 'c', 'd'], 2);
     * // => [['a', 'b'], ['c', 'd']]
     *
     * _.chunk(['a', 'b', 'c', 'd'], 3);
     * // => [['a', 'b', 'c'], ['d']]
	 *
     * auto patterns = _::chunk(list, 2, -1);
	 * auto pattern_iter = patterns.begin();
	 * do {
	 *     auto [pattern, peek] = *pattern_iter++;
     * } while (pattern.size());
	 *
	 * Python>[x for x in stutter_chunk(['a', 'b', 'c', 'd'], 2, 1)]
 	 * [['a', 'b'], ['b', 'c'], ['c', 'd'], ['d', None]]
     */
    template <typename T, typename R = typename T::value_type>
    auto chunk(const T& list, size_t chunk_size, int step = 0) {
        std::vector<std::vector<R>> result;
        size_t length = list.chunk_size();
        size_t index = 0, result_count = length / chunk_size;
        while (index < length) {
            result.emplace_back(baseSlice<std::vector<R>>(list, index, index + chunk_size));
            index += chunk_size + step;
        }
        return result;
    }

    template <typename T, class _Predicate, typename R = typename T::value_type, typename itertype = T::const_iterator>
    auto chunk_if(T& list, _Predicate __pred) {
        std::vector<std::vector<R>> result;
        if (list.empty())
            return result;
        auto iter1 = list.cbegin();
        auto iter2 = list.cbegin();
        std::vector<R> chunk1;
        chunk1.emplace_back(*iter1);
        while (iter1 != list.cend() && ++iter2 != list.cend()) {
            if (__pred(*iter1, *iter2)) {
                chunk1.emplace_back(*iter2);
            } else {
                result.emplace_back(chunk1);
                chunk1 = {*iter2};
            }
            ++iter1;
        }
        if (chunk1.size())
            result.emplace_back(chunk1);

        return result;
    }

    template <class _InputIterator, class _OutputIterator, class _Predicate>
    inline _OutputIterator
    copy_if(_InputIterator __first, _InputIterator __last,
            _OutputIterator __result, _Predicate __pred) {
        for (; __first != __last; ++__first) {
            if (__pred(*__first)) {
                *__result = *__first;
                ++__result;
            }
        }
        return __result;
    }

}  // namespace _
