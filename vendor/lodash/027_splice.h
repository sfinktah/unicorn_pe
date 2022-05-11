#pragma once
#include "lodash_common.h"
#include "helper.h"
namespace _ {
    /// <summary>Mutates the contents of an array by removing existing elements and/or adding new elements</summary>
    /// <param name="container">The container.</param>
    /// <param name="start">Index at which to start changing the array (with origin 0). If greater than the length of the array, actual starting index will be set to the length of the array. If negative, will begin that many elements from the end of the array (with origin -1) and will be set to 0 if absolute value is greater than the length of the array.</param>
    /// <param name="deleteCount">The number of old array elements to remove. 
    /// If deleteCount is omitted, or if its value is larger than array.length - start (that is, if it is greater than the number of elements left in the array, starting at start), then all of the elements from start through the end of the array will be deleted.
    /// If deleteCount is 0 or negative, no elements are removed.In this case, you should specify at least one new element(see below).</param>
    /// <param name="items">The elements to add to the array, beginning at the start index. If you don't specify any elements, splice() will only remove elements from the array.</param>
    /// <returns>An array containing the deleted elements. If only one element is removed, an array of one element is returned. If no elements are removed, an empty array is returned.</returns>
    /// <example><code>
    /// // see: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/splice
    /// </code></example>
    template <typename Container>
    Container splice(Container& container, long int start, long int deleteCount = LONG_MAX, const Container items = {})
    {
        // begin Optional
        //    Zero - based index at which to begin extraction.
        //    A negative index can be used, indicating an offset from the end of the sequence.slice(-2) extracts the last two
        //    elements in the sequence.
        //    If begin is undefined, slice begins from index 0.

        // end Optional
        //    Zero - based index before which to end extraction.slice extracts up to but not including end.
        //    For example, slice(1, 4) extracts the second element through the fourth element(elements indexed 1, 2, and 3).
        //    A negative index can be used, indicating an offset from the end of the sequence.slice(2, -1) extracts the third
        //    element through the second - to - last element in the sequence.
        //    If end is omitted, slice extracts through the end of the sequence(arr.length).
        //    If end is greater than the length of the sequence, slice extracts through the end of the sequence(arr.length).

        /*
        start
            Index at which to start changing the array (with origin 0). 
            If greater than the length of the array, actual starting index will be set to the length of the array. 
            If negative, will begin that many elements from the end of the array (with origin -1) and will be set to 0 if absolute value is greater than the length of the array.

        deleteCount Optional
            An integer indicating the number of old array elements to remove.
            If deleteCount is omitted, or if its value is larger than `array.length - start` 
                (that is, if it is greater than the number of elements left in the array, starting at start), 
                then all of the elements from start through the end of the array will be deleted.
            If deleteCount is 0 or negative, no elements are removed. In this case, you should specify at least one new element (see below).
        */

        Container result;

        const size_t len = container.size();

        if (deleteCount < 1) deleteCount = 0;
        if (start < 0) start = len + start;

        start = helper::clamp<size_t>(start, 0, len);
        size_t end = start + deleteCount;
        end   = helper::clamp<size_t>(end, start, len);
        deleteCount = end - start;

        if (deleteCount > 0)
        for (auto it = std::next(std::begin(container), start); deleteCount; deleteCount--) {
            helper::add_to_container(result, *it), it = container.erase(it);
        }
        auto pos = std::next(std::begin(container), start);
        container.insert(pos, std::begin(items), std::end(items));
        //each(items, [&container, &pos](const auto& item) {
        //    helper::add_to_container(container, item, pos)
        //});
        //result = slice<Container>(container, start, end);
        //size_t       _index = 0;
        //for (auto i = container.begin(); i != container.end(); /* ++i */) {
        //    auto index = _index++;
        //    if (index >= end) break;
        //    if (index >= start) helper::add_to_container(result, *i);
        //}
        return result;
    }
}
