#pragma once
#include "lodash_common.h"
#include "helper.h"
namespace _ {
    // append
    /// <summary>Add a new element <paramref="element" /> to copy of an existing array <paramref="container" /> with </summary>
    /// <param name="container">container</param>
    /// <param name="element">element</param>
    /// <returns></returns>
    template <typename Container>
    Container append(const Container& container, const typename Container::value_type& element)
    {
        Container result;

        // This may be a terrible idea, if reserve or size is not defined.
        // result.reserve(container1.size() + container2.size());
        each(container, [&result](auto value) { helper::add_to_container(result, value); });
        helper::add_to_container(result, element);

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
}
