#pragma once
#include "lodash_common.h"
#include "017_tuple_keys.h"
#include "014_filter.h"
#include "001_each.h"

namespace _ {
    // Functions

    // bind
    // bindAll
    // memoize
    // delay
    // defer
    // throttle
    // debounce
    // once
    // after
    // wrap
    // compose

    // Objects

    // keys
    // values
    // functions
    // extend
    // defaults
    // clone
    // tap
    // has
    // isEqual
    // isEmpty
    // isElement
    // isArray
    // isArguments
    // isFunction
    // isString
    // isNumber
    // isBoolean
    // isDate
    // isRegExp
    // isNaN
    // isNull
    // isUndefined

    // Utility

    // noConflict
    // identity
    // times
    // mixin
    // uniqueId
    // escape
    // template

    // Chaining

    template <typename Container>
    class Wrapper;

    // chain
    template <typename Container>
    Wrapper<Container> chain(Container container)
    {
        return Wrapper<Container>(std::move(container));
    }

    // value
    template <typename Container>
    typename Container::value_type value(Wrapper<Container>& wrapper)
    {
        return wrapper.value();
    }

    template <typename Container>
    class Wrapper {
    public:
        // what's this for?
        typedef Container value_type;
        Wrapper(Container container) : container_(std::move(container)) {}

        Container value() { return container_; }

        template <typename Function>
        Wrapper& each(Function function)
        {
            _::each(container_, function);
            return *this;
        }

        template <typename Function, typename ResultContainer = std::vector<typename Container::value_type>>
        Wrapper<ResultContainer> filter(Function function)
        {
            return chain(_::filter<ResultContainer>(container_, function));
        }

        template <typename ResultContainer, typename Function>
        Wrapper<ResultContainer> map(Function function)
        {
            return chain(_::map<ResultContainer>(container_, function));
        }

        template <typename Function, typename Memo>
        Wrapper<Memo> reduce(Function function, Memo memo)
        {
            return chain(_::reduce(container_, function, memo));
        }

        template <typename ResultContainer = std::vector<typename Container::value_type>>
        Wrapper<ResultContainer> tuple_keys()
        {
            return chain(_::tuple_keys<ResultContainer>(container_));
        }


    private:
        Container container_;
    };
}
