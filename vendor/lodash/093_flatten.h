#pragma once
#include "helper.h"
#include <type_traits>

namespace _ {
    namespace helper {
        template <typename T>
        class HasConstIterator {
        private:
            typedef char yes[1];
            typedef char no[2];
            template <typename C>
            static yes& test(typename C::const_iterator*) = delete;
            template <typename C>
            static no& test(...) = delete;

        public:
            static bool const value = sizeof(test<T>(0)) == sizeof(yes);
        };

        template <typename ResultContainer, typename Container>
        ResultContainer flatten_one_layer(Container const& container)
        {
            ResultContainer result;
            for (auto i = container.begin(); i != container.end(); ++i) {
                for (typename Container::value_type::const_iterator j = i->begin(); j != i->end(); ++j) {
                    add_to_container(result, *j);
                }
            }
            return result;
        }

        template <typename ResultContainer, typename Container>
        typename std::enable_if<!HasConstIterator<typename Container::value_type>::value, void>::type flatten_loop(
            ResultContainer& result, Container const& container)
        {
            for (auto i = container.begin(); i != container.end(); ++i) {
                add_to_container(result, *i);
            }
        }

        template <typename ResultContainer, typename Container>
        typename std::enable_if<HasConstIterator<typename Container::value_type>::value, void>::type flatten_loop(
            ResultContainer& result, Container const& container)
        {
            for (auto i = container.begin(); i != container.end(); ++i) {
                flatten_loop(result, *i);
            }
        }

    }  // namespace helper

    template <typename ResultContainer, typename Container>
    ResultContainer flatten(Container const& container)
    {
        ResultContainer result;
        helper::flatten_loop(result, container);
        return result;
    }

    template <typename ResultContainer, bool                        shallow, typename Container>
    typename std::enable_if<shallow == true, ResultContainer>::type flatten(Container const& container)
    {
        return helper::flatten_one_layer<ResultContainer>(container);
    }

    template <typename ResultContainer, bool                         shallow, typename Container>
    typename std::enable_if<shallow == false, ResultContainer>::type flatten(Container const& container)
    {
        return flatten<ResultContainer>(container);
    }

}
